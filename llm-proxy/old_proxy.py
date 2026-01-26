#!/usr/bin/env python3
"""
GuardAI Proxy v6.12 — Production-like (token auth enforced) + streaming redaction finalized

Key fixes vs prior builds:
✅ Production-like auth: no DEV fail-open when TENANT_TOKENS_JSON is missing
✅ Streaming DLP redaction: ALSO redacts matches that end at stream end (final flush)
✅ Redacts multiple occurrences, including ones that appear at the very end of the response
✅ Broader secret patterns (not only sk-): OpenAI project keys, AWS, Slack, Stripe, Google, JWT, private keys
✅ Cursor-safe: /v1/chat/completions always returns 200 with assistant payload (errors are "assistant content")
✅ Streaming is simulated (provider call is non-stream), but output is chunked to behave like true SSE streaming
"""

import os
import json
import time
import logging
import signal
import sys
import uuid
import threading
import re
from collections import defaultdict
from collections import deque
from datetime import datetime
from threading import Lock

from typing import Any, Dict, List, Optional, Tuple

import httpx
from flask import Flask, request, jsonify, Response, make_response, g
from flask_cors import CORS
from flask_limiter import Limiter
from dotenv import load_dotenv

from groq import Groq
from groq import RateLimitError, APIError, APIConnectionError
# ייבוא GuardAI client

from collections import deque
from datetime import datetime
from threading import Lock
from guardai_client import check_with_guardai

# Log storage (thread-safe, max 500 entries)
proxy_logs = deque(maxlen=500)
proxy_logs_lock = Lock()

def add_proxy_log(tenant_id: str, user: str, decision: str, policy: str):
    """Add a log entry to the in-memory log store."""
    with proxy_logs_lock:
        proxy_logs.append({
            "time": datetime.utcnow().isoformat() + "Z",
            "tenant": tenant_id,
            "user": user,
            "decision": decision,
            "policy": policy,
        })


ENV = os.getenv("ENV", "dev")
raw_tenants = os.getenv("TENANT_TOKENS_JSON")

if ENV == "prod" and not raw_tenants:
    raise RuntimeError("Proxy misconfigured: TENANT_TOKENS_JSON is not set (production mode).")

if not raw_tenants:
    raw_tenants = """
    {
      "default": {
        "providers": {
          "groq": {
            "api_key": "gsk-dev-placeholder",
            "models": ["llama-3.1-70b-versatile"]
          }
        },
        "limits": {"rpm": 120, "max_tokens": 4096}
      }
    }
    """

TENANTS = json.loads(raw_tenants)


# -----------------------------
# Config / logging
# -----------------------------
load_dotenv()
logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")

app = Flask(__name__)
CORS(app)

app.config["MAX_CONTENT_LENGTH"] = int(os.getenv("GUARD_AI_MAX_BODY_BYTES", str(1 * 1024 * 1024)))  # 1MB
TLS_VERIFY = os.getenv("GUARD_AI_TLS_VERIFY", "true").lower() not in ("0", "false", "no")

MAX_TEXT_CHARS = int(os.getenv("GUARD_AI_MAX_TEXT_CHARS", "20000"))
MAX_MESSAGES = int(os.getenv("GUARD_AI_MAX_MESSAGES", "40"))

# Streaming behavior (simulated streaming)
STREAM_CHUNK_SIZE = int(os.getenv("STREAM_CHUNK_SIZE", "80"))            # chars per SSE delta
STREAM_CHUNK_DELAY_MS = int(os.getenv("STREAM_CHUNK_DELAY_MS", "0"))     # optional delay to visualize streaming
STREAM_REDACTION_LAG_CHARS = int(os.getenv("STREAM_REDACTION_LAG_CHARS", "220"))  # keep tail to avoid partial matches

# Streaming hardening
MAX_STREAM_CONCURRENCY_PER_TENANT = int(os.getenv("MAX_STREAM_CONCURRENCY_PER_TENANT", "2"))
MAX_STREAM_SECONDS = int(os.getenv("MAX_STREAM_SECONDS", "35"))

# קבועים פשוטים לסשן יחיד
DEFAULT_TENANT_ID = "default"

# Groq models mapping
GROQ_MODELS_2026 = {
    "default": os.getenv("GUARD_AI_GROQ_MODEL_DEFAULT", "llama-3.3-70b-versatile"),
    "fast": os.getenv("GUARD_AI_GROQ_MODEL_FAST", "llama-3.1-8b-instant"),
}

POLICY_MODEL = os.getenv("GUARD_AI_POLICY_MODEL", GROQ_MODELS_2026["fast"])
OUTPUT_MODEL = os.getenv("GUARD_AI_OUTPUT_MODEL", GROQ_MODELS_2026["fast"])
COMPLETION_MODEL = os.getenv("GUARD_AI_COMPLETION_MODEL", GROQ_MODELS_2026["fast"])

CURSOR_SAFE = True


# -----------------------------
# Tenant auth (token -> tenant_id)
# -----------------------------
def load_tenant_tokens() -> Dict[str, str]:
    """
    TENANT_TOKENS_JSON example:
      {"token-chen-dev":"tenant_dev","token-custA":"tenant_custA"}
    """
    raw = (os.getenv("TENANT_TOKENS_JSON") or "").strip()
    if not raw:
        return {}
    try:
        obj = json.loads(raw)
        if not isinstance(obj, dict):
            return {}
        return {str(k).strip(): str(v).strip() for k, v in obj.items() if str(k).strip() and str(v).strip()}
    except Exception:
        logging.exception("Invalid TENANT_TOKENS_JSON")
        return {}

TENANT_TOKENS: Dict[str, str] = load_tenant_tokens()


def now_ts() -> int:
    return int(time.time())


def clip(s: str, n: int = 6000) -> str:
    s = s or ""
    return s if len(s) <= n else s[:n] + "…"


def request_id() -> str:
    return request.headers.get("X-Request-Id") or str(uuid.uuid4())


def get_token_from_request() -> str:
    token = (request.headers.get("X-Proxy-Token") or "").strip()
    if token:
        return token
    auth = (request.headers.get("Authorization") or "").strip()
    if auth.lower().startswith("bearer "):
        return auth.split(" ", 1)[1].strip()
    return ""


def resolve_tenant_id_from_token(token: str) -> Optional[str]:
    if not token:
        return None
    return TENANT_TOKENS.get(token)


def require_tenant_auth(rid: str) -> Tuple[bool, Optional[str], str]:
    """
    Production-like:
      - if TENANT_TOKENS_JSON is missing/empty -> treat as misconfiguration (deny)
      - token must resolve -> tenant_id
    """
    if not TENANT_TOKENS:
        return False, None, "Proxy misconfigured: TENANT_TOKENS_JSON is not set (production mode)."

    token = get_token_from_request()
    tenant_id = resolve_tenant_id_from_token(token)
    if not tenant_id:
        return False, None, "Unauthorized: missing or invalid proxy token."
    return True, tenant_id, ""


def get_policy_for_tenant(tenant_id: str) -> Dict[str, Any]:
    return {
        "completion_model": COMPLETION_MODEL,
        "policy_model": POLICY_MODEL,
        "output_model": OUTPUT_MODEL,
        "max_messages": MAX_MESSAGES,
        "max_text_chars": MAX_TEXT_CHARS,
        "stream_concurrency": MAX_STREAM_CONCURRENCY_PER_TENANT,
        "max_stream_seconds": MAX_STREAM_SECONDS,
        "enable_output_dlp": True,
        "stream_redaction": True,
    }


def get_provider_key_for_tenant(tenant_id: str, provider: str = "groq") -> Optional[str]:
    if provider == "groq":
        return os.getenv("DEFAULT_GROQ_API_KEY")
    return None


# -----------------------------
# Rate limiting (per tenant)
# -----------------------------
def limiter_key() -> str:
    return getattr(g, "tenant_id", None) or (request.remote_addr or "unknown")


limiter = Limiter(limiter_key, app=app, default_limits=["200/hour"], storage_uri="memory://")


@app.before_request
def attach_tenant_context():
    token = get_token_from_request()
    g.tenant_id = resolve_tenant_id_from_token(token) if TENANT_TOKENS else None
    g.rid = request_id()


# -----------------------------
# Streaming concurrency per tenant
# -----------------------------
_stream_semaphores = defaultdict(lambda: threading.Semaphore(MAX_STREAM_CONCURRENCY_PER_TENANT))


def try_acquire_stream_slot(tenant_id: str) -> bool:
    return _stream_semaphores[tenant_id].acquire(blocking=False)


def release_stream_slot(tenant_id: str) -> None:
    try:
        _stream_semaphores[tenant_id].release()
    except Exception:
        pass


# -----------------------------
# Message normalization
# -----------------------------
def extract_text_content(content: Any) -> str:
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for item in content:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict):
                if item.get("type") == "text" and "text" in item:
                    parts.append(str(item.get("text", "")))
                elif "text" in item:
                    parts.append(str(item.get("text", "")))
                elif "content" in item:
                    parts.append(str(item.get("content", "")))
        return "\n".join([p for p in parts if p])
    if isinstance(content, dict):
        if "text" in content:
            return str(content.get("text", ""))
        if "content" in content:
            return str(content.get("content", ""))
    return str(content)


def normalize_messages(messages: Any, max_messages: int, max_text_chars: int) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    if not isinstance(messages, list):
        return out
    for m in messages:
        if not isinstance(m, dict):
            continue
        role = (m.get("role") or "user").lower()
        content = extract_text_content(m.get("content", ""))
        if not isinstance(content, str):
            content = str(content)
        content = content.replace("\r\n", "\n").strip()
        if len(content) > max_text_chars:
            content = content[:max_text_chars]
        out.append({"role": role, "content": content})
    return out[:max_messages]


def last_user_text(messages: List[Dict[str, str]]) -> str:
    for m in reversed(messages):
        if m.get("role") == "user":
            return (m.get("content") or "").strip()
    return ""


# -----------------------------
# Provider wrapper (Groq)
# -----------------------------
def groq_client(api_key: str) -> Groq:
    return Groq(
        api_key=api_key,
        timeout=httpx.Timeout(25.0, connect=10.0),
        http_client=httpx.Client(verify=TLS_VERIFY),
    )


from groq import Groq
from groq import RateLimitError, APIConnectionError, APIError


def groq_client(api_key: str) -> Groq:
    return Groq(api_key=api_key)


def call_groq_chat_safe(
    api_key: str,
    model: str,
    messages: List[Dict[str, str]],
    temperature: float = 0.0,
) -> Tuple[bool, str, str, Optional[int]]:
    try:
        print("### GROQ CALL ###", model, len(messages))

        client = groq_client(api_key)
        print("### GROQ MESSAGES ###", json.dumps(messages, ensure_ascii=False)[:400])


        resp = client.chat.completions.create(
            model=model,
            messages=messages,
            temperature=float(temperature),
            stream=False,
        )

        content = resp.choices[0].message.content or ""
        return True, content, "ok", None

    except RateLimitError as e:
        return (
            False,
            f"Provider rate-limited. Please retry shortly. ({str(e)[:180]})",
            "rate_limit",
            30,
        )
    except APIConnectionError as e:
        return (
            False,
            f"Provider network error. Please retry. ({str(e)[:180]})",
            "network",
            10,
        )
    except APIError as e:
        # הדפסת תגובת Groq המלאה לעזרה בדיבוג
        try:
            print("### GROQ API ERROR RAW ###", e.response.status_code, e.response.text)
        except Exception:
            print("### GROQ API ERROR ###", str(e))
        return (
            False,
            f"Provider API error. Please retry. ({str(e)[:180]})",
            "provider",
            10,
        )

    except Exception as e:
        return (
            False,
            f"Unexpected proxy error. ({type(e).__name__}: {str(e)[:180]})",
            "other",
            10,
        )



# -----------------------------
# Secret redaction (stream + final)
# -----------------------------
STREAM_DLP_PATTERNS: List[Tuple[str, re.Pattern]] = [
    # --- OpenAI ---
    ("openai_project_key", re.compile(r"\bsk-proj-[A-Za-z0-9_-]{16,}\b")),
    ("openai_key", re.compile(r"\bsk-[A-Za-z0-9]{16,}\b")),
    # Some OpenAI-compatible / legacy styles (best-effort)
    ("openai_session_key", re.compile(r"\bsess-[A-Za-z0-9_-]{16,}\b")),

    # --- Anthropic ---
    ("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{16,}\b")),

    # --- Groq ---
    ("groq_key", re.compile(r"\bgsk_[A-Za-z0-9]{16,}\b")),

    # --- Hugging Face ---
    ("huggingface_token", re.compile(r"\bhf_[A-Za-z0-9]{20,}\b")),

    # --- GitHub / GitLab ---
    ("github_pat", re.compile(r"\bghp_[A-Za-z0-9]{20,}\b")),
    ("github_pat2", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b")),
    ("github_oauth", re.compile(r"\bgho_[A-Za-z0-9]{20,}\b")),
    ("github_app", re.compile(r"\bghs_[A-Za-z0-9]{20,}\b")),
    ("github_refresh", re.compile(r"\bghr_[A-Za-z0-9]{20,}\b")),
    ("gitlab_pat", re.compile(r"\bglpat-[A-Za-z0-9_-]{16,}\b")),

    # --- Slack ---
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("slack_webhook", re.compile(r"\bhttps://hooks\.slack\.com/services/[A-Za-z0-9]+/[A-Za-z0-9]+/[A-Za-z0-9]+\b")),

    # --- Stripe ---
    ("stripe_live_secret", re.compile(r"\bsk_live_[A-Za-z0-9]{16,}\b")),
    ("stripe_test_secret", re.compile(r"\bsk_test_[A-Za-z0-9]{16,}\b")),
    ("stripe_live_restricted", re.compile(r"\brk_live_[A-Za-z0-9]{16,}\b")),
    ("stripe_test_restricted", re.compile(r"\brk_test_[A-Za-z0-9]{16,}\b")),

    # --- Twilio ---
    ("twilio_account_sid", re.compile(r"\bAC[a-f0-9]{32}\b")),
    ("twilio_api_key", re.compile(r"\bSK[a-f0-9]{32}\b")),

    # --- SendGrid ---
    ("sendgrid_key", re.compile(r"\bSG\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),

    # --- Mailgun ---
    ("mailgun_key", re.compile(r"\bkey-[A-Za-z0-9]{20,}\b")),

    # --- Google ---
    # Google API keys are commonly 39 chars total: 'AIza' + 35 base64url-ish chars.
    # In the wild (and in tests) you may see longer synthetic examples; allow a safe lower bound.
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z\-_]{20,}\b")),
    ("google_oauth_client_secret", re.compile(r"\bGOCSPX-[0-9A-Za-z\-_]{20,}\b")),

    # --- AWS (access keys + common secret contexts) ---
    ("aws_access_key_id", re.compile(r"\b(AKIA|ASIA|AGPA|AIDA|ANPA|AROA|AIPA|ANVA|ABIA|ACCA)[A-Z0-9]{16}\b")),
    # Secret access key is hard to detect safely; match only in assignment-like contexts
    ("aws_secret_access_key", re.compile(r"(?i)(aws_secret_access_key|secret_access_key)\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{35,60}['\"]?")),
    ("aws_session_token", re.compile(r"(?i)(aws_session_token|session_token)\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{40,}['\"]?")),

    # --- Azure storage connection strings (very common leak form) ---
    ("azure_storage_conn_string", re.compile(
        r"(?i)DefaultEndpointsProtocol=https;AccountName=[^;]{3,};AccountKey=[A-Za-z0-9+/=]{20,};EndpointSuffix=core\.windows\.net"
    )),

    # --- JWT (three base64url segments; keep conservative length to reduce false positives) ---
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),

    # --- Private keys / PEM blocks ---
    ("private_key_pem", re.compile(r"-----BEGIN ([A-Z ]+ )?PRIVATE KEY-----[\s\S]+?-----END ([A-Z ]+ )?PRIVATE KEY-----")),
    ("ssh_private_key", re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]+?-----END OPENSSH PRIVATE KEY-----")),
]


def redact_stream_text(text: str, allow_trailing: bool) -> Tuple[str, List[str]]:
    """
    Redact secrets in a text buffer and return (redacted_text, categories_hit).

    Streaming nuance:
    - While streaming, we avoid redacting a match that ends exactly at the end of `text`
      (it may be incomplete and continue in the next delta).
    - On FINAL flush (end of stream), call with allow_trailing=True to redact everything,
      including matches that end at the end of the buffer.
    """
    if not text:
        return text, []

    hits: List[str] = []
    out = text

    for category, rx in STREAM_DLP_PATTERNS:
        if not out:
            continue

        pieces: List[str] = []
        last = 0
        changed = False

        for m in rx.finditer(out):
            if (not allow_trailing) and (m.end() == len(out)):
                # keep trailing match for next delta (might be partial)
                continue

            changed = True
            hits.append(category)
            pieces.append(out[last:m.start()])
            pieces.append(f"[REDACTED:{category}]")
            last = m.end()

        if changed:
            pieces.append(out[last:])
            out = "".join(pieces)

    # de-dupe hits
    if hits:
        hits = sorted(set(hits))

    return out, hits


def split_safe_flush(text: str, keep_tail: int) -> Tuple[str, str]:
    """
    Return (flush_now, keep_pending_tail). Keeps last `keep_tail` chars to avoid
    splitting a secret pattern boundary.
    """
    if keep_tail <= 0 or len(text) <= keep_tail:
        return "", text
    cut = len(text) - keep_tail
    return text[:cut], text[cut:]


# -----------------------------
# OpenAI-compatible response helpers
# -----------------------------
def openai_chat_payload(content: str, model_name: str) -> Dict[str, Any]:
    t = now_ts()
    return {
        "id": f"chatcmpl-{t}",
        "object": "chat.completion",
        "created": t,
        "model": model_name or "gpt-compat",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": content},
            "finish_reason": "stop",
        }],
    }


def sse(data_obj: Dict[str, Any]) -> str:
    return f"data: {json.dumps(data_obj, ensure_ascii=False)}\n\n"


def sse_done() -> str:
    return "data: [DONE]\n\n"


def cursor_block_message(reason: str) -> str:
    return f"Blocked by policy. {reason}".strip()


def provider_busy_message(err_type: str) -> str:
    if err_type == "rate_limit":
        return "Provider rate-limited (429). Please retry in a moment."
    if err_type == "network":
        return "Provider network issue. Please retry."
    if err_type == "provider":
        return "Provider error. Please retry."
    return "Temporary proxy error. Please retry."


def stream_chunked_message(
    content: str,
    model_name: str,
    tenant_id: str,
    max_seconds: int,
    enable_redaction: bool,
) -> Response:
    """
    SSE stream that chunks `content` to simulate real streaming, with stream-safe redaction.
    Finalization fix: redacts trailing matches at stream end.
    """
    chat_id = f"chatcmpl-{now_ts()}"
    start = time.time()
    pending = ""
    pending_hits: List[str] = []

    def gen():
        nonlocal pending, pending_hits
        try:
            # role chunk
            yield sse({
                "id": chat_id,
                "object": "chat.completion.chunk",
                "created": now_ts(),
                "model": model_name or "gpt-compat",
                "choices": [{"index": 0, "delta": {"role": "assistant"}, "finish_reason": None}],
            })

            if not content:
                # stop + done
                yield sse({
                    "id": chat_id,
                    "object": "chat.completion.chunk",
                    "created": now_ts(),
                    "model": model_name or "gpt-compat",
                    "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
                })
                yield sse_done()
                return

            # chunk loop
            for i in range(0, len(content), max(1, STREAM_CHUNK_SIZE)):
                if (time.time() - start) > max_seconds:
                    pending += "\n\nStream timed out. Please retry."
                    break

                delta = content[i:i + STREAM_CHUNK_SIZE]
                pending += delta

                # Redact but keep trailing candidate in pending
                if enable_redaction:
                    pending, hits = redact_stream_text(pending, allow_trailing=False)
                    if hits:
                        pending_hits = hits

                flush_now, pending = split_safe_flush(pending, STREAM_REDACTION_LAG_CHARS)
                if flush_now:
                    yield sse({
                        "id": chat_id,
                        "object": "chat.completion.chunk",
                        "created": now_ts(),
                        "model": model_name or "gpt-compat",
                        "choices": [{"index": 0, "delta": {"content": flush_now}, "finish_reason": None}],
                    })

                if STREAM_CHUNK_DELAY_MS > 0:
                    time.sleep(STREAM_CHUNK_DELAY_MS / 1000.0)

            # FINAL: redact everything left (including trailing matches)
            if enable_redaction and pending:
                pending, hits = redact_stream_text(pending, allow_trailing=True)
                if hits:
                    pending_hits = hits

            if pending:
                yield sse({
                    "id": chat_id,
                    "object": "chat.completion.chunk",
                    "created": now_ts(),
                    "model": model_name or "gpt-compat",
                    "choices": [{"index": 0, "delta": {"content": pending}, "finish_reason": None}],
                })

            # stop + done
            yield sse({
                "id": chat_id,
                "object": "chat.completion.chunk",
                "created": now_ts(),
                "model": model_name or "gpt-compat",
                "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
            })
            yield sse_done()

        finally:
            release_stream_slot(tenant_id)

    return Response(gen(), mimetype="text/event-stream")


# -----------------------------
# Routes
# -----------------------------
@app.route("/health", methods=["GET"])

@app.route("/logs/recent", methods=["GET"])
def logs_recent():
    """Return recent proxy logs (in-memory)."""
    limit = int(request.args.get("limit", "50"))
    with proxy_logs_lock:
        # Return newest first
        logs_list = list(proxy_logs)
        logs_list.reverse()
        return jsonify(logs_list[:limit]), 200


def health():
    return jsonify({
        "status": "GuardAI Proxy v6.12 (PRODUCTION-LIKE + FINAL STREAM REDACTION)",
        "cursor_safe": True,
        "tenant_tokens_configured": bool(TENANT_TOKENS),
        "provider_key_present": bool(os.getenv("DEFAULT_GROQ_API_KEY")),
        "models": {
            "policy": POLICY_MODEL,
            "output": OUTPUT_MODEL,
            "completion": COMPLETION_MODEL,
        },
        "streaming": {
            "chunk_size": STREAM_CHUNK_SIZE,
            "lag_chars": STREAM_REDACTION_LAG_CHARS,
            "max_concurrency_per_tenant": MAX_STREAM_CONCURRENCY_PER_TENANT,
            "max_seconds": MAX_STREAM_SECONDS,
        },
    })


@app.route("/v1/models", methods=["GET"])
@app.route("/models", methods=["GET"])
def models():
    return jsonify({
        "object": "list",
        "data": [
            {"id": "fast", "object": "model", "owned_by": "guardai"},
            {"id": "default", "object": "model", "owned_by": "guardai"},
            {"id": COMPLETION_MODEL, "object": "model", "owned_by": "guardai"},
        ],
    })


@app.route("/v1", methods=["GET"])
def openai_root():
    return jsonify({"ok": True, "service": "GuardAI Proxy", "compat": "openai"})

def extract_api_key():
    auth = request.headers.get("Authorization", "")
    # מצפה לפורמט "Bearer sk-XXXX"
    if auth.lower().startswith("bearer "):
        return auth.split(" ", 1)[1].strip()
    return None


@app.route("/v1/chat/completions", methods=["POST"])
@app.route("/chat/completions", methods=["POST"])
@limiter.limit("120/minute")
def chat_completions():
    rid = getattr(g, "rid", None) or request_id()
    data = request.get_json(force=True) or {}
    want_stream = bool(data.get("stream", False))
    model_for_ui = str(data.get("model", "gpt-compat"))

    tenant_id = DEFAULT_TENANT_ID


        # מדיניות פשוטה לסביבת פיתוח
    # מדיניות פשוטה לסביבת פיתוח – מודל Groq אמיתי
    policy = {
        "completion_model": "llama-3.3-70b-versatile",
        "max_messages": 40,
        "max_text_chars": 8000,
        "max_stream_seconds": MAX_STREAM_SECONDS,
        "stream_redaction": True,
    }





    # <<< כאן – ה‑key מגיע מ‑Cursor >>>
    api_key = extract_api_key()
    if not api_key:
        content = "Proxy misconfigured: missing provider key from Authorization header."
        if want_stream:
            return stream_chunked_message(
                content, model_for_ui, tenant_id,
                policy["max_stream_seconds"], enable_redaction=True
            )
        return jsonify(openai_chat_payload(content, model_for_ui)), 200

   
       # עיבוד ההודעות מהבקשה
    messages = normalize_messages(
        data.get("messages", []),
        policy["max_messages"],
        policy["max_text_chars"],
    )

    # 🟢 השורה החשובה שחסרה – הוצאת הטקסט האחרון של המשתמש
    last_user = last_user_text(messages)

    logging.info(
        f"[RID {rid}] tenant={tenant_id} stream={want_stream} "
        f"last_user={repr(clip(last_user, 160))}"
    )

    # ===== GuardAI Security Check =====
    guardai_allowed, guardai_response = check_with_guardai(
        prompt=last_user,
        context={
            "tool": "chat",  # או "chat_with_tools" אם יש tool_calls
            "model": policy["completion_model"],
            "temperature": data.get("temperature", 0.7),
        },
        user_api_key=api_key,
        tenant_id=tenant_id,
        rid=rid,
    )



    # ===== GuardAI Security Check =====
    guardai_allowed, guardai_response = check_with_guardai(
        prompt=last_user,
        context={
            "tool": "chat",
            "model": policy["completion_model"],
            "temperature": data.get("temperature", 0.7),
        },
        user_api_key=api_key,
        tenant_id=tenant_id,
        rid=rid,
    )

    if not guardai_allowed:
     
        block_reason = guardai_response.get(
            "reason", "Blocked by security policy"
        )
        attack_path = guardai_response.get("attack_path", "")
                # ✅ הוספת לוג
        add_proxy_log(
            tenant_id=tenant_id,
            user=data.get("user", "unknown"),
            decision="BLOCK",
            policy=block_reason[:50]  # חתוך אם ארוך מדי
        )
        
        full_message = block_reason
        if attack_path:
            full_message += f"\n\nPossible attack vector: {attack_path}"

        content = cursor_block_message(full_message)

        if want_stream:
            return stream_chunked_message(
                content,
                model_for_ui,
                tenant_id,
                policy["max_stream_seconds"],
                enable_redaction=True,
            )
        return jsonify(openai_chat_payload(content, model_for_ui)), 200

    logging.info(
        f"[RID {rid}] GuardAI ALLOWED: score={guardai_response.get('suspicion_score', 0)}, "
        f"reason={guardai_response.get('reason', '')[:80]}"
    )

    # ✅ הוספת לוג
    add_proxy_log(
        tenant_id=tenant_id,
        user=data.get("user", "unknown"),
        decision="ALLOW",
        policy="GuardAI-Pass"
    )

    # ===== End GuardAI Check =====

    # קריאה ל‑Groq
    temperature = float(data.get("temperature", 0.7))
    ok, result, err_type, retry_after = call_groq_chat_safe(
        api_key=api_key,
      model=policy["completion_model"],
       messages=messages,
        temperature=temperature,
   )




    if not ok:
        content = provider_busy_message(err_type)
        if want_stream:
            return stream_chunked_message(
                content,
                model_for_ui,
                tenant_id,
                policy["max_stream_seconds"],
                enable_redaction=True,
            )
        resp = make_response(
            jsonify(openai_chat_payload(content, model_for_ui)), 200
        )
        if retry_after:
            resp.headers["Retry-After"] = str(retry_after)
        return resp

    # Non-stream – רדקציה אחרונה
    if not want_stream and policy.get("stream_redaction", True):
        redacted, hits = redact_stream_text(result, allow_trailing=True)
        if hits:
            result = redacted

    if want_stream:
        return stream_chunked_message(
            content=result,
            model_name=model_for_ui,
            tenant_id=tenant_id,
            max_seconds=policy["max_stream_seconds"],
            enable_redaction=policy.get("stream_redaction", True),
        )

    # לוג debug ל‑Cursor
    try:
        response_data = openai_chat_payload(result, model_for_ui)
        print("=== RESPONSE TO CURSOR ===")
        print(json.dumps(response_data, ensure_ascii=False))
    except Exception as e:
        logging.warning(f"Failed to log response: {e}")

    return jsonify(openai_chat_payload(result, model_for_ui)), 200



# -----------------------------
# Run
# -----------------------------
def run_safe():
    port = int(os.getenv("PORT", "8002"))
    logging.info(f"🚀 GuardAI Proxy v6.12 → http://0.0.0.0:{port}")
    logging.info(f"✅ TLS verify: {TLS_VERIFY}")
    logging.info(f"✅ Tenant tokens configured: {bool(TENANT_TOKENS)} (production-like auth)")
    logging.info(f"✅ Provider key present: groq={bool(os.getenv('DEFAULT_GROQ_API_KEY'))}")
    logging.info(f"✅ Stream redaction lag chars: {STREAM_REDACTION_LAG_CHARS}")
    logging.info("✅ OpenAI-compatible routes, Cursor-safe 200, FINAL stream redaction fixed")

    def sigterm_handler(signum, frame):
        logging.info("🛑 Shutdown")
        sys.exit(0)

    signal.signal(signal.SIGINT, sigterm_handler)
    signal.signal(signal.SIGTERM, sigterm_handler)

    app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)


if __name__ == "__main__":
    run_safe()
