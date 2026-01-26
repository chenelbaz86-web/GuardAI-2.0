#!/usr/bin/env python3
"""
GuardAI Proxy v7 – עם לוגים עשירים ל-Dashboard

- תומך ב-Cursor (OpenAI-compatible /v1/chat/completions).
- מחבר ל-GuardAI Policy Engine דרך guardai_client.check_with_guardai.
- שומר לוגים בזיכרון עם:
  tenant, user, agent, decision, policy, prompt, reason, attack_type, suspicion_score.
- מספק /logs/recent לדשבורד ב-guardai-dashboard.
"""
from pathlib import Path
from datetime import datetime, timedelta, timezone
import os
import json
import time
import logging
import signal
import sys
import uuid
import threading
from collections import defaultdict, deque
from threading import Lock
from typing import Any, Dict, List, Optional, Tuple

import httpx
from flask import Flask, request, jsonify, Response, make_response, g
from flask_cors import CORS
from flask_limiter import Limiter
from dotenv import load_dotenv

from groq import Groq, RateLimitError, APIError, APIConnectionError
from guardai_client import check_with_guardai


# =============================
# Log storage (for dashboard)
# =============================

proxy_logs: deque[Dict[str, Any]] = deque(maxlen=500)
proxy_logs_lock = Lock()
LOG_DIR = Path(os.getenv("GUARDAI_LOG_DIR", "logs"))
LOG_DIR.mkdir(parents=True, exist_ok=True)

RETENTION_DAYS = 90  # במקום 30


def _log_file_for_today() -> Path:
    return LOG_DIR / f"proxy-{datetime.now(timezone.utc).strftime('%Y-%m-%d')}.jsonl"


def add_proxy_log(
    tenant_id: str,
    user: str,
    agent: str,
    decision: str,
    policy: str,
    prompt: Optional[str] = None,
    reason: Optional[str] = None,
    attack_type: Optional[str] = None,
    suspicion_score: Optional[int] = None,
) -> None:
    entry = {
        "time": datetime.now(timezone.utc).isoformat(),
        "tenant": tenant_id,
        "user": user,
        "agent": agent,
        "decision": decision,
        "policy": policy,
        "prompt": prompt or "",
        "reason": reason or "",
        "attack_type": attack_type or "none",
        "suspicion_score": suspicion_score or 0,
    }

    # לזיכרון
    with proxy_logs_lock:
        proxy_logs.append(entry)

    # לדיסק – JSONL יומי
    try:
        with _log_file_for_today().open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception:
        logging.exception("Failed to write proxy log to disk")


def load_recent_logs_into_memory():
    cutoff = datetime.now(timezone.utc) - timedelta(days=RETENTION_DAYS)
    entries: List[Dict[str, Any]] = []

    for path in sorted(LOG_DIR.glob("proxy-*.jsonl")):
        # parse date from filename
        try:
            date_str = path.stem.split("proxy-")[1]
            file_date = datetime.strptime(date_str, "%Y-%m-%d").replace(
                tzinfo=timezone.utc
            )
        except Exception:
            continue

        # מחיקת קבצים ישנים מ-90 יום
        if file_date < cutoff:
            try:
                path.unlink()
                logging.info("Deleted old log file %s", path)
            except Exception:
                logging.exception("Failed to delete old log file %s", path)
            continue

        # טעינה מקבצים בטווח
        try:
            with path.open("r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                        t_str = obj.get("time")
                        if t_str:
                            t = datetime.fromisoformat(t_str)
                            if t.tzinfo is None:
                                t = t.replace(tzinfo=timezone.utc)
                            if t < cutoff:
                                continue
                        entries.append(obj)
                    except Exception:
                        continue
        except Exception:
            logging.exception("Failed to load logs from %s", path)

    entries.sort(key=lambda e: e.get("time", ""))
    with proxy_logs_lock:
        for e in entries[-proxy_logs.maxlen :]:
            proxy_logs.append(e)
    logging.info("Loaded %d recent logs into memory", len(proxy_logs))


# =============================
# Config / logging
# =============================

ENV = os.getenv("ENV", "dev")
raw_tenants = os.getenv("TENANT_TOKENS_JSON")

if ENV == "prod" and not raw_tenants:
    raise RuntimeError(
        "Proxy misconfigured: TENANT_TOKENS_JSON is not set (production mode)."
    )

if not raw_tenants:
    # Dev default – tenant "default"
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

load_dotenv()
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)

app = Flask(__name__)
CORS(app)

app.config["MAX_CONTENT_LENGTH"] = int(
    os.getenv("GUARD_AI_MAX_BODY_BYTES", str(1 * 1024 * 1024))
)  # 1MB
TLS_VERIFY = os.getenv("GUARD_AI_TLS_VERIFY", "true").lower() not in (
    "0",
    "false",
    "no",
)

MAX_TEXT_CHARS = int(os.getenv("GUARD_AI_MAX_TEXT_CHARS", "20000"))
MAX_MESSAGES = int(os.getenv("GUARD_AI_MAX_MESSAGES", "40"))

STREAM_CHUNK_SIZE = int(os.getenv("STREAM_CHUNK_SIZE", "80"))
STREAM_CHUNK_DELAY_MS = int(os.getenv("STREAM_CHUNK_DELAY_MS", "0"))
STREAM_REDACTION_LAG_CHARS = int(
    os.getenv("STREAM_REDACTION_LAG_CHARS", "220")
)

MAX_STREAM_CONCURRENCY_PER_TENANT = int(
    os.getenv("MAX_STREAM_CONCURRENCY_PER_TENANT", "2")
)
MAX_STREAM_SECONDS = int(os.getenv("MAX_STREAM_SECONDS", "35"))

DEFAULT_TENANT_ID = "default"

GROQ_MODELS_2026 = {
    "default": os.getenv(
        "GUARD_AI_GROQ_MODEL_DEFAULT", "llama-3.3-70b-versatile"
    ),
    "fast": os.getenv("GUARD_AI_GROQ_MODEL_FAST", "llama-3.1-8b-instant"),
}

POLICY_MODEL = os.getenv("GUARD_AI_POLICY_MODEL", GROQ_MODELS_2026["fast"])
OUTPUT_MODEL = os.getenv("GUARD_AI_OUTPUT_MODEL", GROQ_MODELS_2026["fast"])
COMPLETION_MODEL = os.getenv(
    "GUARD_AI_COMPLETION_MODEL", GROQ_MODELS_2026["fast"]
)

CURSOR_SAFE = True


# =============================
# Tenant auth
# =============================

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
        return {
            str(k).strip(): str(v).strip()
            for k, v in obj.items()
            if str(k).strip() and str(v).strip()
        }
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
    """Production-like: enforce TENANT_TOKENS_JSON and token -> tenant_id."""
    if not TENANT_TOKENS:
        return (
            False,
            None,
            "Proxy misconfigured: TENANT_TOKENS_JSON is not set (production mode).",
        )

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


def get_provider_key_for_tenant(
    tenant_id: str, provider: str = "groq"
) -> Optional[str]:
    if provider == "groq":
        return os.getenv("DEFAULT_GROQ_API_KEY")
    return None


# =============================
# Rate limiting
# =============================

def limiter_key() -> str:
    return getattr(g, "tenant_id", None) or (request.remote_addr or "unknown")


limiter = Limiter(
    limiter_key, app=app, default_limits=["200/hour"], storage_uri="memory://"
)


@app.before_request
def attach_tenant_context():
    token = get_token_from_request()
    g.tenant_id = resolve_tenant_id_from_token(token) if TENANT_TOKENS else None
    g.rid = request_id()


# =============================
# Streaming concurrency
# =============================

_stream_semaphores: Dict[str, threading.Semaphore] = defaultdict(
    lambda: threading.Semaphore(MAX_STREAM_CONCURRENCY_PER_TENANT)
)


def try_acquire_stream_slot(tenant_id: str) -> bool:
    return _stream_semaphores[tenant_id].acquire(blocking=False)


def release_stream_slot(tenant_id: str) -> None:
    try:
        _stream_semaphores[tenant_id].release()
    except Exception:
        pass


# =============================
# Message normalization
# =============================

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


def normalize_messages(
    messages: Any, max_messages: int, max_text_chars: int
) -> List[Dict[str, str]]:
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


# =============================
# Provider wrapper (Groq)
# =============================

def groq_client(api_key: str) -> Groq:
    return Groq(
        api_key=api_key,
        timeout=httpx.Timeout(25.0, connect=10.0),
        http_client=httpx.Client(verify=TLS_VERIFY),
    )


def call_groq_chat_safe(
    api_key: str,
    model: str,
    messages: List[Dict[str, str]],
    temperature: float = 0.0,
) -> Tuple[bool, str, str, Optional[int]]:
    try:
        logging.info("### GROQ CALL ### model=%s messages=%d", model, len(messages))

        client = groq_client(api_key)
        logging.info(
            "### GROQ MESSAGES ### %s",
            json.dumps(messages, ensure_ascii=False)[:400],
        )

        resp = client.chat.completions.create(
            model=model,
            messages=messages,
            temperature=float(temperature),
            stream=False,
        )

        content = resp.choices[0].message.content or ""
        logging.info(
            "### GROQ OK ### len=%d", len(content or "")
        )
        return True, content, "ok", None

    except RateLimitError as e:
        logging.warning("GROQ rate limit: %s", str(e)[:200])
        return (
            False,
            f"Provider rate-limited. Please retry shortly. ({str(e)[:180]})",
            "rate_limit",
            30,
        )
    except APIConnectionError as e:
        logging.error("GROQ network error: %s", str(e)[:200])
        return (
            False,
            f"Provider network error. Please retry. ({str(e)[:180]})",
            "network",
            10,
        )
    except APIError as e:
        try:
            logging.error(
                "### GROQ API ERROR RAW ### %s %s",
                e.response.status_code,
                e.response.text,
            )
        except Exception:
            logging.error("### GROQ API ERROR ### %s", str(e))
        return (
            False,
            f"Provider API error. Please retry. ({str(e)[:180]})",
            "provider",
            10,
        )
    except Exception as e:
        logging.exception("Unexpected provider error")
        return (
            False,
            f"Unexpected proxy error. ({type(e).__name__}: {str(e)[:180]})",
            "other",
            10,
        )


# =============================
# Agent / User detection
# =============================

def extract_api_key() -> Optional[str]:
    auth = request.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        return auth.split(" ", 1)[1].strip()
    return None


def detect_agent(req) -> str:
    ua = (req.headers.get("User-Agent") or "").lower()
    logging.info("[AGENT DEBUG] User-Agent=%r", ua)

    # === IDE-based & coding assistants ===

    # Cursor
    if "cursor" in ua or "go-http-client" in ua:
        return "cursor"

    # GitHub Copilot / Copilot Chat / Agents
    if "github-copilot" in ua or "copilot" in ua:
        if "vscode" in ua:
            return "copilot-vscode"
        if "jetbrains" in ua or "intellij" in ua or "pycharm" in ua:
            return "copilot-jetbrains"
        return "copilot"

    # VS Code HTTP clients
    if "vscode-restclient" in ua:
        return "vscode-rest-client"
    if "thunder client" in ua or "thunder-client" in ua:
        return "thunder-client"
    if "hoppscotch" in ua:
        return "hoppscotch"

    # JetBrains HTTP Client
    if "jetbrains" in ua or "intellij http client" in ua or "intellij-http-client" in ua:
        return "jetbrains-http-client"

    # === API tools / generic clients ===

    if "postmanruntime" in ua or "postman" in ua:
        return "postman"
    if "insomnia" in ua:
        return "insomnia"
    if "curl/" in ua:
        return "curl"
    if "wget/" in ua:
        return "wget"

    # Python HTTP libraries
    if "python-requests" in ua:
        return "python-requests"
    if "aiohttp" in ua:
        return "aiohttp"
    if "httpx" in ua:
        return "httpx"

    # Node.js / JS HTTP clients
    if "axios/" in ua or "axios " in ua:
        return "axios"
    if "node-fetch" in ua:
        return "node-fetch"
    if "superagent" in ua:
        return "superagent"
    if "got/" in ua:
        return "got"

    # Java / OkHttp / Apache
    if "okhttp" in ua:
        return "okhttp"
    if "apache-httpclient" in ua:
        return "apache-httpclient"
    if "java " in ua or "java/" in ua:
        return "java-http-client"

    # Generic Go HTTP client
    if "go-http-client" in ua:
        return "go-http-client"

    # Browsers
    if "chrome/" in ua or "crios/" in ua:
        return "chrome"
    if "firefox/" in ua or "fxios/" in ua:
        return "firefox"
    if "safari/" in ua and "chrome/" not in ua:
        return "safari"
    if "edg/" in ua:
        return "edge"

    return "unknown"


import getpass


def detect_user(req, data: dict) -> str:
    # אם יש header מפורש – נכבד אותו
    user = req.headers.get("X-GuardAI-User")
    if user:
        return user

    # משתמש מקומי/דומייני מהמחשב שרץ עליו ה-agent
    username = os.environ.get("USERNAME") or getpass.getuser()
    userdomain = os.environ.get("USERDOMAIN")
    if userdomain:
        return f"{userdomain}\\{username}"

    # fallback אחרון – רק אם ממש אין מהמערכת
    if "user" in data and isinstance(data["user"], str):
        return data["user"]

    return "unknown"


# =============================
# SSE helpers (Cursor)
# =============================

def openai_chat_payload(content: str, model_name: str) -> Dict[str, Any]:
    t = now_ts()
    return {
        "id": f"chatcmpl-{t}",
        "object": "chat.completion",
        "created": t,
        "model": model_name or "gpt-compat",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "finish_reason": "stop",
            }
        ],
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


# =============================
# Routes
# =============================

@app.route("/health", methods=["GET"])
def health():
    return jsonify(
        {
            "status": "GuardAI Proxy v7 (logs + dashboard)",
            "cursor_safe": True,
            "tenant_tokens_configured": bool(TENANT_TOKENS),
            "provider_key_present": bool(os.getenv("DEFAULT_GROQ_API_KEY")),
            "models": {
                "policy": POLICY_MODEL,
                "output": OUTPUT_MODEL,
                "completion": COMPLETION_MODEL,
            },
        }
    )


@app.get("/shadow/agents/summary")
def shadow_agents_summary():
    with proxy_logs_lock:
        logs = list(proxy_logs)

    by_agent: Dict[str, Dict[str, Any]] = {}

    for e in logs:
        agent = (e.get("agent") or "unknown").lower()
        user = e.get("user") or "unknown"
        tstr = e.get("time")

        if agent not in by_agent:
            by_agent[agent] = {
                "agent": agent,
                "platform_name": agent,
                "total_events": 0,
                "users": set(),
                "first_seen": tstr,
                "last_seen": tstr,
                "risk": "medium",  # ברירת מחדל
                "known": False,  # נחשב בהמשך
            }

        row = by_agent[agent]
        row["total_events"] += 1
        row["users"].add(user)

        if tstr:
            if not row["first_seen"] or tstr < row["first_seen"]:
                row["first_seen"] = tstr
            if not row["last_seen"] or tstr > row["last_seen"]:
                row["last_seen"] = tstr

    # allow‑list של כלים "מאושרים"
    KNOWN_AGENTS = {"chatgpt-enterprise", "internal-bot"}

    result: List[Dict[str, Any]] = []
    for agent, row in by_agent.items():
        total = row["total_events"]
        unique_users = len(row["users"])

        # חישוב risk פשטני
        if unique_users >= 50 or total >= 2000:
            risk = "critical"
        elif unique_users >= 10 or total >= 500:
            risk = "high"
        elif unique_users >= 3 or total >= 100:
            risk = "medium"
        else:
            risk = "low"

        known = agent in KNOWN_AGENTS

        result.append(
            {
                "agent": agent,
                "platform_name": row["platform_name"],
                "total_events": total,
                "unique_users": unique_users,
                "first_seen": row["first_seen"],
                "last_seen": row["last_seen"],
                "risk": risk,
                "known": known,
            }
        )

    logging.info("Shadow summary: %d agents", len(result))
    return result


@app.route("/logs/recent", methods=["GET"])
def logs_recent():
    """Return recent proxy logs (in-memory) for dashboard."""
    limit = int(request.args.get("limit", "50"))
    with proxy_logs_lock:
        logs_list = list(proxy_logs)
        logs_list.reverse()
        logging.info(
            "Logs recent requested: limit=%d, available=%d",
            limit,
            len(logs_list),
        )
        return jsonify(logs_list[:limit]), 200


@app.route("/v1/models", methods=["GET"])
@app.route("/models", methods=["GET"])
def models():
    return jsonify(
        {
            "object": "list",
            "data": [
                {"id": "fast", "object": "model", "owned_by": "guardai"},
                {"id": "default", "object": "model", "owned_by": "guardai"},
                {
                    "id": COMPLETION_MODEL,
                    "object": "model",
                    "owned_by": "guardai",
                },
            ],
        }
    )


@app.route("/v1", methods=["GET"])
def openai_root():
    return jsonify({"ok": True, "service": "GuardAI Proxy", "compat": "openai"})


# =============================
# Main chat completions route
# =============================

@app.route("/v1/chat/completions", methods=["POST"])
@app.route("/chat/completions", methods=["POST"])
@limiter.limit("120/minute")
def chat_completions():
    rid = getattr(g, "rid", None) or request_id()
    logging.info("=== NEW REQUEST RID=%s ===", rid)

    data = request.get_json(force=True) or {}
    want_stream = bool(data.get("stream", False))
    model_for_ui = str(data.get("model", "gpt-compat"))

    tenant_id = DEFAULT_TENANT_ID

    policy = {
        "completion_model": COMPLETION_MODEL,
        "max_messages": MAX_MESSAGES,
        "max_text_chars": MAX_TEXT_CHARS,
        "max_stream_seconds": MAX_STREAM_SECONDS,
        "stream_redaction": True,
    }

    api_key = extract_api_key()
    if not api_key:
        content = "Proxy misconfigured: missing provider key from Authorization header."
        logging.warning("[RID %s] Missing provider API key", rid)
        payload = openai_chat_payload(content, model_for_ui)
        if want_stream:
            return Response(
                sse(payload) + sse_done(), mimetype="text/event-stream"
            )
        return jsonify(payload), 200

    messages = normalize_messages(
        data.get("messages", []),
        policy["max_messages"],
        policy["max_text_chars"],
    )
    last_user = last_user_text(messages)

    agent = detect_agent(request)
    user_id = detect_user(request, data)
    logging.info("[RID %s] DEBUG user_id=%r agent=%r", rid, user_id, agent)

    logging.info(
        "[RID %s] tenant=%s agent=%s user=%s stream=%s last_user=%r",
        rid,
        tenant_id,
        agent,
        user_id,
        want_stream,
        clip(last_user, 160),
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

    logging.info(
        "[RID %s] DEBUG guardai_allowed=%r guardai_response=%r",
        rid,
        guardai_allowed,
        guardai_response,
    )

    if not guardai_allowed:
        block_reason = guardai_response.get(
            "reason", "Blocked by security policy"
        )
        attack_type = guardai_response.get("attack_type", "none")
        suspicion_score = guardai_response.get("suspicion_score", 0)
        attack_path = guardai_response.get("attack_path", "")

        # Log BLOCK event
        add_proxy_log(
            tenant_id=tenant_id,
            user=user_id,
            agent=agent,
            decision="BLOCK",
            policy="GuardAI-Policy",
            prompt=last_user,
            reason=block_reason,
            attack_type=attack_type,
            suspicion_score=suspicion_score,
        )
        logging.info(
            "[RID %s] LOGGED BLOCK event; total_logs=%d",
            rid,
            len(proxy_logs),
        )

        full_message = block_reason
        if attack_path:
            full_message += f"\n\nPossible attack vector: {attack_path}"

        content = cursor_block_message(full_message)
        payload = openai_chat_payload(content, model_for_ui)
        if want_stream:
            return Response(
                sse(payload) + sse_done(), mimetype="text/event-stream"
            )
        return jsonify(payload), 200

    logging.info(
        "[RID %s] GuardAI ALLOWED: score=%s, reason=%s",
        rid,
        guardai_response.get("suspicion_score", 0),
        guardai_response.get("reason", "")[:80],
    )

    # Log ALLOW event
    add_proxy_log(
        tenant_id=tenant_id,
        user=user_id,
        agent=agent,
        decision="ALLOW",
        policy="GuardAI-Pass",
        prompt=last_user,
        reason=guardai_response.get("reason", ""),
        attack_type=guardai_response.get("attack_type", "none"),
        suspicion_score=guardai_response.get("suspicion_score", 0),
    )
    logging.info(
        "[RID %s] LOGGED ALLOW event; total_logs=%d",
        rid,
        len(proxy_logs),
    )

    # ===== Call provider (Groq) =====
    temperature = float(data.get("temperature", 0.7))
    ok, result, err_type, retry_after = call_groq_chat_safe(
        api_key=api_key,
        model=policy["completion_model"],
        messages=messages,
        temperature=temperature,
    )

    if not ok:
        content = provider_busy_message(err_type)
        payload = openai_chat_payload(content, model_for_ui)
        if want_stream:
            return Response(
                sse(payload) + sse_done(), mimetype="text/event-stream"
            )
        resp = make_response(jsonify(payload), 200)
        if retry_after:
            resp.headers["Retry-After"] = str(retry_after)
        logging.warning("[RID %s] Provider busy type=%s", rid, err_type)
        return resp

    # Non-stream: final redaction (optional)
    if not want_stream and policy.get("stream_redaction", True):
        # כאן אפשר להכניס רדקציה עתידית
        pass

    if want_stream:
        payload = openai_chat_payload(result, model_for_ui)
        logging.info("[RID %s] Sending streamed response", rid)
        return Response(
            sse(payload) + sse_done(), mimetype="text/event-stream"
        )

    response_data = openai_chat_payload(result, model_for_ui)
    try:
        logging.info(
            "[RID %s] RESPONSE TO CLIENT: %s",
            rid,
            json.dumps(response_data, ensure_ascii=False)[:400],
        )
    except Exception:
        logging.exception("Failed to log response JSON")

    return jsonify(response_data), 200


# =============================
# Run
# =============================

def run_safe():
    port = int(os.getenv("PORT", "8002"))
    load_recent_logs_into_memory()
    logging.info("🚀 GuardAI Proxy v7 → http://0.0.0.0:%d", port)
    logging.info("✅ TLS verify: %s", TLS_VERIFY)
    logging.info(
        "✅ Tenant tokens configured: %s (production-like auth)",
        bool(TENANT_TOKENS),
    )
    logging.info(
        "✅ Provider key present: groq=%s", bool(os.getenv("DEFAULT_GROQ_API_KEY"))
    )
    logging.info(
        "✅ OpenAI-compatible routes, Cursor-safe 200, logs for dashboard enabled"
    )

    def sigterm_handler(signum, frame):
        logging.info("🛑 Shutdown")
        sys.exit(0)

    signal.signal(signal.SIGINT, sigterm_handler)
    signal.signal(signal.SIGTERM, sigterm_handler)

    app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)


if __name__ == "__main__":
    run_safe()
