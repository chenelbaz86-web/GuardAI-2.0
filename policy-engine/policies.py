import re
from dataclasses import dataclass
from typing import Any, Dict


@dataclass
class Decision:
    decision: str          # "ALLOW" / "BLOCK"
    reason: str
    details: Dict[str, Any] | None = None

    @staticmethod
    def allow(reason: str = "OK", details: Dict[str, Any] | None = None) -> "Decision":
        return Decision("ALLOW", reason, details or {})

    @staticmethod
    def block(reason: str = "Blocked", details: Dict[str, Any] | None = None) -> "Decision":
        return Decision("BLOCK", reason, details or {})

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decision": self.decision,
            "reason": self.reason,
            "details": self.details or {},
            "allowed": self.decision == "ALLOW",
            "suspicion_score": (self.details or {}).get("suspicion_score", 0),
            "attack_type": (self.details or {}).get("attack_type", "none"),
        }


def _compile(patterns):
    return [re.compile(p, re.IGNORECASE) for p in (patterns or [])]


def contains_sensitive(text: str, patterns) -> bool:
    if not text:
        return False
    for rx in _compile(patterns):
        if rx.search(text):
            return True
    return False


def redact_text(text: str, patterns) -> str:
    if not text:
        return text
    redacted = text
    for rx in _compile(patterns):
        redacted = rx.sub("[REDACTED]", redacted)
    return redacted


def looks_like_secret_dump(query: str) -> bool:
    q = (query or "").lower()
    signals = [
        ".env", "id_rsa", "private_key", "private key",
        "aws_access_key_id", "aws_secret_access_key",
        "authorization:", "bearer ", "x-api-key", "apikey", "api_key",
        "token=", "access token", "refresh token",
        "-----begin", "ssh-rsa",
    ]
    score = sum(1 for s in signals if s in q)
    return score >= 2


def looks_like_secrets_request(query: str) -> bool:
    q = (query or "").lower()

    secret_terms = [
        "api key", "api keys", "api-key",
        "מפתח api", "מפתחות api", "מפתחות",
        "secrets", "secret keys", "tokens",
        "credentials", "passwords", "password", "סיסמאות", "סיסמה",
        "access keys", "private keys", "keys",
    ]

    exfil_terms = [
        "send to my email", "email me", "to my email",
        "שלח לי למייל", "תשלח לי למייל", "שלח למייל",
        "send to slack", "שלח לסלאק",
        "webhook", "post to this url", "שלח לי ל",
    ]

    has_secret_word = any(t in q for t in secret_terms)
    has_exfil = any(t in q for t in exfil_terms)

    return has_secret_word or (has_secret_word and has_exfil)


def enforce_max_results(max_results: int, limit: int):
    if max_results <= 0:
        return True, "OK"
    if max_results > limit:
        return False, f"Too many results requested (max_results={max_results}, limit={limit})"
    return True, "OK"


def validate_github_query_qualifiers(query: str, allowed_qualifiers: list[str]):
    if not query:
        return False, "Empty query is not allowed"

    qualifiers = re.findall(r"\b[a-zA-Z_]+:\b", query)
    if not qualifiers:
        return True, "OK"

    allowed = set(allowed_qualifiers or [])
    for q in qualifiers:
        if q not in allowed:
            return False, f"Qualifier '{q}' is not allowed"
    return True, "OK"


def decide_for_chat(prompt: str, context: dict) -> Decision:
    """
    החלטת מדיניות עבור tool="chat".
    כאן מחליטים ALLOW/BLOCK על בסיס הטקסט של המשתמש + קונטקסט.
    """
    q = (prompt or "").strip()

    if not q:
        return Decision.allow("Empty prompt – allowing but logging.")

    # 1) בקשה מפורשת לסודות/API keys → BLOCK
    if looks_like_secrets_request(q):
        return Decision.block(
            "Blocked: user is requesting secrets/API keys (data exfiltration attempt).",
            {
                "attack_type": "data_exfiltration",
                "suspicion_score": 85,
                "indicator": "secrets_request",
            },
        )

    # 2) נסיונות dump של סודות / env / מפתחות → BLOCK
    if looks_like_secret_dump(q):
        return Decision.block(
            "Blocked: query resembles a secrets dump (env/keys/tokens).",
            {
                "attack_type": "data_exfiltration",
                "suspicion_score": 80,
                "indicator": "secret_dump",
            },
        )

    # ברירת מחדל: לא זיהינו שום דבר חריג → ALLOW
    return Decision.allow(
        "All security checks passed for chat.",
        {
            "attack_type": "none",
            "suspicion_score": 15,
        },
    )
