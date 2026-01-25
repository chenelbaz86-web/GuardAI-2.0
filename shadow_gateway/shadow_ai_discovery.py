# shadow_gateway/shadow_ai_discovery.py
from typing import Optional, Dict, Any
from .models import ShadowEvent, ChatCompletionRequest

def build_shadow_event(
    req: ChatCompletionRequest,
    direction: str,
    payload: Dict[str, Any],
    tool_name: str = "openai-chat",
    agent_id: Optional[str] = None,
    user_id: Optional[str] = None,
) -> ShadowEvent:
    text_preview = ""
    if direction == "request" and req.messages:
        text_preview = req.messages[-1].content[:200]
    elif direction == "response":
        text_preview = str(payload)[:200]

    risk_score = 0.5  # TODO: חישוב אמיתי

    return ShadowEvent(
        tool_name=tool_name,
        agent_id=agent_id,
        user_id=user_id,
        model=req.model,
        endpoint="/v1/chat/completions",
        direction=direction,
        payload_preview=text_preview,
        risk_score=risk_score,
    )

def persist_shadow_event(event: ShadowEvent) -> None:
    print(f"[SHADOW] {event.json()}")