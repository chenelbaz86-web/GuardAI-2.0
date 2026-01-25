# guardai_gateway/guardai_engine_adapter.py
from typing import Dict, Any
from .models import GuardAIDecision, ChatCompletionRequest

def evaluate_prompt(req: ChatCompletionRequest, context: Dict[str, Any]) -> GuardAIDecision:
    # TODO: לקרוא לפונקציות / API שקיימים כבר ב-GuardAI שלך
    # כרגע fake:
    return GuardAIDecision(
        decision="allow",
        reason="no dangerous patterns detected",
        confidence=0.9,
    )

def evaluate_response(
    req: ChatCompletionRequest,
    response_json: Dict[str, Any],
    context: Dict[str, Any],
) -> GuardAIDecision:
    # TODO: חיבור אמיתי ל-GuardAI
    return GuardAIDecision(
        decision="allow",
        reason="no sensitive data leakage detected",
        confidence=0.9,
    )
