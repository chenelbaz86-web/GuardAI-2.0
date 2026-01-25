# guardai_gateway/models.py
from typing import List, Optional, Any
from pydantic import BaseModel

class ChatMessage(BaseModel):
    role: str
    content: str

class ChatCompletionRequest(BaseModel):
    model: str
    messages: List[ChatMessage]
    temperature: Optional[float] = 0.7
    max_tokens: Optional[int] = None
    stream: Optional[bool] = False

class GuardAIDecision(BaseModel):
    decision: str  # allow | block
    reason: str
    confidence: float

class ShadowEvent(BaseModel):
    tool_name: str           # למשל "openai-chat"
    agent_id: Optional[str]  # מזהה אפליקציה/agent אם יש
    user_id: Optional[str]
    model: str
    endpoint: str
    direction: str           # request | response
    payload_preview: str
    risk_score: float
