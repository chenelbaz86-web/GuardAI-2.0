# shadow_gateway/main.py

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from typing import Dict, Any

from .config import settings
from .models import ChatCompletionRequest
from .proxy import call_upstream_llm
from .guardai_engine_adapter import evaluate_prompt, evaluate_response
from .shadow_ai_discovery import build_shadow_event, persist_shadow_event

app = FastAPI(title="Shadow Gateway")


@app.post("/v1/chat/completions")
async def chat_completions(request: Request):
    body: Dict[str, Any] = await request.json()
    req = ChatCompletionRequest(**body)

    # Normalize model name from tools like Cursor → Groq model
    model_mapping = {
    "OpenAI Compatible": "gpt-4o",
    "openai-compatible": "gpt-4o",
}


    req.model = model_mapping.get(req.model, req.model)

    # Basic context from headers
    context = {
        "client_ip": request.client.host if request.client else None,
        "user_agent": request.headers.get("user-agent"),
        "x_agent_id": request.headers.get("x-agent-id"),
        "x_user_id": request.headers.get("x-user-id"),
    }

    # 1. Shadow event on request
    shadow_req = build_shadow_event(
        req,
        direction="request",
        payload=body,
        tool_name="openai-chat",
        agent_id=context["x_agent_id"],
        user_id=context["x_user_id"],
    )
    persist_shadow_event(shadow_req)

    # 2. GuardAI – prompt evaluation
    prompt_decision = evaluate_prompt(req, context)

    if settings.GUARDAI_MODE == "enforce" and prompt_decision.decision == "block":
        raise HTTPException(
            status_code=400,
            detail={
                "error": "blocked_by_guardai",
                "reason": prompt_decision.reason,
                "confidence": prompt_decision.confidence,
            },
        )

    # 3. Call upstream LLM (proxy.py כבר מדפיס שגיאות HTTP)
    upstream_response = await call_upstream_llm(req)

    # 4. JSON response – full GuardAI + Shadow
    if isinstance(upstream_response, dict):
        response_decision = evaluate_response(req, upstream_response, context)

        if settings.GUARDAI_MODE == "enforce" and response_decision.decision == "block":
            return JSONResponse(
                status_code=200,
                content={
                    "id": "guardai_block",
                    "object": "chat.completion",
                    "choices": [
                        {
                            "index": 0,
                            "finish_reason": "stop",
                            "message": {
                                "role": "assistant",
                                "content": "The response was blocked by GuardAI due to policy violation.",
                            },
                        }
                    ],
                    "guardai_meta": {
                        "blocked": True,
                        "reason": response_decision.reason,
                        "confidence": response_decision.confidence,
                    },
                },
            )

        shadow_resp = build_shadow_event(
            req,
            direction="response",
            payload=upstream_response,
            tool_name="openai-chat",
            agent_id=context["x_agent_id"],
            user_id=context["x_user_id"],
        )
        persist_shadow_event(shadow_resp)

        return JSONResponse(content=upstream_response)

    # 5. Non-JSON (e.g., streaming text) – basic Shadow + raw wrap
    shadow_resp = build_shadow_event(
        req,
        direction="response",
        payload={"text": str(upstream_response)},
        tool_name="openai-chat",
        agent_id=context["x_agent_id"],
        user_id=context["x_user_id"],
    )
    persist_shadow_event(shadow_resp)

    return JSONResponse(content={"raw": upstream_response})


# Compatibility route for tools that call /chat/completions (e.g., Cursor)
@app.post("/chat/completions")
async def chat_completions_compat(request: Request):
    return await chat_completions(request)
