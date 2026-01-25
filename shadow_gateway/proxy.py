# shadow_gateway/proxy.py
import httpx
from .config import settings
from .models import ChatCompletionRequest

async def call_upstream_llm(req: ChatCompletionRequest) -> dict | str:
    headers = {
        "Authorization": f"Bearer {settings.UPSTREAM_LLM_API_KEY}",
        "Content-Type": "application/json",
    }

    async with httpx.AsyncClient(timeout=60.0) as client:
        r = await client.post(
            str(settings.UPSTREAM_LLM_URL),
            headers=headers,
            json=req.dict(),
        )
        try:
            r.raise_for_status()
        except httpx.HTTPStatusError as e:
            print("UPSTREAM ERROR:", r.status_code, r.text)
            raise

        content_type = r.headers.get("content-type", "")
        if "application/json" in content_type:
            return r.json()
        else:
            # לדוגמה: text/event-stream או טקסט רגיל
            return r.text
