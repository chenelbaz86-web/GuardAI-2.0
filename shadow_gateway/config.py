# shadow_gateway/config.py

from pydantic_settings import BaseSettings
from pydantic import AnyHttpUrl


class Settings(BaseSettings):
    """
    הגדרות ה-Shadow Gateway:
    - GUARDAI_MODE: shadow | enforce | off
    - UPSTREAM_LLM_URL: כתובת ה-LLM שהגייטווי קורא אליו (OpenAI-compatible)
    - UPSTREAM_LLM_API_KEY: המפתח של ה-LLM (לא זה של הלקוח)
    """

    GUARDAI_MODE: str = "shadow"

    # ברירת מחדל: Groq OpenAI-compatible
    UPSTREAM_LLM_URL: AnyHttpUrl = "https://api.openai.com/v1/chat/completions"
    UPSTREAM_LLM_API_KEY: str = "openai_dummy_key"


    class Config:
        env_file = ".env"
        extra = "ignore"


settings = Settings()