"""
GuardAI 2.0 - Policy API
Internal API for AI Judge LLM calls with BYOK support.
Inspired by Lasso Security's policy enforcement architecture.

Author: Chen Shaked
Date: 2026-01-18
"""

import os
import json
import logging
import time
from typing import Dict, Optional
from functools import wraps

# Try to import Groq/OpenAI clients
try:
    from groq import Groq
    GROQ_AVAILABLE = True
except ImportError:
    GROQ_AVAILABLE = False
    logging.warning("Groq not installed. Install with: pip install groq")

try:
    from openai import OpenAI
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False
    logging.warning("OpenAI not installed. Install with: pip install openai")

logging.basicConfig(level=logging.INFO)

# ===========================
# RATE LIMITING & RETRY
# ===========================

MAX_RETRIES = 3
INITIAL_BACKOFF = 0.5  # seconds

def retry_with_backoff(max_retries=MAX_RETRIES):
    """Decorator for retry logic with exponential backoff."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            retries = 0
            backoff = INITIAL_BACKOFF
            
            while retries < max_retries:
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    retries += 1
                    if retries >= max_retries:
                        logging.error(f"Max retries reached for {func.__name__}: {e}")
                        raise
                    
                    logging.warning(
                        f"Retry {retries}/{max_retries} for {func.__name__} "
                        f"after {backoff}s: {e}"
                    )
                    time.sleep(backoff)
                    backoff *= 2  # Exponential backoff
            
            return None
        return wrapper
    return decorator


# ===========================
# LLM CLIENT INITIALIZATION
# ===========================

def get_llm_client(provider: str, api_key: str):
    """
    Get appropriate LLM client based on provider.
    
    Args:
        provider: "groq" or "openai"
        api_key: API key for the provider
    
    Returns:
        LLM client instance
    """
    if provider == "groq":
        if not GROQ_AVAILABLE:
            raise ImportError("Groq not installed. Run: pip install groq")
        return Groq(api_key=api_key)
    
    elif provider == "openai":
        if not OPENAI_AVAILABLE:
            raise ImportError("OpenAI not installed. Run: pip install openai")
        return OpenAI(api_key=api_key)
    
    else:
        raise ValueError(f"Unsupported provider: {provider}")


# ===========================
# POLICY LLM CALL
# ===========================

@retry_with_backoff(max_retries=3)
def evaluate_prompt_with_llm(
    prompt: str,
    tool: str,
    context: Dict,
    tenant_id: Optional[str] = None,
    system_prompt: Optional[str] = None,
) -> Dict:
    """
    Call LLM to evaluate if a prompt is malicious.
    
    This is the core function called by ai_judge.py.
    
    Args:
        prompt: User's input prompt
        tool: Tool being accessed
        context: Additional context (tool_risk, actor, etc.)
        tenant_id: Tenant ID for BYOK
        system_prompt: Optional custom system prompt
    
    Returns:
        {
          "is_malicious": bool,
          "risk_level": str,
          "attack_type": str,
          "explanation": str,
          "attack_path": list,
          "confidence": float
        }
    """
    start_time = time.time()
    
    try:
        # Get LLM configuration (BYOK)
        llm_config = _get_policy_llm_config(tenant_id)
        
        # Get LLM client
        client = get_llm_client(llm_config["provider"], llm_config["api_key"])
        
        # Use provided system prompt or default
        if system_prompt is None:
            from policy_engine.ai_judge import POLICY_JUDGE_SYSTEM_PROMPT
            system_prompt = POLICY_JUDGE_SYSTEM_PROMPT
        
        # Build user message with context
        user_message = f"""Analyze this request for security threats:

**User Query:**
{prompt}

**Context:**
- Tool: {tool}
- Tool Risk Level: {context.get('tool_risk', 'unknown')}
- Actor: {context.get('actor', 'unknown')}
- Tenant: {tenant_id or 'default'}

Is this request malicious? Respond ONLY with JSON in the exact format specified."""

        # Call LLM
        response = _call_llm(
            client=client,
            model=llm_config["model"],
            provider=llm_config["provider"],
            system_prompt=system_prompt,
            user_message=user_message,
        )
        
        # Parse JSON response
        try:
            result = json.loads(response)
        except json.JSONDecodeError:
            # Try to extract JSON from markdown code blocks
            if "```json" in response:
                json_text = response.split("```json").split("```").strip()[1]
                result = json.loads(json_text)
            elif "```" in response:
                json_text = response.split("```")[1].split("```")[0].strip()
                result = json.loads(json_text)
            else:
                logging.error(f"Failed to parse LLM response as JSON: {response}")
                result = {
                    "is_malicious": False,
                    "risk_level": "low",
                    "attack_type": "none",
                    "explanation": "LLM response could not be parsed",
                    "attack_path": [],
                    "confidence": 0.0,
                }
        
        # Add metadata
        result["latency_ms"] = int((time.time() - start_time) * 1000)
        result["model_used"] = llm_config["model"]
        result["provider"] = llm_config["provider"]
        
        logging.info(
            f"✅ Policy LLM call successful | model={llm_config['model']} | "
            f"latency={result['latency_ms']}ms | malicious={result.get('is_malicious')}"
        )
        
        return result
    
    except Exception as e:
        logging.exception(f"Policy LLM call failed: {e}")
        
        # Return safe fallback
        return {
            "is_malicious": False,
            "risk_level": "unknown",
            "attack_type": "error",
            "explanation": f"Policy LLM unavailable: {str(e)}",
            "attack_path": [],
            "confidence": 0.0,
            "error": str(e),
            "latency_ms": int((time.time() - start_time) * 1000),
        }


def _call_llm(
    client,
    model: str,
    provider: str,
    system_prompt: str,
    user_message: str,
) -> str:
    """
    Call LLM with unified interface for Groq/OpenAI.
    
    Args:
        client: LLM client instance
        model: Model name
        provider: "groq" or "openai"
        system_prompt: System prompt
        user_message: User message
    
    Returns:
        LLM response text
    """
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_message},
    ]
    
    if provider == "groq":
        response = client.chat.completions.create(
            model=model,
            messages=messages,
            temperature=0.1,  # Low temperature for consistent security decisions
            max_tokens=1000,
            response_format={"type": "json_object"},  # Force JSON output
        )
        return response.choices[0].message.content
    
    elif provider == "openai":
        response = client.chat.completions.create(
            model=model,
            messages=messages,
            temperature=0.1,
            max_tokens=1000,
            response_format={"type": "json_object"},
        )
        return response.choices[0].message.content
    
    else:
        raise ValueError(f"Unsupported provider: {provider}")


def _get_policy_llm_config(tenant_id: Optional[str] = None) -> Dict:
    """
    Get LLM configuration for policy evaluation (BYOK support).
    
    Args:
        tenant_id: Optional tenant ID for tenant-specific keys
    
    Returns:
        {
          "api_key": str,
          "model": str,
          "provider": str
        }
    """
    # Check for tenant-specific policy key
    if tenant_id:
        tenant_key = os.getenv(f"TENANT_{tenant_id}_POLICY_KEY")
        if tenant_key:
            return {
                "api_key": tenant_key,
                "model": os.getenv(
                    f"TENANT_{tenant_id}_POLICY_MODEL",
                    "llama-3.1-8b-instant"
                ),
                "provider": os.getenv(
                    f"TENANT_{tenant_id}_POLICY_PROVIDER",
                    "groq"
                ),
            }
    
    # Fallback to shared GuardAI policy key
    return {
        "api_key": os.getenv("GUARDAI_POLICY_KEY", os.getenv("GROQ_API_KEY")),
        "model": os.getenv("GUARDAI_POLICY_MODEL", "llama-3.1-8b-instant"),
        "provider": os.getenv("GUARDAI_POLICY_PROVIDER", "groq"),
    }


# ===========================
# HEALTH CHECK
# ===========================

def health_check() -> Dict:
    """
    Check if policy API is healthy and can reach LLM providers.
    
    Returns:
        Health status dict
    """
    config = _get_policy_llm_config()
    
    status = {
        "status": "healthy",
        "provider": config["provider"],
        "model": config["model"],
        "api_key_configured": bool(config["api_key"]),
        "groq_available": GROQ_AVAILABLE,
        "openai_available": OPENAI_AVAILABLE,
    }
    
    # Quick test call
    try:
        test_result = evaluate_prompt_with_llm(
            prompt="Hello, this is a test",
            tool="chat.completion",
            context={"tool_risk": "low"},
            tenant_id=None,
        )
        status["test_call"] = "success"
        status["test_latency_ms"] = test_result.get("latency_ms")
    except Exception as e:
        status["status"] = "unhealthy"
        status["test_call"] = "failed"
        status["error"] = str(e)
    
    return status
