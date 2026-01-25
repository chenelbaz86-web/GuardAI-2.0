# llm-proxy/guardai_client.py
"""
GuardAI Client - Integration layer for calling GuardAI policy engine
"""
import os
import logging
import requests
from typing import Dict, Any, Optional, Tuple

GUARDAI_URL = os.getenv("GUARDAI_URL", "http://localhost:5001/check")
GUARDAI_TIMEOUT = int(os.getenv("GUARDAI_TIMEOUT", "5"))  # seconds


def check_with_guardai(
    prompt: str,
    context: Dict[str, Any],
    user_api_key: str,
    tenant_id: str,
    rid: str
) -> Tuple[bool, Dict[str, Any]]:
    """
    Call GuardAI policy engine to check if request is allowed.
    
    Args:
        prompt: User prompt/query
        context: Additional context (tool name, user_id, etc.)
        user_api_key: User's BYOK API key for AI calls
        tenant_id: Tenant identifier
        rid: Request ID for logging
    
    Returns:
        (is_allowed, response_data)
        - is_allowed: True if request should proceed
        - response_data: Full GuardAI response with decision details
    """
    try:
        payload = {
            "prompt": prompt,
            "context": {
                **context,
                "tenant_id": tenant_id,
                "request_id": rid,
                "source": "llm-proxy"
            },
            "api_key": user_api_key
        }
        
        logging.info(f"[RID {rid}] GuardAI check: prompt_len={len(prompt)}, context={context}")
        
        response = requests.post(
            GUARDAI_URL,
            json=payload,
            timeout=GUARDAI_TIMEOUT
        )
        
        if response.status_code == 200:
            data = response.json()
            allowed = data.get("allowed", False)
            decision = data.get("decision", "UNKNOWN")
            reason = data.get("reason", "")
            score = data.get("suspicion_score", 0)
            
            logging.info(
                f"[RID {rid}] GuardAI response: decision={decision}, "
                f"allowed={allowed}, score={score}, reason={reason[:100]}"
            )
            
            return allowed, data
        else:
            # GuardAI returned error - fail-open for chat, fail-closed for sensitive tools
            logging.warning(
                f"[RID {rid}] GuardAI error: status={response.status_code}, "
                f"body={response.text[:200]}"
            )
            
            # Check if this is a sensitive tool call
            is_sensitive_tool = context.get("tool") in ["github_search", "file_access", "code_execution"]
            
            if is_sensitive_tool:
                # Fail-closed for sensitive operations
                return False, {
                    "allowed": False,
                    "decision": "BLOCK",
                    "reason": "GuardAI unavailable - blocking sensitive operation for safety",
                    "suspicion_score": 0,
                    "fail_mode": "closed"
                }
            else:
                # Fail-open for regular chat
                return True, {
                    "allowed": True,
                    "decision": "ALLOW",
                    "reason": "GuardAI unavailable - allowing regular chat (fail-open)",
                    "suspicion_score": 0,
                    "fail_mode": "open"
                }
                
    except requests.exceptions.Timeout:
        logging.error(f"[RID {rid}] GuardAI timeout after {GUARDAI_TIMEOUT}s")
        
        # Same fail-open/closed logic as above
        is_sensitive_tool = context.get("tool") in ["github_search", "file_access", "code_execution"]
        
        if is_sensitive_tool:
            return False, {
                "allowed": False,
                "decision": "BLOCK",
                "reason": "GuardAI timeout - blocking sensitive operation",
                "suspicion_score": 0,
                "fail_mode": "closed"
            }
        else:
            return True, {
                "allowed": True,
                "decision": "ALLOW",
                "reason": "GuardAI timeout - allowing regular chat (fail-open)",
                "suspicion_score": 0,
                "fail_mode": "open"
            }
            
    except Exception as e:
        logging.exception(f"[RID {rid}] GuardAI exception: {str(e)}")
        
        # Same fail-open/closed logic
        is_sensitive_tool = context.get("tool") in ["github_search", "file_access", "code_execution"]
        
        if is_sensitive_tool:
            return False, {
                "allowed": False,
                "decision": "BLOCK",
                "reason": f"GuardAI error - blocking sensitive operation: {str(e)[:100]}",
                "suspicion_score": 0,
                "fail_mode": "closed"
            }
        else:
            return True, {
                "allowed": True,
                "decision": "ALLOW",
                "reason": f"GuardAI error - allowing regular chat (fail-open): {str(e)[:100]}",
                "suspicion_score": 0,
                "fail_mode": "open"
            }
