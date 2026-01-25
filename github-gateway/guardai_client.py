"""
GuardAI Client for GitHub Gateway - Integration with GuardAI policy engine
"""
import os
import logging
import requests
from typing import Dict, Any, Tuple

GUARDAI_URL = os.getenv("GUARDAI_URL", "http://localhost:5001/check")
GUARDAI_TIMEOUT = int(os.getenv("GUARDAI_TIMEOUT", "5"))


def check_github_search_with_guardai(
    query: str,
    parameters: Dict[str, Any],
    meta: Dict[str, Any],
    user_api_key: str
) -> Tuple[bool, Dict[str, Any]]:
    """
    Check GitHub search request with GuardAI before executing.
    
    Args:
        query: Search query string
        parameters: Additional search parameters
        meta: Metadata (actor, IP, etc.)
        user_api_key: User's BYOK API key
    
    Returns:
        (is_allowed, response_data)
    """
    try:
        # Build prompt from search query
        prompt = f"GitHub code search: {query}"
        
        context = {
            "tool": "github_search",
            "parameters": parameters,
            "actor": meta.get("actor", "unknown"),
            "source": "github-gateway"
        }
        
        payload = {
            "prompt": prompt,
            "context": context,
            "api_key": user_api_key
        }
        
        logging.info(f"GuardAI check for GitHub search: query={query[:100]}")
        
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
                f"GuardAI response: decision={decision}, allowed={allowed}, "
                f"score={score}, reason={reason[:80]}"
            )
            
            return allowed, data
        else:
            # GitHub search is a SENSITIVE tool - fail-closed
            logging.warning(
                f"GuardAI error: status={response.status_code}, "
                f"body={response.text[:200]}"
            )
            
            return False, {
                "allowed": False,
                "decision": "BLOCK",
                "reason": "GuardAI unavailable - blocking sensitive GitHub search (fail-closed)",
                "suspicion_score": 0,
                "fail_mode": "closed"
            }
            
    except requests.exceptions.Timeout:
        logging.error(f"GuardAI timeout after {GUARDAI_TIMEOUT}s")
        
        # Fail-closed for GitHub search (sensitive tool)
        return False, {
            "allowed": False,
            "decision": "BLOCK",
            "reason": "GuardAI timeout - blocking GitHub search for safety",
            "suspicion_score": 0,
            "fail_mode": "closed"
        }
        
    except Exception as e:
        logging.exception(f"GuardAI exception: {str(e)}")
        
        # Fail-closed for GitHub search
        return False, {
            "allowed": False,
            "decision": "BLOCK",
            "reason": f"GuardAI error - blocking GitHub search: {str(e)[:100]}",
            "suspicion_score": 0,
            "fail_mode": "closed"
        }
