"""
GuardAI 2.0 - GitHub Gateway
Entry point for GitHub tool requests with improved error handling.

Author: Chen Shaked
Date: 2026-01-18 (Updated)
"""

from flask import Flask, request, jsonify
import os
import sys
import logging

# Allow import from ../policy-engine
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "policy-engine")))

try:
    from guardai_client import check_github_search_with_guardai
except ImportError as e:
    logging.error(f"Failed to import policy_engine: {e}")
    logging.error("Make sure policy-engine is in PYTHONPATH")
    raise

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)

app = Flask(__name__)

@app.route("/health", methods=["GET"])
def health():
    """Health check endpoint."""
    return jsonify({
        "status": "healthy",
        "service": "github-gateway",
        "version": "2.0"
    })

@app.post("/github/search_code")
def search_code():
    """
    Expect body:
    {
        "parameters": {"query":"...", "max_results": 5},
        "meta": {...},
        "api_key": "user_groq_api_key"  # BYOK - optional, falls back to DEFAULT_GROQ_API_KEY
    }
    """
    body = request.get_json(force=True, silent=True) or {}
    
    # Extract parameters
    parameters = body.get("parameters") or {}
    meta = body.get("meta") or {}
    query = parameters.get("query", "")
    user_api_key = body.get("api_key", os.getenv("DEFAULT_GROQ_API_KEY", ""))
    
    
    allowed, guardai_response = check_github_search_with_guardai(
        query=query,
        parameters=parameters,
        meta=meta,
        user_api_key=user_api_key
    )
    
    # Detailed logging
    logging.info({
        "tool": "github.search_code",
        "decision": guardai_response.get("decision"),
        "allowed": allowed,
        "reason": guardai_response.get("reason", "")[:200],
        "suspicion_score": guardai_response.get("suspicion_score", 0),
        "query": query[:100],
        "actor": meta.get("actor"),
        "ip": request.remote_addr
    })
    
    # Block if GuardAI says no
    if not allowed:
        block_reason = guardai_response.get("reason", "Request blocked by security policy")
        attack_path = guardai_response.get("attack_path", "")
        
        return jsonify({
            "error": "blocked",
            "decision": guardai_response.get("decision"),
            "message": block_reason,
            "attack_path": attack_path,
            "suspicion_score": guardai_response.get("suspicion_score", 0),
            "guardai_response": guardai_response
        }), 403
    # ===== End GuardAI Check =====
    
    # GuardAI allowed - proceed with GitHub API call
    # כאן בדמו אנחנו מחזירים תוצאה מזויפת.
    # בפועל: תקראי ל-GitHub API /search/code עם טוקן מוגבל הרשאות.
    return jsonify({
        "results": [
            {"file": "README.md", "snippet": "dummy result"}
        ],
        "guardai_decision": {
            "decision": guardai_response.get("decision"),
            "suspicion_score": guardai_response.get("suspicion_score", 0),
            "reason": guardai_response.get("reason", "")
        }
    })


if __name__ == "__main__":
    port = int(os.getenv("GITHUB_GATEWAY_PORT", 8001))
    app.run(host="0.0.0.0", port=port, debug=True)
