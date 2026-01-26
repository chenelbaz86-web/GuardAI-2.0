"""
GuardAI 2.0 - Flask API Server
Wraps the policy engine with REST API
"""

from flask import Flask, request, jsonify
import logging
import uuid
from datetime import datetime
from dotenv import load_dotenv
import os
from policy_engine import evaluate  # כמו שהיה קודם

from policies import decide_for_chat, Decision  # ← שימי לב: מ-importים את policies.py החדש


# טען .env בהתחלה
load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)

# בדיקה שהמפתח נטען (אופציונלי, רק לוג)
if os.getenv("GROQ_API_KEY"):
    logging.info("✅ GROQ_API_KEY loaded in app.py")
else:
    logging.warning("❌ GROQ_API_KEY not found in app.py")


app = Flask(__name__)


@app.route("/health", methods=["GET"])
def health():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "service": "GuardAI 2.0 Policy Engine",
        "version": "2.0.0"
    })


@app.route("/check", methods=["POST"])
def check():
    """
    Main security check endpoint

    Expects JSON:
    {
        "prompt": "user query",
        "context": {
            "tool": "chat" | "github_search" | ...,
            "tenant_id": "...",
            "user_id": "...",
            "source": "llm-proxy",
            "request_id": "..."
        },
        "api_key": "user_groq_key"
    }

    Returns JSON:
    {
        "allowed": true/false,
        "decision": "ALLOW" | "BLOCK",
        "reason": "...",
        "suspicion_score": 0-100,
        "details": { ... },
        "attack_type": "data_exfiltration" | "none" | ...
    }
    """
    try:
        data = request.get_json(force=True) or {}

        prompt = data.get("prompt", "") or ""
        context = data.get("context", {}) or {}
        tool = context.get("tool", "chat")

        # אפשר להרחיב בעתיד לכלי נוספים (github_search וכו')
        if tool == "chat":
            decision_obj: Decision = decide_for_chat(prompt, context)
        else:
            # כרגע אין הבדל – אפשר להוסיף decide_for_github וכו'
            decision_obj: Decision = decide_for_chat(prompt, context)

        result = decision_obj.to_dict()

        # נבנה תגובה בפורמט שה-llm-proxy מצפה לו
        decision = result.get("decision", "BLOCK")
        allowed = result.get("allowed", False)

        response = {
            "allowed": allowed,
            "decision": decision,
            "reason": result.get("reason", ""),
            "suspicion_score": result.get("suspicion_score", 0),
            "details": result.get("details", {}),
            "attack_type": result.get("attack_type", "none"),
            # NEW: העברה מפורשת ל-proxy
            "prompt": prompt,
            "context": context,
        }


        status_code = 200 if allowed else 403
        logging.info(
            f"[PolicyEngine] tool={tool} allowed={allowed} "
            f"decision={decision} score={response['suspicion_score']} "
            f"reason={response['reason'][:80]}"
        )

        return jsonify(response), status_code

    except Exception as e:
        logging.exception(f"Error in /check endpoint: {str(e)}")
        return jsonify({
            "allowed": False,
            "decision": "ERROR",
            "reason": f"Internal error: {str(e)[:100]}",
            "suspicion_score": 0,
            "details": {"fail_mode": "error"},
        }), 500


if __name__ == "__main__":
    port = int(os.getenv("PORT", "5001"))
    logging.info(f"🚀 GuardAI 2.0 Policy Engine running on http://0.0.0.0:{port}")
    app.run(host="0.0.0.0", port=port, debug=True)
