"""
GuardAI 2.0 - Policy Engine with 3-Tier Architecture
Tier 1: Pattern-Based (Regex/Heuristics)
Tier 2: Guardrails AI (ML-based)
Tier 3: LLM Judge (AI Decision-Making)

Inspired by Lasso Security's multi-layered approach.

Author: Chen Shaked
Date: 2026-01-20 (Updated - Added critical pattern immediate blocking)
"""

import os
import yaml
import logging
import uuid
from datetime import datetime
from typing import Dict

# Import existing modules
from policies import (
    Decision,
    redact_text,
    contains_sensitive,
    looks_like_secret_dump,
    enforce_max_results,
    validate_github_query_qualifiers,
)

# Import GuardAI 2.0 modules
from heuristics import (
    calculate_suspicion_score,
    should_invoke_ai_judge,
    get_tool_risk_level,
    extract_query_from_action_plan,
    get_context_summary,
    get_matched_patterns,
)

from ai_judge import call_llm_judge, PolicyAIException, PolicyAIUnavailable
from decision_logger import log_decision, log_attack_attempt, collect_training_sample

# Import Guardrails integration (existing)
try:
    from guardrails_integration import validate_with_guardrails
    GUARDRAILS_AVAILABLE = True
except ImportError:
    GUARDRAILS_AVAILABLE = False
    logging.warning("Guardrails not available")

logging.basicConfig(level=logging.INFO)

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
RULES_PATH = os.path.join(ROOT_DIR, "rules.yaml")

DEFAULTS = {
    "max_results_limit": 3,
    "block_on_sensitive": True,
    "redact_sensitive_in_logs": True,
    "allowed_qualifiers": ["repo:", "org:", "user:", "path:", "language:", "filename:"],
    "sensitive_patterns": [
        r"password",
        r"secret",
        r"api[_-]?key",
        r"token",
        r"authorization:\s*bearer\s+\S+",
        r"-----begin\s+.*private\s+key-----",
    ],
    "github": {
        "search_code": {
            "max_results_limit": 3,
            "block_if_query_contains_sensitive": True,
            "block_if_query_looks_like_secret_dump": True,
        }
    },
    # GuardAI 2.0 settings
    "ai_judge": {
        "enabled": True,
        "fail_mode": {
            "chat": "open",  # fail-open for low-risk
            "tools_sensitive": "closed",  # fail-closed for high-risk
        }
    }
}

def load_rules():
    """Load rules from rules.yaml with defaults."""
    try:
        with open(RULES_PATH, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        return {**DEFAULTS, **data}
    except FileNotFoundError:
        logging.warning(f"rules.yaml not found, using defaults")
        return DEFAULTS

def evaluate(action_plan: dict) -> dict:
    """
    GuardAI 2.0 - Evaluate action plan with 3-Tier architecture.
    
    Tier 1: Pattern-Based (Regex, Heuristics) - Always runs
    Tier 2: Guardrails AI (ML-based) - If suspicion > threshold
    Tier 3: LLM Judge (Context-aware AI) - Smart invocation
    
    Args:
        action_plan: {
            "tool": str,
            "parameters": dict,
            "meta": {
                "tenant_id": str,
                "actor": str,
                ...
            }
        }
    
    Returns:
        {
            "decision": "ALLOW" | "BLOCK",
            "reason": str,
            "details": dict
        }
    """
    request_id = str(uuid.uuid4())
    rules = load_rules()
    
    tool = (action_plan.get("tool") or "").strip()
    params = action_plan.get("parameters") or {}
    meta = action_plan.get("meta") or {}
    tenant_id = meta.get("tenant_id", "default")
    
    # Extract query from different formats
    query = extract_query_from_action_plan(action_plan)
    max_results = int(params.get("max_results") or 0)
    
    logging.info(f"🔍 [{request_id[:8]}] Evaluating: tool={tool}, tenant={tenant_id}")
    
    # ==========================================
    # TIER 1: PATTERN-BASED (Always runs)
    # ==========================================
    
    # 1.1 Calculate suspicion score
    suspicion_score, tier1_reason, tier1_details = calculate_suspicion_score(query, tool)
    matched_patterns = get_matched_patterns(query)
    
    logging.info(f"📊 [{request_id[:8]}] Suspicion score: {suspicion_score}/100")
    
    # 1.1.5 ✨ NEW: High suspicion OR critical patterns = immediate block
    critical_categories = {"social_engineering", "indirect_command", "homoglyph_detection"}

    detected_categories = {p["category"] for p in matched_patterns}
    
    # Block on high score OR critical pattern detection
    if suspicion_score >= 80 or (detected_categories & critical_categories):
        if detected_categories & critical_categories:
            reason = f"Critical attack pattern detected (Tier 1): {', '.join(detected_categories & critical_categories)}"
        else:
            reason = f"High suspicion score (Tier 1): {suspicion_score}/100"
        
        _log_and_return_block(
            request_id, tenant_id, query, tool, reason,
            {
                "suspicion_score": suspicion_score,
                "matched_patterns": [p["category"] for p in matched_patterns[:3]],
                "tier1_details": tier1_details,
                "critical_patterns": list(detected_categories & critical_categories)
            },
            suspicion_score, matched_patterns
        )
        return Decision.block(
            reason,
            {
                "suspicion_score": suspicion_score,
                "tier": "tier1_heuristics",
                "patterns": [p["category"] for p in matched_patterns[:3]],
                "critical_patterns": list(detected_categories & critical_categories)
            }
        ).to_dict()
    
    # 1.2 Legacy checks (from original GuardAI)
    ok, reason = enforce_max_results(max_results, rules["max_results_limit"])
    if not ok:
        _log_and_return_block(
            request_id, tenant_id, query, tool, reason,
            {"max_results": max_results}, suspicion_score, matched_patterns
        )
        return Decision.block(reason, {"max_results": max_results}).to_dict()
    
    ok, reason = validate_github_query_qualifiers(query, rules["allowed_qualifiers"])
    if not ok:
        _log_and_return_block(
            request_id, tenant_id, query, tool, reason,
            {"query": query[:100]}, suspicion_score, matched_patterns
        )
        return Decision.block(reason, {"query": query[:50]}).to_dict()
    
    # 1.3 Sensitive patterns (legacy)
    if rules["block_on_sensitive"]:
        if contains_sensitive(query, rules["sensitive_patterns"]) or looks_like_secret_dump(query):
            reason = "Sensitive/secret pattern detected (Tier 1)"
            _log_and_return_block(
                request_id, tenant_id, query, tool, reason,
                {"query_redacted": redact_text(query, rules["sensitive_patterns"])},
                suspicion_score, matched_patterns
            )
            return Decision.block(
                reason,
                {"query_redacted": redact_text(query, rules["sensitive_patterns"])}
            ).to_dict()
    
    # ==========================================
    # TIER 2: GUARDRAILS AI (If enabled)
    # ==========================================
    
    if GUARDRAILS_AVAILABLE and suspicion_score >= 30:
        logging.info(f"🛡️ [{request_id[:8]}] Tier 2: Guardrails AI activated")
        gr_result = validate_with_guardrails(query, validation_type="input")
        
        if not gr_result.get("valid", True):
            reason = f"Guardrails blocked (Tier 2): {', '.join(gr_result.get('errors', []))}"
            _log_and_return_block(
                request_id, tenant_id, query, tool, reason,
                {"guardrails": gr_result}, suspicion_score, matched_patterns
            )
            return Decision.block(reason, {"guardrails": gr_result}).to_dict()
    
    # ==========================================
    # TIER 3: LLM JUDGE (Smart invocation)
    # ==========================================
    
    tool_risk = get_tool_risk_level(tool)
    ai_judge_enabled = rules.get("ai_judge", {}).get("enabled", True)
    
    if ai_judge_enabled and should_invoke_ai_judge(suspicion_score, tool_risk):
        logging.info(f"🤖 [{request_id[:8]}] Tier 3: AI Judge activated")
        
        context = get_context_summary(action_plan)
        
        try:
            ai_result = call_llm_judge(
                query=query,
                tool=tool,
                context=context,
                tenant_id=tenant_id
            )
            
            if ai_result.get("is_malicious"):
                # AI Judge says BLOCK
                reason = f"AI Judge: {ai_result.get('attack_type', 'unknown')} detected"
                
                # Log attack attempt
                log_attack_attempt(
                    tenant_id=tenant_id,
                    attack_type=ai_result.get("attack_type"),
                    attack_path=ai_result.get("attack_path", []),
                    query_preview=query[:100],
                    tool=tool,
                    confidence=ai_result.get("confidence", 0),
                )
                
                # Log decision
                log_decision(
                    request_id=request_id,
                    tenant_id=tenant_id,
                    query=query,
                    tool=tool,
                    decision="BLOCK",
                    reason=reason,
                    details={
                        "ai_judge": ai_result,
                        "tier": "tier3_ai_judge"
                    },
                    suspicion_score=suspicion_score,
                    ai_judge_result=ai_result,
                    matched_patterns=matched_patterns,
                )
                
                # Collect training sample
                collect_training_sample(
                    query=query,
                    tool=tool,
                    decision="BLOCK",
                    suspicion_score=suspicion_score,
                    ai_judge_result=ai_result,
                )
                
                return Decision.block(
                    reason,
                    {
                        "ai_policy": ai_result,
                        "explanation": ai_result.get("explanation"),
                        "attack_path": ai_result.get("attack_path", []),
                        "confidence": ai_result.get("confidence"),
                    }
                ).to_dict()
            
        except (PolicyAIUnavailable, PolicyAIException) as e:
            logging.error(f"⚠️ [{request_id[:8]}] AI Judge error: {e}")
            
            # Fail-safe handling based on tool risk
            fail_mode_key = "tools_sensitive" if tool_risk in ["high", "critical"] else "chat"
            fail_mode = rules.get("ai_judge", {}).get("fail_mode", {}).get(fail_mode_key, "open")
            
            if fail_mode == "closed":
                # Fail-closed: BLOCK when AI unavailable for sensitive tools
                reason = "AI Judge unavailable - fail-closed for sensitive tool"
                _log_and_return_block(
                    request_id, tenant_id, query, tool, reason,
                    {"error": str(e), "fail_mode": "closed"}, suspicion_score, matched_patterns
                )
                return Decision.block(reason, {"error": str(e)}).to_dict()
            else:
                # Fail-open: Continue with static rules only
                logging.warning(f"⚠️ [{request_id[:8]}] Fail-open: AI unavailable, continuing")
    
    # ==========================================
    # ALL TIERS PASSED - ALLOW
    # ==========================================
    
    reason = "All security tiers passed"
    
    log_decision(
        request_id=request_id,
        tenant_id=tenant_id,
        query=query,
        tool=tool,
        decision="ALLOW",
        reason=reason,
        details={"tiers": ["tier1", "tier2", "tier3"]},
        suspicion_score=suspicion_score,
        matched_patterns=matched_patterns,
    )
    
    # Collect training sample
    collect_training_sample(
        query=query,
        tool=tool,
        decision="ALLOW",
        suspicion_score=suspicion_score,
    )
    
    logging.info(f"✅ [{request_id[:8]}] ALLOW: {reason}")
    
    return Decision.allow(reason).to_dict()

def _log_and_return_block(
    request_id: str,
    tenant_id: str,
    query: str,
    tool: str,
    reason: str,
    details: dict,
    suspicion_score: int,
    matched_patterns: list,
):
    """Helper to log BLOCK decisions."""
    log_decision(
        request_id=request_id,
        tenant_id=tenant_id,
        query=query,
        tool=tool,
        decision="BLOCK",
        reason=reason,
        details=details,
        suspicion_score=suspicion_score,
        matched_patterns=matched_patterns,
    )
    logging.warning(f"🚨 [{request_id[:8]}] BLOCK: {reason}")
