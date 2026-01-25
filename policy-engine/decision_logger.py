"""
GuardAI 2.0 - Decision Logger
Immutable logging of all policy decisions for audit trail.
Inspired by Lasso Security's cryptographic logging approach.

Author: Chen Shaked
Date: 2026-01-18
"""

import os
import json
import hashlib
import logging
from datetime import datetime
from typing import Dict, Optional
from pathlib import Path

logging.basicConfig(level=logging.INFO)

# ===========================
# CONFIGURATION
# ===========================

LOGS_DIR = Path("logs/decisions")
LOGS_DIR.mkdir(parents=True, exist_ok=True)

# ===========================
# DECISION LOGGING
# ===========================

def log_decision(
    request_id: str,
    tenant_id: str,
    query: str,
    tool: str,
    decision: str,
    reason: str,
    details: Dict,
    suspicion_score: int = 0,
    ai_judge_result: Optional[Dict] = None,
    matched_patterns: Optional[list] = None,
) -> None:
    """
    Log a policy decision with full context for audit trail.
    
    Args:
        request_id: Unique request identifier
        tenant_id: Tenant/organization ID
        query: User's original query (hashed for privacy)
        tool: Tool being accessed
        decision: ALLOW or BLOCK
        reason: Human-readable reason
        details: Additional decision metadata
        suspicion_score: Heuristic suspicion score (0-100)
        ai_judge_result: AI Judge decision details
        matched_patterns: List of matched heuristic patterns
    """
    try:
        # Hash query for privacy (don't store full query in logs)
        query_hash = hashlib.sha256(query.encode()).hexdigest()[:16]
        
        # Build log entry
        log_entry = {
            "request_id": request_id,
            "tenant_id": tenant_id,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "query_hash": query_hash,
            "query_preview": query[:50] + "..." if len(query) > 50 else query,  # First 50 chars only
            "tool": tool,
            "decision": decision,
            "reason": reason,
            "suspicion_score": suspicion_score,
            "tiers_activated": _get_tiers_activated(suspicion_score, ai_judge_result),
            "matched_patterns": matched_patterns or [],
            "ai_judge": ai_judge_result,
            "details": details,
        }
        
        # Write to daily log file (JSONL format)
        log_file = LOGS_DIR / f"{datetime.utcnow().strftime('%Y-%m-%d')}.jsonl"
        
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(log_entry, ensure_ascii=False) + "\n")
        
        # Also log to console for immediate visibility
        emoji = "🚨" if decision == "BLOCK" else "✅"
        logging.info(
            f"{emoji} Decision logged | {decision} | {tool} | "
            f"score={suspicion_score} | reason={reason[:50]}"
        )
    
    except Exception as e:
        logging.exception(f"Failed to log decision: {e}")


def _get_tiers_activated(suspicion_score: int, ai_judge_result: Optional[Dict]) -> list:
    """Determine which tiers were activated based on the decision flow."""
    tiers = ["tier1_regex"]  # Always runs
    
    if suspicion_score >= 30:
        tiers.append("tier2_guardrails")
    
    if ai_judge_result and not ai_judge_result.get("error"):
        tiers.append("tier3_ai_judge")
    
    return tiers


# ===========================
# ATTACK PATH LOGGING
# ===========================

def log_attack_attempt(
    tenant_id: str,
    attack_type: str,
    attack_path: list,
    query_preview: str,
    tool: str,
    confidence: float,
) -> None:
    """
    Log a detected attack attempt with detailed attack path.
    This creates a separate log for security monitoring/alerting.
    
    Args:
        tenant_id: Tenant identifier
        attack_type: Type of attack detected
        attack_path: Step-by-step attack reconstruction
        query_preview: Preview of the malicious query
        tool: Tool that was targeted
        confidence: AI Judge confidence score
    """
    try:
        attack_log_file = LOGS_DIR / "attacks.jsonl"
        
        log_entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "tenant_id": tenant_id,
            "attack_type": attack_type,
            "attack_path": attack_path,
            "query_preview": query_preview,
            "tool": tool,
            "confidence": confidence,
            "severity": _calculate_severity(attack_type, tool),
        }
        
        with open(attack_log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(log_entry, ensure_ascii=False) + "\n")
        
        logging.warning(
            f"🚨 Attack detected | {attack_type} | tenant={tenant_id} | "
            f"confidence={confidence:.2f}"
        )
    
    except Exception as e:
        logging.exception(f"Failed to log attack: {e}")


def _calculate_severity(attack_type: str, tool: str) -> str:
    """Calculate attack severity based on type and target."""
    high_risk_tools = ["database.execute", "filesystem.write", "github.search_code"]
    
    if attack_type in ["data_exfiltration", "privilege_escalation"]:
        return "critical"
    elif attack_type in ["prompt_injection", "tool_abuse"] and tool in high_risk_tools:
        return "high"
    elif attack_type == "jailbreak":
        return "medium"
    else:
        return "low"


# ===========================
# TRAINING DATA COLLECTION
# ===========================

def collect_training_sample(
    query: str,
    tool: str,
    decision: str,
    suspicion_score: int,
    ai_judge_result: Optional[Dict] = None,
    manual_label: Optional[str] = None,
) -> None:
    """
    Collect samples for future ML training / Fine-tuning.
    
    This creates a dataset that can be used later to:
    1. Train ML classifiers (Tier 2.5)
    2. Fine-tune the LLM Judge
    
    Args:
        query: User's original query
        tool: Tool accessed
        decision: ALLOW or BLOCK
        suspicion_score: Heuristic score
        ai_judge_result: AI Judge decision
        manual_label: Optional manual review label
    """
    try:
        training_file = Path("data/training_samples.jsonl")
        training_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Extract features for ML
        features = {
            "length": len(query),
            "word_count": len(query.split()),
            "has_code": bool("```" in query or "`" in query),
            "has_urls": bool("http" in query.lower()),
            "has_base64": bool(len([w for w in query.split() if len(w) > 30]) > 0),
            "suspicion_score": suspicion_score,
        }
        
        sample = {
            "query": query,
            "tool": tool,
            "features": features,
            "label": manual_label or decision,
            "ai_judge": ai_judge_result,
            "timestamp": datetime.utcnow().isoformat() + "Z",
        }
        
        with open(training_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(sample, ensure_ascii=False) + "\n")
    
    except Exception as e:
        logging.exception(f"Failed to collect training sample: {e}")


# ===========================
# LOG ANALYSIS HELPERS
# ===========================

def get_daily_stats(date: str = None) -> Dict:
    """
    Get statistics for a specific day.
    
    Args:
        date: Date in YYYY-MM-DD format (default: today)
    
    Returns:
        Statistics dict with counts by decision, attack type, etc.
    """
    if date is None:
        date = datetime.utcnow().strftime("%Y-%m-%d")
    
    log_file = LOGS_DIR / f"{date}.jsonl"
    
    if not log_file.exists():
        return {"error": "No logs for this date"}
    
    stats = {
        "total_requests": 0,
        "blocked": 0,
        "allowed": 0,
        "attack_types": {},
        "tools_accessed": {},
        "ai_judge_invocations": 0,
    }
    
    try:
        with open(log_file, "r", encoding="utf-8") as f:
            for line in f:
                entry = json.loads(line)
                stats["total_requests"] += 1
                
                if entry["decision"] == "BLOCK":
                    stats["blocked"] += 1
                else:
                    stats["allowed"] += 1
                
                if entry.get("ai_judge"):
                    stats["ai_judge_invocations"] += 1
                    attack_type = entry["ai_judge"].get("attack_type", "unknown")
                    stats["attack_types"][attack_type] = stats["attack_types"].get(attack_type, 0) + 1
                
                tool = entry.get("tool", "unknown")
                stats["tools_accessed"][tool] = stats["tools_accessed"].get(tool, 0) + 1
        
        return stats
    
    except Exception as e:
        return {"error": str(e)}


# ===========================
# CLEANUP
# ===========================

def cleanup_old_logs(days_to_keep: int = 30) -> None:
    """
    Clean up logs older than specified days.
    
    Args:
        days_to_keep: Number of days to retain logs
    """
    try:
        cutoff_date = datetime.utcnow().timestamp() - (days_to_keep * 86400)
        
        for log_file in LOGS_DIR.glob("*.jsonl"):
            if log_file.stat().st_mtime < cutoff_date:
                log_file.unlink()
                logging.info(f"Deleted old log: {log_file}")
    
    except Exception as e:
        logging.exception(f"Failed to cleanup logs: {e}")
