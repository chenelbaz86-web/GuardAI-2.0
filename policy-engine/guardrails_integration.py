"""
GuardAI 2.0 - Guardrails AI Integration (Tier 2)
Simplified - works with any Guardrails version.
"""

import logging

logging.basicConfig(level=logging.INFO)

# Try to import Guardrails
try:
    from guardrails import Guard
    GUARDRAILS_AVAILABLE = True
    logging.info("✅ Guardrails AI is available (Tier 2 active)")
except ImportError:
    GUARDRAILS_AVAILABLE = False
    Guard = None
    logging.warning("⚠️ Guardrails AI not available (Tier 2 disabled)")


def validate_with_guardrails(text: str, validation_type: str = "input") -> dict:
    """
    Validate text using Guardrails AI.
    
    For now, this is a placeholder that returns valid.
    You can add specific validators later.
    
    Args:
        text: Input text to validate
        validation_type: "input" or "output"
    
    Returns:
        {
            "valid": bool,
            "errors": list,
            "validated_output": str
        }
    """
    if not GUARDRAILS_AVAILABLE:
        # Tier 2 disabled - pass through
        return {
            "valid": True,
            "errors": [],
            "validated_output": text
        }
    
    try:
        # Simple validation using Guardrails
        # You can add validators here later:
        # guard = Guard().use(ToxicLanguage(), PII(), etc...)
        
        guard = Guard()
        
        # For now, just validate that it's not empty
        if not text or len(text.strip()) == 0:
            return {
                "valid": False,
                "errors": ["Empty input"],
                "validated_output": text
            }
        
        # All good
        return {
            "valid": True,
            "errors": [],
            "validated_output": text
        }
    
    except Exception as e:
        logging.error(f"Guardrails validation error: {e}")
        # Fail-open on error
        return {
            "valid": True,
            "errors": [f"Validation error: {str(e)}"],
            "validated_output": text
        }
