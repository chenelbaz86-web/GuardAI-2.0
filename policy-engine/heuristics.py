"""
GuardAI 2.0 - Heuristics Engine (v3.0 - Context-Aware Scoring)
Reduces false positives with intelligent pattern weighting.

Author: Chen Shaked
Date: 2026-01-20 (v3.0 - False Positive Reduction)
"""
import re
import base64
import logging
from typing import Dict, List, Tuple

logging.basicConfig(level=logging.INFO)

# ===========================
# PATTERN WEIGHTS (v3.0)
# ===========================

PATTERN_WEIGHTS = {

    "prompt_injection": 50,
    "jailbreak": 50,
    "social_engineering": 45,
    "data_exfiltration": 40,
    "secret_hunting": 35,
    "role_manipulation": 40,
    "context_manipulation": 45,
    "indirect_command": 35,
    "homoglyph_detection": 30,
    "ssti": 40,
    "system_prompt_leakage": 50,
    "false_legitimacy": 35,
    "sql_injection": 60,  
    "file_attacks": 40,
    "encoding_attacks": 35,
    "injection_patterns": 35,
    "advanced_jailbreak": 30,
    }
# ===========================
# EDUCATIONAL SIGNALS
# ===========================
EDUCATIONAL_SIGNALS = [
    r"\bhow\s+(do\s+i|to|can\s+i|should\s+i)\b",
    r"\bwhat\s+(is|are|does|would|should)\b",
    r"\b(explain|tutorial|learn|example|guide|documentation)\b",
    r"\bbest\s+practices?\b",
    r"\b(blog|article|post|writing)\b",
    r"\b(security\s+)?(course|training|lesson)\b",
    r"\bfor\s+(my|our)\s+(project|work|thesis|research)\b",
    r"\bמה\s+(ה|זה|את)\b",  # שאלות בעברית
    r"\b(איך|כיצד)\b",
]

ATTACK_KEYWORDS = [
    "dump", "show", "reveal", "extract", "export", 
    "bypass", "disable", "override", "ignore"
]

SENSITIVE_DATA_KEYWORDS = [
    "password", "secret", "api_key", "token", "credential",
    "private_key", "database", "admin", "root"
]

# ===========================
# SUSPICION PATTERNS (Original)
# ===========================

SUSPICION_PATTERNS = {
    "prompt_injection": [
        r"ignore\s+(previous|above|prior|all|any)\s+(instructions?|prompts?|directions?|rules?)",
        r"disregard\s+(all|any|previous|above|prior|the)\s+(instructions?|prompts?|rules?|safety)",
        r"forget\s+(everything|all|previous|prior|that|the)\s+(you|instructions?|rules?)",
        r"you\s+are\s+now\s+(a|the|in)\s+",
        r"system\s*:\s*(new|updated|override|admin)\s+instructions?",
        r"new\s+instructions?\s*:\s*",
        r"act\s+as\s+(if|though|a)\s+",
        r"pretend\s+(you|to|that)\s+",
        r"override\s+(previous|all|prior|the)\s+",
        r"reset\s+(your|the)\s+(instructions?|directives?|settings?)",
        r"(?:ignore|disregard|bypass|skip).*(?:previous|all|above).*(?:instructions?|prompts?|rules?)",
        r"dump\s+(?:all|the|your)\s+(?:instructions?|prompts?|system|secrets?)",
        r"show\s+(?:me\s+)?(?:your|the)\s+(?:system\s+)?(?:prompt|instructions?|rules?)",
    ],
    
    "jailbreak": [
        r"\bDAN\b\s+mode",
        r"developer\s+mode",
        r"[Dd]o\s+[Aa]nything\s+[Nn]ow",
        r"evil\s+mode",
        r"unrestricted\s+mode",
        r"bypass\s+(restrictions?|filters?|safety|guidelines?|rules?)",
        r"disable\s+(safety|moderation|filters?|restrictions?)",
        r"disregard.*safety.*restrictions?",
        r"ignore.*safety.*guidelines?",
        r"without.*restrictions?",
        r"you\s+have\s+no\s+restrictions?",
        r"act\s+without\s+(?:any\s+)?(?:restrictions?|limits?|rules?)",
        r"unrestricted\s+(?:access|capabilities|powers?)",
    ],
    
    "social_engineering": [
        r"urgent.*(?:ceo|admin|management|authorized|director)",
        r"(?:ceo|admin|manager|director).*(?:needs|requires|requests|demands).*(?:immediately|urgent|asap)",
        r"authorized\s+by\s+(?:management|admin|ceo|director)",
        r"emergency.*(?:access|override|bypass)",
        r"this\s+is\s+(?:an\s+)?(?:urgent|emergency|critical)",
        r"(?:ceo|admin|director|manager).*(?:needs|requires).*(?:api|secret|password|token|credential)s?\s*(?:keys?|codes?)",
        r"(?:urgent|immediately|asap).*(?:api|secret|password|token)\s*(?:keys?|codes?)",
        r"(?:api|secret|password|token)\s*(?:keys?|codes?).*(?:urgent|immediately|asap|audit|emergency)",
        r"authorized.*(?:audit|review|inspection).*(?:api|secrets?|keys?|credentials?)",
    ],
    
    "data_exfiltration": [
        r"dump\s+(all|entire|full|complete)\s+",
        r"export\s+(all|data|everything)\s+to\s+(csv|json|xml)",
        r"show\s+(?:me\s+)?(?:all|entire|complete|the)?\s*(?:sensitive|secret|confidential|admin|private)\s+(?:data|info|information|files?)",
        r"list\s+(all|every)\s+(users?|passwords?|keys?|tokens?|secrets?)",
        r"select\s+\*\s+from",
        r"print\s+(all|entire|system)\s+",
        r"reveal\s+(all|the)?\s*(?:sensitive|secret|admin)?\s*(secrets?|keys?|passwords?|data)",
    ],

    
    "secret_hunting": [
        r"(password|secret|api[_-]?key|token|credential)s?\s*[:=]",
        r"-----BEGIN\s+.*PRIVATE\s+KEY-----",
        r"authorization\s*:\s*bearer",
        r"aws[_-]?(access|secret)[_-]?key",
        r"sk-[A-Za-z0-9]{20,}",
    ],
    
    "role_manipulation": [
        r"you\s+are\s+(not\s+)?(a\s+)?assistant",
        r"your\s+role\s+is\s+(now\s+)?to",
        r"from\s+now\s+on",
        r"starting\s+now",
        r"pretend.*you.*are",
        r"roleplay.*as",
        r"simulate.*being",
    ],
    
    "context_manipulation": [
        r"according\s+to\s+(?:the\s+)?(?:system|documentation|manual|docs)",
        r"(?:system|documentation)\s+(?:says|states|indicates|allows)",
        r"(?:the\s+)?(?:manual|docs|documentation)\s+(?:says|allows|permits)",
        r"as\s+(?:per|stated|mentioned)\s+(?:in\s+)?(?:the\s+)?(?:documentation|system)",
        r"(?:according\s+to|as\s+per|the).*(?:documentation|system|manual).*(?:users?\s+can|you\s+can|allows?|permits?)",
        r"(?:documentation|system|manual).*(?:access|reveal|show|dump).*(?:admin|sensitive|secret)",
    ],
    
    # ===== SYSTEM PROMPT LEAKAGE ===== ✨ Enhanced for Test 39
    "system_prompt_leakage": [
        r"show\s+(?:me\s+)?(?:your|the)\s+(?:system\s+)?(?:prompt|instructions?)",
        r"what\s+(?:is|are|were)\s+your\s+(?:system\s+)?(?:prompt|instructions?|initial\s+instructions?)",
        r"display\s+(?:your|the)\s+(?:system\s+)?(?:prompt|configuration)",
        r"print\s+(?:your|the)\s+(?:system\s+)?(?:prompt|rules?)",
        r"reveal\s+(?:your|the)\s+(?:initial|system)\s+(?:prompt|instructions?)",
        r"repeat\s+(?:everything|all|what).*(?:system\s+prompt|initial\s+instructions?|you\s+were\s+told)",
        r"(?:word\s+for\s+word|verbatim|exactly).*(?:prompt|instructions?|told)",
    ],

        # ===== SQL INJECTION ===== ✨ NEW for Test 33
    "sql_injection": [
        r"(?:;|\s)DROP\s+TABLE",
        r"(?:;|\s)DELETE\s+FROM",
        r"(?:;|\s)UPDATE\s+.*\s+SET",
        r"(?:;|\s)INSERT\s+INTO",
        r"'\s*;\s*\w+",  # '; command
        r"--\s*$",  # SQL comment at end
        r"UNION\s+SELECT",
        r"OR\s+1\s*=\s*1",
        r"'\s*OR\s*'",
    ],


    
    # ===== FALSE LEGITIMACY ===== ✨ NEW for Test 42
    "false_legitimacy": [
        r"(?:for\s+)?(?:research|academic|educational)\s+purposes?",
        r"(?:security|penetration)\s+(?:research|testing)",
        r"(?:authorized|approved)\s+(?:security\s+)?(?:test|audit)",
        r"(?:legitimate|authorized)\s+(?:research|study|analysis)",
    ],

    "indirect_command": [
        r"follow\s+(?:any|the|all)\s+instructions?\s+(?:you\s+find|in|from)",
        r"execute\s+(?:commands?|instructions?)\s+(?:from|in|found)",
        r"read\s+and\s+(?:execute|follow|obey)",
        r"(?:search|find).*readme.*(?:follow|execute|obey)",
        r"find.*and.*(?:follow|execute)\s+(?:any|the|those|them)",
        r"(?:readme|document).*(?:follow|execute)\s+(?:instructions?|commands?)",
    ],


    "file_attacks": [
        r"\.\./",  # Path traversal
        r"\.\.\\",
        r"/etc/passwd",
        r"/etc/shadow",
        r"\.php\.",  # Double extension
        r"\.jsp\.",
        r"%00",  # Null byte
        r"bomb",  # ZIP bomb
        r"petabytes?",
    ],

    # ===== ENCODING ATTACKS =====
    "encoding_attacks": [
        r"rot13|rot-13",
        r"0x[0-9a-f]{20,}",  # Long hex strings
        r"\\x[0-9a-f]{2}",  # Hex encoding
        r"%0d%0a",  # CRLF injection
        r"\r\n",
    ],

    # ===== INJECTION PATTERNS =====
    "injection_patterns": [
        r"\{\{.*\}\}",  # SSTI (Jinja2, etc)
        r"\$\{.*\}",    # SSTI (Freemarker)
        r"<%.*%>",      # SSTI (JSP)
        r"SELECT.*FROM",  # SQL (case-insensitive already caught)
        r"'.*\|\|.*'",   # SQL concatenation
    ],

    # ===== ADVANCED JAILBREAKS =====
    "advanced_jailbreak": [
        r"grandma.*bedtime.*story",
        r"deceased.*grandmother",
        r"research.*purposes?.*phd|thesis|university",
        r"grant.*(?:me|access|permission)",
    ],


        
        "homoglyph_detection": [
            r"[\u0400-\u04FF]",
            r"[\u0370-\u03FF]",
            r"[\uFF21-\uFF3A\uFF41-\uFF5A]",
        ],
}

# ===========================
# TOOL RISK LEVELS
# ===========================

TOOL_RISK_LEVELS = {
    "github_search": "high",
    "github.search_code": "high",
    "github.read_file": "high",
    "github.create_issue": "medium",
    "database.query": "high",
    "database.execute": "critical",
    "filesystem.read": "high",
    "filesystem.write": "critical",
    "slack.send_message": "medium",
    "email.send": "medium",
    "chat": "low",
    "chat.completion": "low",
    "web.search": "low",
    "calculator.compute": "low",
}

# ===========================
# BASE64 DETECTION
# ===========================

def looks_like_base64(text: str) -> bool:
    """Detect base64-encoded malicious content."""
    if not text or len(text) < 30:
        return False
    
    base64_pattern = r'[A-Za-z0-9+/]{30,}={0,2}'
    matches = re.findall(base64_pattern, text)
    
    if not matches:
        return False
    
    for match in matches:
        try:
            decoded = base64.b64decode(match, validate=True)
            decoded_str = decoded.decode('utf-8', errors='ignore').lower()
            
            attack_keywords = [
                'ignore', 'disregard', 'secret', 'password', 'dump',
                'dan', 'mode', 'instruction', 'previous', 'bypass',
                'jailbreak', 'admin', 'token', 'api_key', 'reveal'
            ]
            
            if any(keyword in decoded_str for keyword in attack_keywords):
                logging.warning(
                    f"⚠️ Base64 obfuscation detected! "
                    f"Encoded: {match[:30]}... → Decoded: {decoded_str[:50]}..."
                )
                return True
        except:
            continue
    
    if matches and len(max(matches, key=len)) > 60:
        logging.info(f"⚠️ Long base64 string detected: {len(max(matches, key=len))} chars")
        return True
    
    return False



def looks_like_rot13(text: str) -> bool:
    """Detect ROT13-encoded malicious content."""
    if not text or len(text) < 20:
        return False
    
    # Try ROT13 decode
    try:
        decoded = text.translate(str.maketrans(
            'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
            'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm'
        )).lower()
        
        attack_keywords = [
            'select', 'insert', 'update', 'delete', 'drop', 'union',
            'script', 'alert', 'eval', 'exec', 'system', 'shell',
            'ignore', 'disregard', 'bypass', 'jailbreak', 'dan'
        ]
        
        if any(keyword in decoded for keyword in attack_keywords):
            logging.warning(f"⚠️ ROT13 obfuscation detected! Decoded: {decoded[:80]}...")
            return True
    except:
        pass
    
    return False


# ===========================
# CONTEXT ANALYSIS (v3.0)
# ===========================

def check_context_signals(query: str, matched_categories: List[str]) -> int:
    """
    Analyze query context to adjust suspicion score intelligently.
    Returns boost (positive = more suspicious, negative = less suspicious)
    """
    boost = 0
    query_lower = query.lower()
    
    # NEGATIVE SIGNALS - Educational/Legitimate
    educational_match = False
    for pattern in EDUCATIONAL_SIGNALS:
        if re.search(pattern, query, re.IGNORECASE):
            educational_match = True
            boost -= 20
            logging.debug(f"📚 Educational signal detected")
            break
    
    # Technical/Programming context
    tech_keywords = [
        r"\b(python|javascript|regex|sql|code|function|variable)\b",
        r"\b(syntax|error|bug|debug|compile)\b",
        r"\b(stackoverflow|github|documentation)\b",
    ]
    
    tech_count = sum(1 for kw in tech_keywords if re.search(kw, query, re.IGNORECASE))
    if tech_count >= 1 and educational_match:
        boost -= 10
        logging.debug(f"💻 Technical educational content: {tech_count} keywords")
    
    # Casual/conversational tone
    casual_indicators = [
        r"\b(thanks|please|sorry|hello|hi)\b",
        r"\b(i'm|i am|i've|i have)\b",
        r"\?$",
    ]
    
    if any(re.search(ind, query, re.IGNORECASE) for ind in casual_indicators):
        boost -= 5
        logging.debug("😊 Casual/polite tone detected")
    
    # POSITIVE SIGNALS - Attack Indicators
    attack_count = sum(1 for kw in ATTACK_KEYWORDS if kw in query_lower)
    sensitive_count = sum(1 for kw in SENSITIVE_DATA_KEYWORDS if kw in query_lower)
    
    if attack_count >= 2:
        boost += 15
        logging.debug(f"⚠️ Multiple attack keywords: {attack_count}")
    
    if sensitive_count >= 2:
        boost += 20
        logging.debug(f"🔐 Multiple sensitive data keywords: {sensitive_count}")
    
    # Combined attack + sensitive
    if attack_count >= 1 and sensitive_count >= 1:
        boost += 25
        logging.debug("🚨 Attack + Sensitive data combination!")
    
    # Imperative commands
    imperative_patterns = [
        r"^(show|dump|reveal|extract|list|print)\s+",
        r"\b(now|immediately|asap)\b.*\b(show|dump|reveal)\b",
    ]
    
    if any(re.search(pat, query, re.IGNORECASE) for pat in imperative_patterns):
        if not educational_match:
            boost += 15
            logging.debug("📢 Imperative command detected")
    
    # Social engineering + sensitive
    if ("social_engineering" in matched_categories or 
        any(word in query_lower for word in ["urgent", "ceo", "admin", "authorized"])):
        if any(word in query_lower for word in ["password", "key", "secret", "credential"]):
            boost += 20
            logging.debug("🎭 Social engineering + sensitive data!")
    
    # Obfuscation attempts
    obfuscation_indicators = [
        len([c for c in query if ord(c) > 127]) > 5,
        query.count("%") > 3,
        "\\x" in query or "\\u" in query,
    ]
    
    if any(obfuscation_indicators):
        boost += 15
        logging.debug("🎭 Obfuscation detected")
    
    if boost != 0:
        direction = "↑ INCREASED" if boost > 0 else "↓ DECREASED"
        logging.info(f"Context boost: {direction} suspicion by {abs(boost)} points")
    
    return boost


def is_legitimate_tech_question(query: str) -> bool:
    """Quick check if this is a legitimate technical question."""
    has_question = any(word in query.lower() for word in ["how", "what", "why", "when", "where"])
    
    tech_patterns = [
        r"\b(code|coding|program|script|function|syntax)\b",
        r"\b(python|java|javascript|sql|regex|api)\b",
        r"\b(error|exception|bug|issue|problem)\b",
    ]
    has_tech_context = any(re.search(pat, query, re.IGNORECASE) for pat in tech_patterns)
    
    return has_question and has_tech_context


# ===========================
# CALCULATE SUSPICION SCORE (v3.0)
# ===========================

def calculate_suspicion_score(query: str, tool: str) -> Tuple[int, str, Dict]:
    """
    Calculate suspicion score (0-100) with context-aware intelligence.
    """
    score = 0
    matched_patterns = []
    matched_categories = []
    details = {}
    
    query_lower = query.lower() if query else ""
    
    # STEP 1: Pattern Matching (Weighted)
    for category, patterns in SUSPICION_PATTERNS.items():
        category_matched = False
        
        for pattern in patterns:
            if re.search(pattern, query, re.IGNORECASE):
                category_weight = PATTERN_WEIGHTS.get(category, 20)
                score += category_weight
                
                matched_patterns.append({
                    "category": category,
                    "pattern": pattern[:50],
                    "weight": category_weight,
                })
                matched_categories.append(category)
                category_matched = True
                
                logging.debug(f"Pattern matched: {category} (+{category_weight})")
                break
        
        if category_matched:
            details[f"{category}_detected"] = True
    
    # STEP 2: Base64 Detection
    if looks_like_base64(query):
        base64_score = 60
        score += base64_score
        details["base64_obfuscation"] = True
        matched_patterns.append({
            "category": "obfuscation",
            "pattern": "base64_encoding",
            "weight": base64_score,
        })
        matched_categories.append("obfuscation")
        
    # ROT13 obfuscation ✨ NEW
    if looks_like_rot13(query):
        rot13_score = 60
        score += rot13_score
        details["rot13_obfuscation"] = True
        matched_patterns.append({
            "category": "obfuscation",
            "pattern": "rot13_encoding",
            "weight": rot13_score,
        })
        matched_categories.append("obfuscation")
    
    # STEP 3: Context Analysis
    context_boost = check_context_signals(query, matched_categories)
    score += context_boost
    details["context_boost"] = context_boost
    
    # STEP 4: Tool Risk
    risk_level = get_tool_risk_level(tool)
    risk_points = {"critical": 30, "high": 20, "medium": 10, "low": 0}
    tool_score = risk_points.get(risk_level, 0)
    score += tool_score
    details["tool_risk"] = risk_level
    details["tool_risk_points"] = tool_score
    
    # STEP 5: Additional Heuristics
    if len(query) > 1000:
        score += 10
        details["long_prompt"] = True
    
    multi_step_keywords = ['first', 'then', 'finally', 'next', 'after that', 'step']
    multi_step_count = sum(1 for kw in multi_step_keywords if kw in query_lower)
    if multi_step_count >= 3:
        score += 20
        details["multi_step_pattern"] = True
    
    # STEP 6: Anomaly detection - sudden malicious shift ✨ NEW for Test 33
    benign_words = ['weather', 'recipe', 'help', 'please', 'thank', 'how']
    malicious_words = ['ignore', 'disregard', 'bypass', 'dump', 'reveal', 'hack']
    
    has_benign = any(word in query_lower for word in benign_words)
    has_malicious = any(word in query_lower for word in malicious_words)
    
    if has_benign and has_malicious and len(matched_patterns) > 0:
        score += 25
        details["anomaly_detected"] = True
        logging.warning("⚠️ Anomaly detected: Benign-to-malicious shift")
    
    # STEP 7: Normalize
    score = max(0, min(score, 100))
    
    # STEP 8: Build Explanation
    if not matched_patterns:
        reason = "No suspicious patterns detected"
    else:
        unique_categories = list(set(matched_categories))
        reason = f"Detected: {', '.join(unique_categories[:3])}"
        
        if len(unique_categories) > 3:
            reason += f" (+{len(unique_categories) - 3} more)"
        
        if context_boost < -10:
            reason += " [Educational context]"
        elif context_boost > 20:
            reason += " [High-risk combination]"
    
    details["matched_patterns"] = matched_patterns
    details["total_patterns"] = len(matched_patterns)
    details["final_score"] = score
    
    logging.info(
        f"📊 Suspicion: {score}/100 | Tool: {tool} ({risk_level}) | "
        f"Patterns: {len(matched_patterns)} | Context: {context_boost:+d}"
    )
    
    return score, reason, details



def get_matched_patterns(query: str) -> List[Dict]:
    """Get list of matched suspicion patterns for logging."""
    matched = []
    for category, patterns in SUSPICION_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, query, re.IGNORECASE):
                matched.append({"category": category, "pattern": pattern})
    return matched


# ===========================
# AI JUDGE INVOCATION
# ===========================

def should_invoke_ai_judge(suspicion_score: int, tool_type: str) -> bool:
    """Decide whether to invoke AI Judge."""
    thresholds = {"critical": 20, "high": 35, "medium": 50, "low": 60}
    threshold = thresholds.get(tool_type, 40)
    should_invoke = suspicion_score >= threshold
    
    if should_invoke:
        logging.info(f"🤖 AI Judge invoked: score={suspicion_score}, threshold={threshold}")
    
    return should_invoke


def get_tool_risk_level(tool: str) -> str:
    """Get risk level of a tool."""
    return TOOL_RISK_LEVELS.get(tool, "low")


# ===========================
# CONTEXT EXTRACTION
# ===========================

def extract_query_from_action_plan(action_plan: dict) -> str:
    """Extract user query from action plan."""
    params = action_plan.get("parameters", {})
    
    if "query" in params:
        return params["query"]
    
    if "messages" in params:
        for msg in reversed(params["messages"]):
            if msg.get("role") == "user":
                return msg.get("content", "")
    
    if "content" in params:
        return params["content"]
    
    return str(params)


def get_context_summary(action_plan: dict) -> Dict:
    """Extract context summary for AI Judge."""
    return {
        "tool": action_plan.get("tool", "unknown"),
        "tool_risk": get_tool_risk_level(action_plan.get("tool", "")),
        "tenant_id": action_plan.get("meta", {}).get("tenant_id"),
        "actor": action_plan.get("meta", {}).get("actor"),
        "timestamp": action_plan.get("meta", {}).get("timestamp"),
    }
