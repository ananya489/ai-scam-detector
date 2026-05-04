import re

# ✅ FIXED IMPORTS (IMPORTANT)
from backend.matcher import match_scam_type, detect_tactics
from backend.ai_analyzer import get_ai_analysis


# --- Signal Definitions ---

URGENCY_PATTERNS = [
    r"\burgent\b", r"\bimmediately\b", r"\bact now\b", r"\blimited time\b",
    r"\bexpires?\b", r"\bdeadline\b", r"\blast chance\b", r"\bdon't delay\b",
    r"\bhurry\b", r"\btoday only\b"
]

OTP_PATTERNS = [
    r"\botp\b", r"\bone.?time.?password\b", r"\bverification code\b",
    r"\bsecurity code\b", r"\benter.*code\b", r"\bshare.*code\b",
    r"\bconfirm.*code\b", r"\bsms code\b"
]

SUSPICIOUS_LINK_PATTERNS = [
    r"http[s]?://(?!(?:www\.)?(google|amazon|apple|microsoft|gov)\.\w+)\S+",
    r"\bclick here\b", r"\bbit\.ly\b", r"\btinyurl\b", r"\bgoo\.gl\b",
]

PRIZE_PATTERNS = [
    r"\byou('ve)? won\b", r"\bcongratulations\b", r"\bprize\b",
    r"\blottery\b", r"\bfree gift\b", r"\breward\b", r"\blucky winner\b",
    r"\bclaim.*reward\b", r"\bselected\b"
]

THREAT_PATTERNS = [
    r"\baccount.*blocked\b", r"\baccount.*suspend\b", r"\bsuspend.*account\b",
    r"\blegal action\b", r"\bpolice\b", r"\barrest\b", r"\bpenalty\b",
    r"\bwill be charged\b", r"\bwarning\b"
]

MONEY_PATTERNS = [
    r"\bsend money\b", r"\bwire transfer\b", r"\bgift card\b",
    r"\bpay.*fee\b", r"\badvance.*fee\b", r"\bdouble.*money\b",
    r"\b\$\d+\b", r"\blakh\b", r"\bcrore\b"
]

PERSONAL_INFO_PATTERNS = [
    r"\bbank.*detail\b", r"\baccount.*number\b", r"\bpassword\b",
    r"\bpin\b", r"\baadhar\b", r"\bpan card\b", r"\bkyc\b",
    r"\bsocial security\b", r"\bdate of birth\b", r"\bmother.*maiden\b"
]


# --- Signal Registry ---

SIGNAL_REGISTRY = [
    {"id": "urgency",         "label": "Urgency / Pressure",       "patterns": URGENCY_PATTERNS,         "weight": 10},
    {"id": "suspicious_link", "label": "Suspicious Link",          "patterns": SUSPICIOUS_LINK_PATTERNS, "weight": 15},
    {"id": "prize_claim",     "label": "Prize / Lottery Claim",    "patterns": PRIZE_PATTERNS,           "weight": 15},
    {"id": "threat",          "label": "Threat / Fear Tactic",     "patterns": THREAT_PATTERNS,          "weight": 20},
    {"id": "money_request",   "label": "Money / Transfer Request", "patterns": MONEY_PATTERNS,           "weight": 20},
    {"id": "otp_request",     "label": "OTP / Code Request",       "patterns": OTP_PATTERNS,             "weight": 25},
    {"id": "personal_info",   "label": "Personal Info Request",    "patterns": PERSONAL_INFO_PATTERNS,   "weight": 25},
]

MAX_SCORE = sum(s["weight"] for s in SIGNAL_REGISTRY)


# --- Thresholds ---

def _get_risk_level(score: int) -> str:
    if score == 0:
        return "safe"
    elif score <= 20:
        return "low"
    elif score <= 50:
        return "medium"
    else:
        return "high"


# --- Core Detection ---

def detect_signals(text: str) -> list[dict]:
    text_lower = text.lower()
    matched = []

    for signal in SIGNAL_REGISTRY:
        hits = []
        for pattern in signal["patterns"]:
            match = re.search(pattern, text_lower)
            if match:
                hits.append(match.group())

        if hits:
            matched.append({
                "id":      signal["id"],
                "label":   signal["label"],
                "matches": list(set(hits)),
                "weight":  signal["weight"],
            })

    return matched


def calculate_score(signals: list[dict]) -> int:
    raw = sum(s["weight"] for s in signals)
    return round(min(raw / MAX_SCORE, 1.0) * 100)


# ✅ FINAL ANALYZE FUNCTION (clean + working)

def analyze_message(text: str) -> dict:
    signals    = detect_signals(text)
    score      = calculate_score(signals)
    risk_level = _get_risk_level(score)

    signal_ids = [s["id"] for s in signals]

    scam_type  = match_scam_type(text, signal_ids)
    tactics    = detect_tactics(text)

    ai         = get_ai_analysis(text, signals, scam_type, tactics, score)

    return {
        "is_scam":             score > 20,
        "risk_level":          risk_level,
        "risk_score":          score,
        "score_breakdown": {
            "raw_score":    sum(s["weight"] for s in signals),
            "max_possible": MAX_SCORE,
            "normalized":   score,
        },
        "scam_type":           scam_type,
        "tactics":             tactics,
        "signals":             signals,
        "total_signals_found": len(signals),
        "ai_analysis":         ai,
    }