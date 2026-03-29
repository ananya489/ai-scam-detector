import re

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
    r"\bshorten\b", r"\btrack.*link\b"
]

PRIZE_PATTERNS = [
    r"\byou('ve)? won\b", r"\bcongratulations\b", r"\bprize\b",
    r"\blottery\b", r"\bfree gift\b", r"\breward\b", r"\blucky winner\b",
    r"\bclaim.*reward\b", r"\bselected\b"
]

THREAT_PATTERNS = [
    r"\baccount.*blocked\b", r"\baccount.*suspend\b", r"\bsuspend.*account\b",
    r"\blegal action\b", r"\bpolice\b", r"\barrest\b", r"\bpenalty\b",
    r"\bfine\b", r"\bwill be charged\b", r"\bwarning\b"
]

MONEY_PATTERNS = [
    r"\bsend money\b", r"\bwire transfer\b", r"\bgift card\b",
    r"\bpay.*fee\b", r"\badvance.*fee\b", r"\binvestment\b",
    r"\bdouble.*money\b", r"\b\$\d+\b", r"\blakh\b", r"\bcrore\b"
]

PERSONAL_INFO_PATTERNS = [
    r"\bbank.*detail\b", r"\baccount.*number\b", r"\bpassword\b",
    r"\bpin\b", r"\baadhar\b", r"\bpan card\b", r"\bkyc\b",
    r"\bsocial security\b", r"\bdate of birth\b", r"\bmother.*maiden\b"
]

# --- Signal Registry ---

SIGNAL_REGISTRY = [
    {
        "id":       "urgency",
        "label":    "Urgency / Pressure",
        "patterns": URGENCY_PATTERNS,
        "weight":   1,
    },
    {
        "id":       "otp_request",
        "label":    "OTP / Code Request",
        "patterns": OTP_PATTERNS,
        "weight":   3,            # high weight — almost always scam
    },
    {
        "id":       "suspicious_link",
        "label":    "Suspicious Link",
        "patterns": SUSPICIOUS_LINK_PATTERNS,
        "weight":   2,
    },
    {
        "id":       "prize_claim",
        "label":    "Prize / Lottery Claim",
        "patterns": PRIZE_PATTERNS,
        "weight":   2,
    },
    {
        "id":       "threat",
        "label":    "Threat / Fear Tactic",
        "patterns": THREAT_PATTERNS,
        "weight":   2,
    },
    {
        "id":       "money_request",
        "label":    "Money / Transfer Request",
        "patterns": MONEY_PATTERNS,
        "weight":   2,
    },
    {
        "id":       "personal_info",
        "label":    "Personal Info Request",
        "patterns": PERSONAL_INFO_PATTERNS,
        "weight":   3,            # high weight — major red flag
    },
]

MAX_POSSIBLE_SCORE = sum(s["weight"] for s in SIGNAL_REGISTRY)


# --- Core Detection ---

def detect_signals(text: str) -> list[dict]:
    """
    Scan text against every signal category.
    Returns a list of matched signals with matched keywords.
    """
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
                "matches": list(set(hits)),   # deduplicate
                "weight":  signal["weight"],
            })

    return matched


def calculate_risk(signals: list[dict]) -> dict:
    """
    Score the signals and return risk level + confidence.
    """
    if not signals:
        return {"level": "safe", "confidence": 0.0, "is_scam": False}

    score = sum(s["weight"] for s in signals)
    confidence = round(min(score / MAX_POSSIBLE_SCORE, 1.0), 2)

    if confidence >= 0.5:
        level = "high"
    elif confidence >= 0.25:
        level = "medium"
    else:
        level = "low"

    return {
        "level":      level,
        "confidence": confidence,
        "is_scam":    confidence >= 0.25,
    }


def analyze_message(text: str) -> dict:
    """
    Main entry point. Returns full analysis result.
    """
    signals = detect_signals(text)
    risk    = calculate_risk(signals)

    return {
        "is_scam":    risk["is_scam"],
        "risk_level": risk["level"],
        "confidence": risk["confidence"],
        "signals":    signals,
        "total_signals_found": len(signals),
    }