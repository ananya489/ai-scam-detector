# ---------------------------------------------------------------------------
# SCAM PLAYBOOK
# Each scam type defines:
#   - keywords  : simple word/phrase matches
#   - signals   : which detector signal IDs strengthen the match
#   - tactics   : psychological manipulation methods used in this scam
# ---------------------------------------------------------------------------

SCAM_PLAYBOOK = [
    {
        "id":          "bank_scam",
        "name":        "Bank / Financial Fraud",
        "description": "Impersonates a bank or payment provider to steal credentials or transfer money.",
        "keywords": [
            "bank", "account", "transaction", "netbanking", "upi", "ifsc",
            "credit card", "debit card", "kyc", "blocked", "suspended",
            "verify your account", "payment failed", "refund"
        ],
        "signals":  ["otp_request", "personal_info", "threat"],
        "tactics":  ["fear", "authority", "urgency"],
    },
    {
        "id":          "lottery_scam",
        "name":        "Lottery / Prize Scam",
        "description": "Claims the victim has won a prize to extract a fee or personal details.",
        "keywords": [
            "won", "winner", "lottery", "prize", "lucky draw", "selected",
            "congratulations", "reward", "claim", "coupon", "jackpot"
        ],
        "signals":  ["prize_claim", "money_request", "suspicious_link"],
        "tactics":  ["excitement", "greed", "urgency"],
    },
    {
        "id":          "job_scam",
        "name":        "Fake Job Offer",
        "description": "Offers fake employment to collect a registration fee or personal data.",
        "keywords": [
            "job", "hiring", "vacancy", "work from home", "part time",
            "salary", "per day", "weekly pay", "recruitment", "apply now",
            "joining fee", "registration fee", "offer letter"
        ],
        "signals":  ["money_request", "personal_info", "suspicious_link"],
        "tactics":  ["greed", "trust", "urgency"],
    },
    {
        "id":          "tech_support_scam",
        "name":        "Tech Support Scam",
        "description": "Pretends to be tech support to gain remote access or payment.",
        "keywords": [
            "virus", "hacked", "infected", "microsoft", "apple support",
            "call us", "toll free", "remote access", "install", "software",
            "your device", "your computer", "your phone", "helpdesk"
        ],
        "signals":  ["threat", "urgency", "suspicious_link"],
        "tactics":  ["fear", "authority", "urgency"],
    },
    {
        "id":          "romance_scam",
        "name":        "Romance / Relationship Scam",
        "description": "Builds a fake relationship to eventually request money or gifts.",
        "keywords": [
            "love you", "missing you", "soulmate", "destiny", "met online",
            "send me", "gift card", "stuck abroad", "emergency", "military",
            "divorce", "lonely", "trust me", "just this once"
        ],
        "signals":  ["money_request", "urgency"],
        "tactics":  ["trust", "emotional_manipulation", "guilt"],
    },
    {
        "id":          "investment_scam",
        "name":        "Investment / Crypto Scam",
        "description": "Promises high returns to lure victims into fake investment schemes.",
        "keywords": [
            "invest", "returns", "profit", "crypto", "bitcoin", "trading",
            "double your money", "guaranteed", "passive income", "scheme",
            "portfolio", "broker", "roi", "forex", "nft"
        ],
        "signals":  ["money_request", "prize_claim"],
        "tactics":  ["greed", "trust", "fomo"],
    },
    {
        "id":          "government_scam",
        "name":        "Government / Authority Impersonation",
        "description": "Impersonates government agencies to threaten or extract payments.",
        "keywords": [
            "income tax", "it department", "irs", "police", "court",
            "summons", "arrest warrant", "case filed", "legal notice",
            "government", "aadhaar", "pan", "ration card", "customs"
        ],
        "signals":  ["threat", "personal_info", "urgency"],
        "tactics":  ["fear", "authority", "urgency"],
    },
]


# ---------------------------------------------------------------------------
# PSYCHOLOGICAL TACTICS
# ---------------------------------------------------------------------------

TACTIC_DEFINITIONS = {
    "fear": {
        "label":       "Fear",
        "description": "Creates panic about account loss, arrest, or legal trouble.",
        "patterns": [
            r"\barrest\b", r"\blegal action\b", r"\bblocked\b",
            r"\bsuspended\b", r"\bwarrant\b", r"\bpenalty\b",
            r"\bpolice\b", r"\bcase filed\b"
        ],
    },
    "urgency": {
        "label":       "Urgency",
        "description": "Pressures the victim to act immediately without thinking.",
        "patterns": [
            r"\burgent\b", r"\bimmediately\b", r"\btoday only\b",
            r"\bact now\b", r"\blast chance\b", r"\bexpires\b",
            r"\bdeadline\b", r"\bwithin \d+ hours?\b"
        ],
    },
    "authority": {
        "label":       "Authority",
        "description": "Impersonates a trusted institution to appear legitimate.",
        "patterns": [
            r"\bbank\b", r"\bgovernment\b", r"\bpolice\b", r"\birs\b",
            r"\bmicrosoft\b", r"\bapple\b", r"\bofficial\b",
            r"\bheadquarters\b", r"\bdirector\b", r"\bofficer\b"
        ],
    },
    "greed": {
        "label":       "Greed",
        "description": "Tempts with promises of money, prizes, or high returns.",
        "patterns": [
            r"\bdouble\b", r"\bprofit\b", r"\bguaranteed\b",
            r"\bfree\b", r"\bprize\b", r"\bwon\b", r"\breward\b",
            r"\blottery\b", r"\bjackpot\b", r"\bpassive income\b"
        ],
    },
    "trust": {
        "label":       "Trust Building",
        "description": "Uses familiarity or social proof to lower the victim's guard.",
        "patterns": [
            r"\btrust me\b", r"\bi promise\b", r"\bverified\b",
            r"\bcertified\b", r"\blegit\b", r"\bsafe\b",
            r"\bmy friend\b", r"\bas discussed\b"
        ],
    },
    "excitement": {
        "label":       "Excitement",
        "description": "Generates positive emotions to cloud rational judgment.",
        "patterns": [
            r"\bcongratulations\b", r"\bexciting\b", r"\bamazing\b",
            r"\bincredible\b", r"\bspecial offer\b", r"\bexclusive\b",
            r"\bunbelievable\b"
        ],
    },
    "guilt": {
        "label":       "Guilt",
        "description": "Makes the victim feel responsible for someone else's crisis.",
        "patterns": [
            r"\bplease help\b", r"\bonly you\b", r"\bcount on you\b",
            r"\bnobody else\b", r"\bjust this once\b", r"\bdeserve better\b"
        ],
    },
    "fomo": {
        "label":       "FOMO",
        "description": "Fear of missing out — limited slots, expiring opportunities.",
        "patterns": [
            r"\blimited slots?\b", r"\bonly \d+ left\b", r"\bfilling fast\b",
            r"\bdon't miss\b", r"\bexclusive access\b", r"\bclose soon\b"
        ],
    },
    "emotional_manipulation": {
        "label":       "Emotional Manipulation",
        "description": "Exploits loneliness, affection, or sympathy.",
        "patterns": [
            r"\blove you\b", r"\bmissing you\b", r"\blonely\b",
            r"\bstuck\b", r"\bemergency\b", r"\bhospital\b",
            r"\baccident\b", r"\bhelp me\b"
        ],
    },
}