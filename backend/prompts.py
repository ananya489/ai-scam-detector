def build_analysis_prompt(message: str, signals: list, scam_type: dict | None, tactics: list, risk_score: int) -> str:

    signals_text = "\n".join(
        f"  - {s['label']} (matched: {', '.join(s['matches'])})"
        for s in signals
    ) or "  None detected"

    scam_text = (
        f"{scam_type['name']} — {scam_type['description']}"
        if scam_type else "Unknown / No match"
    )

    tactics_text = ", ".join(t["label"] for t in tactics) or "None detected"

    return f"""You are a scam detection assistant helping everyday people stay safe.

A message has been analyzed by our rule-based system. Here is the structured report:

MESSAGE:
\"\"\"{message}\"\"\"

RULE-BASED FINDINGS:
- Risk Score     : {risk_score} / 100
- Scam Type      : {scam_text}
- Signals Found  : 
{signals_text}
- Psych Tactics  : {tactics_text}

YOUR TASK — respond in this exact JSON format, no extra text:
{{
  "summary":      "2-3 sentence plain-English explanation of why this is or isn't a scam",
  "advice":       ["actionable tip 1", "actionable tip 2", "actionable tip 3"],
  "safe_to_ignore": true or false,
  "report_to":    "who the victim should report this to (or empty string if safe)"
}}

Rules:
- Write for a non-technical person, no jargon
- Be direct and empathetic, not alarming
- advice must be specific to THIS message, not generic
- safe_to_ignore is true only if risk_score < 20
"""