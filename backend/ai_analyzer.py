import os
import json
from anthropic import Anthropic
from prompts import build_analysis_prompt

client = Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

def get_ai_analysis(
    message:    str,
    signals:    list,
    scam_type:  dict | None,
    tactics:    list,
    risk_score: int,
) -> dict:
    """
    Call Claude with the structured findings and get a human-readable analysis.
    Returns a dict with summary, advice, safe_to_ignore, report_to.
    Falls back gracefully if the API call fails.
    """
    prompt = build_analysis_prompt(message, signals, scam_type, tactics, risk_score)

    try:
        response = client.messages.create(
            model="claude-opus-4-5",
            max_tokens=512,
            messages=[{"role": "user", "content": prompt}]
        )

        raw = response.content[0].text.strip()

        # Strip markdown code fences if Claude wraps the JSON
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]

        return json.loads(raw)

    except json.JSONDecodeError:
        return _fallback(risk_score)
    except Exception as e:
        print(f"[ai_analyzer] API error: {e}")
        return _fallback(risk_score)


def _fallback(risk_score: int) -> dict:
    """Returned when the Claude call fails — keeps the API response consistent."""
    return {
        "summary":        "Automated analysis completed. AI explanation unavailable right now.",
        "advice":         [
            "Do not share personal or financial information.",
            "Do not click any links in the message.",
            "Contact the sender through an official channel to verify.",
        ],
        "safe_to_ignore": risk_score < 20,
        "report_to":      "" if risk_score < 20 else "Your local cybercrime helpline or bank fraud team",
    }