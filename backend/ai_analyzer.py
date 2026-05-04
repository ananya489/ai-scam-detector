import os
import json
from openai import OpenAI
from dotenv import load_dotenv
from pathlib import Path
from backend.prompts import build_analysis_prompt

# ✅ Force load .env from root
env_path = Path(__file__).resolve().parent.parent / ".env"
load_dotenv(dotenv_path=env_path)

# ✅ Get API key
api_key = os.getenv("OPENAI_API_KEY")

if not api_key:
    raise ValueError("❌ OPENAI_API_KEY not found in .env")

client = OpenAI(api_key=api_key)


def get_ai_analysis(message, signals, scam_type, tactics, risk_score):
    prompt = build_analysis_prompt(message, signals, scam_type, tactics, risk_score)

    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "Return ONLY JSON."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=512,
            temperature=0.3
        )

        raw = response.choices[0].message.content.strip()

        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]

        return json.loads(raw)

    except Exception as e:
        print("AI ERROR:", e)
        return _fallback(risk_score)


def _fallback(risk_score):
    return {
        "summary": "AI unavailable.",
        "advice": [
            "Do not share personal info",
            "Avoid clicking links",
            "Verify sender"
        ],
        "safe_to_ignore": risk_score < 20,
        "report_to": "" if risk_score < 20 else "Cybercrime helpline"
    }