import re
from backend.playbook import SCAM_PLAYBOOK, TACTIC_DEFINITIONS

def _keyword_hit_count(text: str, keywords: list[str]) -> int:
    """Count how many keywords appear in the text."""
    return sum(1 for kw in keywords if kw.lower() in text)


def _signal_overlap(detected_signal_ids: list[str], playbook_signals: list[str]) -> int:
    """Count how many of this scam's expected signals were actually detected."""
    return len(set(detected_signal_ids) & set(playbook_signals))


def match_scam_type(text: str, detected_signal_ids: list[str]) -> dict | None:
    """
    Score every scam type and return the best match (or None if no match).

    Scoring per scam type:
      +2  per keyword hit
      +3  per overlapping signal (signals are stronger evidence)
    Minimum threshold to be reported: score >= 4
    """
    text_lower = text.lower()
    best       = None
    best_score = 0

    for scam in SCAM_PLAYBOOK:
        kw_hits      = _keyword_hit_count(text_lower, scam["keywords"])
        signal_hits  = _signal_overlap(detected_signal_ids, scam["signals"])
        score        = (kw_hits * 2) + (signal_hits * 3)

        if score > best_score:
            best_score = score
            best = {
                "id":          scam["id"],
                "name":        scam["name"],
                "description": scam["description"],
                "match_score": score,
                "keyword_hits": kw_hits,
                "signal_hits":  signal_hits,
            }

    if best and best_score >= 4:
        return best
    return None


def detect_tactics(text: str) -> list[dict]:
    """
    Scan text for psychological manipulation tactics.
    Returns list of matched tactics with descriptions.
    """
    text_lower = text.lower()
    found      = []

    for tactic_id, tactic in TACTIC_DEFINITIONS.items():
        for pattern in tactic["patterns"]:
            if re.search(pattern, text_lower):
                found.append({
                    "id":          tactic_id,
                    "label":       tactic["label"],
                    "description": tactic["description"],
                })
                break       # one match per tactic is enough

    return found