"""
risk_engine.py

DETERMINISTIC RISK ENGINE stage.

Takes the deduplicated signal list produced by evidence_builder.py and
computes a deterministic, explainable risk_score. No LLM is used here —
this module is purely rule-based arithmetic so every point on the score
can be traced back to a specific signal.

IMPORTANT: risk_score is a heuristic severity index (0-100), NOT a
statistically calibrated probability. Never present it as "X% chance of
scam" — only as a risk score / risk level.
"""

from typing import Dict, List, Optional

# ---------------------------------------------------------------------------
# CONFIGURABLE WEIGHTS / CAPS
# Tune these as the system is evaluated against real examples. Keeping them
# as named constants (not inline magic numbers) is what makes this module
# "configurable" per the phase requirement.
# ---------------------------------------------------------------------------

RISK_LEVELS = [
    (0, 25, "LOW"),
    (26, 50, "MEDIUM"),
    (51, 75, "HIGH"),
    (76, 100, "CRITICAL"),
]

# Max points any single category can contribute, BEFORE the combination
# scaling factor is applied. This is the primary anti-double-counting
# mechanism: no matter how many similar signals fire in one category,
# that category cannot single-handedly dominate the score.
CATEGORY_CAPS = {
    "credential_harvesting": 40,
    "payment_pressure": 40,
    "brand_impersonation": 35,
    "url_structure": 25,
    "text_manipulation": 25,
    "other": 10,
}

# Within a single category, each additional signal contributes less than
# the last (diminishing returns). This is the second anti-double-counting
# mechanism: two signals that are really pointing at the "same" underlying
# problem (e.g. two different phrasing of urgency) don't just add linearly.
DIMINISHING_MULTIPLIERS = [1.0, 0.7, 0.5, 0.3, 0.15]
DIMINISHING_TAIL_MULTIPLIER = 0.1  # applied to any signal beyond the list above

# When MULTIPLE independent categories fire together, that combination is
# itself meaningful evidence (a scam message rarely trips only one category).
# This scaling factor rewards genuine cross-category corroboration, applied
# AFTER per-category caps, BEFORE the final 0-100 clamp.
MULTI_CATEGORY_SCALING = {
    1: 1.0,   # only one category triggered -> no boost
    2: 1.1,
    3: 1.2,
    4: 1.3,
}
MULTI_CATEGORY_SCALING_MAX = 1.35  # for 5+ categories

# If a signal came from OCR-extracted text, and OCR confidence is known and
# low, we trust that signal less. This is the only place ocr_confidence is
# used — deterministically, not via any AI judgement call.
OCR_LOW_CONFIDENCE_THRESHOLD = 0.6

# ---------------------------------------------------------------------------
# Keyword-based fallback classifier
# Used only when a signal doesn't already carry an explicit "risk_category".
# Documented limitation: this is a heuristic, not a semantic understanding.
# ---------------------------------------------------------------------------

CREDENTIAL_KEYWORDS = [
    "password", "otp", "one-time code", "verification code", "login",
    "signin", "sign-in", "credential", "pin code", "security code",
    "2fa", "authenticate",
]

PAYMENT_KEYWORDS = [
    "payment", "gift card", "wire transfer", "bank transfer",
    "western union", "crypto", "bitcoin", "processing fee",
    "claim your prize", "lottery", "winner", "cash prize",
    "refund fee", "shipping fee", "customs fee", "pay now",
]

IMPERSONATION_KEYWORDS = [
    "impersonat", "typosquat", "brand", "spoof", "lookalike",
    "claims to be", "posing as", "pretends to be",
]


def _classify_signal(signal: Dict) -> str:
    """Determines which risk category a signal counts toward."""
    if signal.get("risk_category"):
        return signal["risk_category"]

    haystack = f"{signal.get('id', '')} {signal.get('description', '')}".lower()

    if any(k in haystack for k in CREDENTIAL_KEYWORDS):
        return "credential_harvesting"
    if any(k in haystack for k in PAYMENT_KEYWORDS):
        return "payment_pressure"
    if any(k in haystack for k in IMPERSONATION_KEYWORDS):
        return "brand_impersonation"

    source_category = signal.get("category")
    if source_category == "url":
        return "url_structure"
    if source_category in ("text", "ocr"):
        return "text_manipulation"

    return "other"


def _risk_level_for_score(score: int) -> str:
    for low, high, label in RISK_LEVELS:
        if low <= score <= high:
            return label
    return "CRITICAL"  # safety fallback, should be unreachable given clamp


def _multi_category_scale(num_categories: int) -> float:
    if num_categories >= 5:
        return MULTI_CATEGORY_SCALING_MAX
    return MULTI_CATEGORY_SCALING.get(num_categories, 1.0)


def calculate_risk(
    signals: List[Dict],
    ocr_confidence: Optional[float] = None,
) -> Dict:
    """
    Computes a deterministic risk score from aggregated evidence signals.

    Args:
        signals: deduplicated signal list, e.g. EvidenceBundle.evidence from
                 evidence_builder.py. Each signal must have at least:
                 id, category, description, severity, weight.
        ocr_confidence: 0.0-1.0 confidence score from OCR extraction, if the
                 investigation included a screenshot. Signals whose source
                 category is "ocr" are down-weighted when this is low.

    Returns:
        {
            "risk_score": int (0-100),
            "risk_level": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
            "score_breakdown": [ ...per-signal contribution detail... ],
            "detected_signals": [ ...signal ids that contributed... ],
        }
    """
    if not signals:
        return {
            "risk_score": 0,
            "risk_level": "LOW",
            "score_breakdown": [],
            "detected_signals": [],
        }

    # Group signals by risk category, sorted within each category by
    # base weight descending, so the diminishing multiplier applies to the
    # strongest evidence first.
    grouped: Dict[str, List[Dict]] = {}
    for signal in signals:
        category = _classify_signal(signal)
        grouped.setdefault(category, []).append(signal)

    for category in grouped:
        grouped[category].sort(key=lambda s: s.get("weight", 0), reverse=True)

    score_breakdown = []
    category_totals: Dict[str, float] = {}

    for category, category_signals in grouped.items():
        raw_total = 0.0
        for idx, signal in enumerate(category_signals):
            base_weight = float(signal.get("weight", 0))

            # OCR confidence adjustment (deterministic, not AI-driven)
            adjusted_weight = base_weight
            ocr_adjustment_applied = False
            if signal.get("category") == "ocr" and ocr_confidence is not None:
                confidence = max(0.0, min(1.0, ocr_confidence))
                adjusted_weight = base_weight * confidence
                ocr_adjustment_applied = confidence < OCR_LOW_CONFIDENCE_THRESHOLD

            multiplier = (
                DIMINISHING_MULTIPLIERS[idx]
                if idx < len(DIMINISHING_MULTIPLIERS)
                else DIMINISHING_TAIL_MULTIPLIER
            )
            points = adjusted_weight * multiplier
            raw_total += points

            score_breakdown.append({
                "signal_id": signal.get("id"),
                "risk_category": category,
                "source_category": signal.get("category"),
                "severity": signal.get("severity"),
                "base_weight": base_weight,
                "adjusted_weight": round(adjusted_weight, 2),
                "diminishing_multiplier": multiplier,
                "points_contributed": round(points, 2),
                "ocr_confidence_applied": ocr_adjustment_applied,
                "description": signal.get("description"),
            })

        cap = CATEGORY_CAPS.get(category, CATEGORY_CAPS["other"])
        category_totals[category] = min(raw_total, cap)

    num_categories_triggered = len([c for c, total in category_totals.items() if total > 0])
    scale = _multi_category_scale(num_categories_triggered)

    pre_clamp_score = sum(category_totals.values()) * scale
    risk_score = int(round(max(0.0, min(100.0, pre_clamp_score))))
    risk_level = _risk_level_for_score(risk_score)

    detected_signals = [s.get("id") for s in signals if s.get("id")]

    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "score_breakdown": score_breakdown,
        "detected_signals": detected_signals,
        # Extra explainability fields (additive, doesn't remove required keys)
        "category_totals": {k: round(v, 2) for k, v in category_totals.items()},
        "multi_category_scale_applied": scale,
    }