from typing import Dict, List, Optional


RISK_LEVELS = [
    (0, 25, "LOW"),
    (26, 50, "MEDIUM"),
    (51, 75, "HIGH"),
    (76, 100, "CRITICAL"),
]


CATEGORY_CAPS = {
    "credential_harvesting": 45,
    "payment_pressure": 40,
    "brand_impersonation": 35,
    "url_structure": 35,
    "text_manipulation": 30,
    "other": 15,
}


DIMINISHING_MULTIPLIERS = [1.0, 0.7, 0.5, 0.3, 0.15]
DIMINISHING_TAIL_MULTIPLIER = 0.1


MULTI_CATEGORY_SCALING = {
    1: 1.0,
    2: 1.15,
    3: 1.3,
    4: 1.4,
}

MULTI_CATEGORY_SCALING_MAX = 1.5


OCR_LOW_CONFIDENCE_THRESHOLD = 0.6


CREDENTIAL_KEYWORDS = [
    "password",
    "otp",
    "one-time code",
    "verification code",
    "login",
    "signin",
    "sign-in",
    "credential",
    "pin",
    "security code",
    "2fa",
    "authenticate",
]


PAYMENT_KEYWORDS = [
    "payment",
    "pay",
    "gift card",
    "wire transfer",
    "bank transfer",
    "crypto",
    "bitcoin",
    "processing fee",
    "claim your prize",
    "lottery",
    "winner",
    "cash prize",
    "refund fee",
    "shipping fee",
    "customs fee",
]


IMPERSONATION_KEYWORDS = [
    "impersonat",
    "typosquat",
    "brand",
    "spoof",
    "lookalike",
    "claims to be",
    "posing as",
    "pretends to be",
]


SEVERITY_POINTS = {
    "critical": 28,
    "high": 20,
    "medium": 12,
    "low": 5,
}


SPECIAL_SIGNAL_POINTS = {
    "REQUEST_FOR_OTP": 32,
    "REQUEST_FOR_LOGIN_CREDENTIALS": 32,
    "REQUEST_FOR_PASSWORD": 32,
    "REQUEST_FOR_PAYMENT": 24,
    "PRIZE_CLAIM": 18,
    "BRAND_IMPERSONATION_CLAIM": 22,
    "SUSPICIOUS_URL": 22,
    "IP_ADDRESS_URL": 20,
    "URL_TYPO_SQUATTING": 22,
    "URL_SHORTENER": 12,
    "URGENCY_LANGUAGE": 14,
    "THREAT_LANGUAGE": 18,
}


def _normalize_severity(severity):
    if severity is None:
        return "low"

    return str(severity).strip().lower()


def _get_signal_id(signal):
    value = (
        signal.get("id")
        or signal.get("signal")
        or signal.get("name")
        or signal.get("type")
        or ""
    )

    return str(value).upper().strip()


def _classify_signal(signal):
    if signal.get("risk_category"):
        return signal["risk_category"]

    signal_id = _get_signal_id(signal).lower()

    description = str(
        signal.get("description")
        or signal.get("reason")
        or signal.get("message")
        or ""
    ).lower()

    haystack = signal_id + " " + description

    if any(keyword in haystack for keyword in CREDENTIAL_KEYWORDS):
        return "credential_harvesting"

    if any(keyword in haystack for keyword in PAYMENT_KEYWORDS):
        return "payment_pressure"

    if any(keyword in haystack for keyword in IMPERSONATION_KEYWORDS):
        return "brand_impersonation"

    source_category = str(signal.get("category", "")).lower()

    if source_category == "url":
        return "url_structure"

    if source_category in ("text", "ocr"):
        return "text_manipulation"

    return "other"


def _risk_level_for_score(score):
    for low, high, label in RISK_LEVELS:
        if low <= score <= high:
            return label

    return "CRITICAL"


def _multi_category_scale(num_categories):
    if num_categories >= 5:
        return MULTI_CATEGORY_SCALING_MAX

    return MULTI_CATEGORY_SCALING.get(num_categories, 1.0)


def _get_base_points(signal):
    signal_id = _get_signal_id(signal)

    if signal_id in SPECIAL_SIGNAL_POINTS:
        return float(SPECIAL_SIGNAL_POINTS[signal_id])

    severity = _normalize_severity(signal.get("severity"))

    severity_points = SEVERITY_POINTS.get(severity, 5)

    raw_weight = signal.get("weight", 0)

    try:
        raw_weight = float(raw_weight)
    except (TypeError, ValueError):
        raw_weight = 0

    weight_bonus = max(0, min(raw_weight, 10)) * 0.5

    return severity_points + weight_bonus


def calculate_risk(
    signals: List[Dict],
    ocr_confidence: Optional[float] = None,
) -> Dict:

    if not signals:
        return {
            "risk_score": 0,
            "risk_level": "LOW",
            "score_breakdown": [],
            "detected_signals": [],
            "signals": [],
            "category_totals": {},
            "multi_category_scale_applied": 1.0,
        }

    grouped = {}

    for signal in signals:
        if not isinstance(signal, dict):
            continue

        category = _classify_signal(signal)

        if category not in grouped:
            grouped[category] = []

        grouped[category].append(signal)

    for category in grouped:
        grouped[category].sort(
            key=lambda signal: _get_base_points(signal),
            reverse=True,
        )

    score_breakdown = []
    category_totals = {}

    for category, category_signals in grouped.items():

        raw_total = 0.0

        for index, signal in enumerate(category_signals):

            base_points = _get_base_points(signal)

            adjusted_points = base_points
            ocr_adjustment_applied = False

            if (
                str(signal.get("category", "")).lower() == "ocr"
                and ocr_confidence is not None
            ):
                confidence = max(
                    0.0,
                    min(1.0, float(ocr_confidence))
                )

                adjusted_points = base_points * confidence

                if confidence < OCR_LOW_CONFIDENCE_THRESHOLD:
                    ocr_adjustment_applied = True

            if index < len(DIMINISHING_MULTIPLIERS):
                multiplier = DIMINISHING_MULTIPLIERS[index]
            else:
                multiplier = DIMINISHING_TAIL_MULTIPLIER

            points_contributed = adjusted_points * multiplier

            raw_total += points_contributed

            score_breakdown.append({
                "signal_id": _get_signal_id(signal),
                "risk_category": category,
                "source_category": signal.get("category"),
                "severity": _normalize_severity(signal.get("severity")),
                "base_points": round(base_points, 2),
                "adjusted_points": round(adjusted_points, 2),
                "diminishing_multiplier": multiplier,
                "points_contributed": round(points_contributed, 2),
                "ocr_confidence_applied": ocr_adjustment_applied,
                "description": (
                    signal.get("description")
                    or signal.get("reason")
                    or signal.get("message")
                    or ""
                ),
            })

        cap = CATEGORY_CAPS.get(
            category,
            CATEGORY_CAPS["other"]
        )

        category_totals[category] = min(raw_total, cap)

    active_categories = [
        category
        for category, total in category_totals.items()
        if total > 0
    ]

    scale = _multi_category_scale(len(active_categories))

    pre_clamp_score = sum(category_totals.values()) * scale

    risk_score = int(
        round(
            max(
                0.0,
                min(100.0, pre_clamp_score)
            )
        )
    )

    risk_level = _risk_level_for_score(risk_score)

    detected_signals = []

    for signal in signals:
        if not isinstance(signal, dict):
            continue

        signal_id = _get_signal_id(signal)

        if signal_id and signal_id not in detected_signals:
            detected_signals.append(signal_id)

    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "score_breakdown": score_breakdown,
        "detected_signals": detected_signals,
        "signals": detected_signals,
        "category_totals": {
            category: round(total, 2)
            for category, total in category_totals.items()
        },
        "multi_category_scale_applied": scale,
    }