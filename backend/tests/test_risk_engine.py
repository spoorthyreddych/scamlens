import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.services.risk_engine import calculate_risk
from app.services.url_analyzer import analyze_url


def _sig(id_, category, description, severity, weight,
         risk_category=None, evidence_text=None):
    """Create a consistent test signal."""
    signal = {
        "id": id_,
        "category": category,
        "description": description,
        "severity": severity,
        "weight": weight,
    }

    if risk_category:
        signal["risk_category"] = risk_category

    if evidence_text:
        signal["evidence_text"] = evidence_text

    return signal


def _extract_signals(analyzer_result):
    """Normalize analyzer output formats."""

    if isinstance(analyzer_result, list):
        return analyzer_result

    if not isinstance(analyzer_result, dict):
        return []

    keys = ["signals", "detected_signals", "findings", "evidence"]

    for key in keys:
        value = analyzer_result.get(key)
        if isinstance(value, list):
            return value

    return []


def test_legitimate_delivery_message_is_low():
    signals = []

    result = calculate_risk(signals)

    assert result["risk_score"] == 0
    assert result["risk_level"] == "LOW"
    assert result["detected_signals"] == []


def test_fake_bank_message_is_high_or_critical():
    signals = [
        _sig(
            "REQUEST_FOR_LOGIN_CREDENTIALS",
            "text",
            "Message asks user to re-enter online banking login and password",
            "critical",
            9,
        ),
        _sig(
            "BRAND_IMPERSONATION_CLAIM",
            "text",
            "Message claims to be from the user's bank",
            "high",
            9,
        ),
        _sig(
            "URGENCY_LANGUAGE",
            "text",
            "Message threatens account closure within 24 hours",
            "medium",
            6,
        ),
        _sig(
            "THREAT_LANGUAGE",
            "text",
            "Message threatens legal action",
            "high",
            7,
        ),
    ]

    url_result = analyze_url(
        "http://secure-login.bankofamerica-verify.tk/account"
    )

    signals.extend(_extract_signals(url_result))

    result = calculate_risk(signals)

    assert result["risk_level"] in ("HIGH", "CRITICAL")
    assert result["risk_score"] >= 51
    assert "REQUEST_FOR_LOGIN_CREDENTIALS" in result["detected_signals"]


def test_prize_scam_is_medium_or_higher():
    signals = [
        _sig(
            "PRIZE_CLAIM",
            "text",
            "Message claims user won a cash prize lottery",
            "high",
            8,
        ),
        _sig(
            "REQUEST_FOR_PAYMENT",
            "text",
            "Message asks for processing fee payment",
            "high",
            8,
        ),
        _sig(
            "URGENCY_LANGUAGE",
            "text",
            "Message pressures immediate response",
            "medium",
            6,
        ),
    ]

    result = calculate_risk(signals)

    assert result["risk_level"] in (
        "MEDIUM",
        "HIGH",
        "CRITICAL",
    )

    assert result["risk_score"] >= 26


def test_otp_scam_is_high_or_critical():
    signals = [
        _sig(
            "REQUEST_FOR_OTP",
            "text",
            "Message asks user to share OTP code",
            "critical",
            9,
        ),
        _sig(
            "BRAND_IMPERSONATION_CLAIM",
            "text",
            "Message claims to be from delivery service",
            "high",
            8,
        ),
        _sig(
            "URGENCY_LANGUAGE",
            "text",
            "Message pressures immediate response",
            "medium",
            6,
        ),
    ]

    result = calculate_risk(signals)

    assert result["risk_level"] in ("HIGH", "CRITICAL")
    assert result["risk_score"] >= 51


def test_suspicious_url_alone_is_at_least_medium():
    url_result = analyze_url(
        "http://accounts-google.verify-secure-login.xyz/signin"
    )

    signals = _extract_signals(url_result)

    result = calculate_risk(signals)

    assert result["risk_level"] in (
        "MEDIUM",
        "HIGH",
        "CRITICAL",
    )

    assert result["risk_score"] >= 26


def test_single_weak_url_signal_does_not_spike_to_critical():
    url_result = analyze_url(
        "https://example.com/" + "a" * 100
    )

    signals = _extract_signals(url_result)

    result = calculate_risk(signals)

    assert result["risk_level"] in ("LOW", "MEDIUM")


def test_combination_of_many_signals_is_critical():
    signals = [
        _sig(
            "REQUEST_FOR_LOGIN_CREDENTIALS",
            "text",
            "Message asks for login and password",
            "critical",
            9,
        ),
        _sig(
            "REQUEST_FOR_OTP",
            "text",
            "Message asks user to share OTP code",
            "critical",
            9,
        ),
        _sig(
            "REQUEST_FOR_PAYMENT",
            "text",
            "Message asks for payment",
            "high",
            8,
        ),
        _sig(
            "BRAND_IMPERSONATION_CLAIM",
            "text",
            "Message claims to be from known bank",
            "high",
            9,
        ),
        _sig(
            "URGENCY_LANGUAGE",
            "text",
            "Message threatens immediate suspension",
            "medium",
            6,
        ),
        _sig(
            "THREAT_LANGUAGE",
            "text",
            "Message threatens legal consequences",
            "high",
            8,
        ),
    ]

    result = calculate_risk(signals)

    assert result["risk_level"] == "CRITICAL"
    assert result["risk_score"] >= 51