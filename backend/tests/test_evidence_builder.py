import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.services.evidence_builder import build_evidence, aggregate_signals
from app.services.risk_engine import calculate_risk
from app.services.text_analyzer import analyze_text
from app.services.url_analyzer import analyze_url


def test_empty_input():
    """Verify empty input handling across various empty structures."""

    res1 = build_evidence()
    assert res1 == {
        "signals": [],
        "total_signals": 0,
        "sources_used": [],
    }

    res2 = build_evidence(None)
    assert res2 == {
        "signals": [],
        "total_signals": 0,
        "sources_used": [],
    }

    res3 = build_evidence([])
    assert res3 == {
        "signals": [],
        "total_signals": 0,
        "sources_used": [],
    }

    res4 = build_evidence({})
    assert res4 == {
        "signals": [],
        "total_signals": 0,
        "sources_used": [],
    }

    res5 = build_evidence(None, [], {})
    assert res5 == {
        "signals": [],
        "total_signals": 0,
        "sources_used": [],
    }


def test_one_analyzer():
    """Verify evidence builder works with a single analyzer output."""

    text_findings = analyze_text(
        "Please share your OTP code immediately to prevent account closure."
    )

    result = build_evidence(text_analyzer=text_findings)

    assert result["total_signals"] > 0
    assert len(result["signals"]) == result["total_signals"]
    assert "text" in result["sources_used"]

    sig = result["signals"][0]

    assert "id" in sig
    assert "source" in sig
    assert "sources" in sig
    assert "category" in sig
    assert "description" in sig
    assert "severity" in sig
    assert "weight" in sig


def test_multiple_analyzers():
    """Verify evidence builder aggregates controlled signals from text, url, and OCR."""

    text_findings = [
        {
            "signal": "REQUEST_FOR_OTP",
            "severity": "HIGH",
            "reason": "Asks user for OTP",
            "category": "text",
        }
    ]

    url_output = {
        "source": "url",
        "signals": [
            {
                "signal": "SUSPICIOUS_URL",
                "severity": "HIGH",
                "reason": "Suspicious domain structure detected",
                "category": "url",
            }
        ],
    }

    ocr_output = {
        "source": "ocr",
        "ocr_confidence": 0.9,
        "findings": [
            {
                "signal": "BRAND_IMPERSONATION_CLAIM",
                "severity": "CRITICAL",
                "reason": "Logo impersonating Google",
                "category": "ocr",
            }
        ],
    }

    result = build_evidence(
        text=text_findings,
        url=url_output,
        ocr=ocr_output,
    )

    assert result["total_signals"] == 3

    assert set(result["sources_used"]) == {
        "text",
        "url",
        "ocr",
    }

    signal_ids = {
        signal["id"]
        for signal in result["signals"]
    }

    assert "REQUEST_FOR_OTP" in signal_ids
    assert "SUSPICIOUS_URL" in signal_ids
    assert "BRAND_IMPERSONATION_CLAIM" in signal_ids


def test_duplicate_signal_ids():
    """Verify duplicate signals across analyzers are merged."""

    text_findings = [
        {
            "id": "URGENCY_LANGUAGE",
            "signal": "URGENCY_LANGUAGE",
            "severity": "MEDIUM",
            "description": "Text uses urgent phrasing",
            "weight": 5.0,
            "category": "text",
        }
    ]

    ocr_findings = {
        "source": "ocr",
        "findings": [
            {
                "id": "URGENCY_LANGUAGE",
                "signal": "URGENCY_LANGUAGE",
                "severity": "HIGH",
                "description": (
                    "Image banner uses urgent phrasing (ACT NOW)"
                ),
                "weight": 8.0,
                "category": "ocr",
            }
        ],
    }

    result = build_evidence(
        text=text_findings,
        ocr=ocr_findings,
    )

    assert result["total_signals"] == 1

    assert set(result["sources_used"]) == {
        "text",
        "ocr",
    }

    sig = result["signals"][0]

    assert sig["id"] == "URGENCY_LANGUAGE"

    assert set(sig["sources"]) == {
        "text",
        "ocr",
    }

    assert sig["severity"] == "HIGH"
    assert sig["weight"] == 8.0

    assert "Image banner" in sig["description"]


def test_provenance_preservation():
    """Verify all evidence provenance attributes are preserved."""

    findings = [
        {
            "id": "CUSTOM_SIGNAL_01",
            "source": "custom_scanner",
            "category": "payment_pressure",
            "description": (
                "Detailed explanation of suspicious payment request"
            ),
            "severity": "CRITICAL",
            "weight": 9.5,
            "evidence_text": "pay $500 via bitcoin",
            "risk_category": "payment_pressure",
        }
    ]

    result = build_evidence(findings)

    assert result["total_signals"] == 1

    sig = result["signals"][0]

    assert sig["id"] == "CUSTOM_SIGNAL_01"
    assert sig["source"] == "custom_scanner"
    assert sig["sources"] == ["custom_scanner"]
    assert sig["category"] == "payment_pressure"

    assert (
        sig["description"]
        == "Detailed explanation of suspicious payment request"
    )

    assert sig["severity"] == "CRITICAL"
    assert sig["weight"] == 9.5
    assert sig["evidence_text"] == "pay $500 via bitcoin"
    assert sig["risk_category"] == "payment_pressure"


def test_malformed_input_safety():
    """Verify robust handling of malformed inputs."""

    malformed_inputs = [
        "not a dict or list",
        12345,
        True,
        [None, 123, "invalid", {}],
        {
            "findings": "not a list",
        },
        {
            "findings": [
                {
                    "no_signal_id": True,
                }
            ]
        },
        {
            "findings": [
                {
                    "id": "VALID_SIGNAL",
                    "severity": "invalid_severity",
                    "weight": "not_a_number",
                }
            ]
        },
    ]

    result = build_evidence(*malformed_inputs)

    assert isinstance(result, dict)

    assert "signals" in result
    assert "total_signals" in result
    assert "sources_used" in result

    assert result["total_signals"] == 1

    sig = result["signals"][0]

    assert sig["id"] == "VALID_SIGNAL"
    assert sig["severity"] == "LOW"
    assert sig["weight"] == 0.0


def test_compatibility_with_risk_engine():
    """Verify evidence output works directly with risk engine."""

    text_findings = analyze_text(
        "Urgent! Send us your password and OTP immediately "
        "to avoid account suspension!"
    )

    url_output = analyze_url(
        "http://secure-login.bankofamerica-verify.tk/account"
    )

    evidence = build_evidence(
        text=text_findings,
        url=url_output,
    )

    risk_res = calculate_risk(
        evidence["signals"]
    )

    assert isinstance(risk_res, dict)

    assert "risk_score" in risk_res
    assert "risk_level" in risk_res
    assert "detected_signals" in risk_res

    assert risk_res["risk_score"] > 0

    assert risk_res["risk_level"] in (
        "MEDIUM",
        "HIGH",
        "CRITICAL",
    )

    assert len(risk_res["detected_signals"]) == (
        evidence["total_signals"]
    )


def test_aggregate_signals_alias():
    """Verify aggregate_signals behaves exactly like build_evidence."""

    text_findings = analyze_text(
        "Enter your password now"
    )

    res1 = build_evidence(
        text=text_findings
    )

    res2 = aggregate_signals(
        text=text_findings
    )

    assert res1 == res2