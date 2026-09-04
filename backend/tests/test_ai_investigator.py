"""
Unit tests for backend/app/services/ai_investigator.py

Covers:
- Successful AI API response with mocked OpenAI client
- Missing FEATHERLESS_API_KEY fallback
- Featherless API network failure fallback
- Invalid JSON response handling
- Verification of required response keys
- Verification that risk_score is never modified
"""

import json
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

# Ensure backend directory is in sys.path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.services.ai_investigator import investigate_with_ai

REQUIRED_KEYS = [
    "summary",
    "why_suspicious",
    "evidence_explanation",
    "recommended_actions",
    "user_safety_warning",
]


def _assert_required_keys(result: dict):
    """Helper to verify that all required keys are present in the response dict."""
    assert isinstance(result, dict), "Result must be a dictionary"
    for key in REQUIRED_KEYS:
        assert key in result, f"Missing required key: {key}"


def test_successful_ai_response(monkeypatch):
    """Test successful AI investigation with mocked Featherless API call."""
    monkeypatch.setenv("FEATHERLESS_API_KEY", "fake-featherless-key-123")

    mock_ai_json = json.dumps({
        "summary": "This message is a potential phishing attempt targeting online credentials.",
        "why_suspicious": [
            "The message urgently requests a one-time verification code (OTP).",
            "Legitimate services never ask users to send back confidential security codes."
        ],
        "evidence_explanation": [
            {
                "signal_id": "REQUEST_FOR_OTP",
                "explanation": "The text explicitly asks the user to enter or reply with an OTP."
            }
        ],
        "recommended_actions": [
            "Do not share any verification codes.",
            "Contact your service provider directly."
        ],
        "user_safety_warning": "High risk of account takeover if OTP is shared."
    })

    with patch("app.services.ai_investigator.OpenAI") as mock_openai_cls:
        # Mock client completion response
        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client
        mock_response = MagicMock()
        mock_response.choices = [MagicMock(message=MagicMock(content=mock_ai_json))]
        mock_client.chat.completions.create.return_value = mock_response

        text = "Please reply with your OTP code immediately to verify your account."
        evidence = [{"id": "REQUEST_FOR_OTP", "severity": "HIGH", "category": "text"}]
        risk_result = {
            "risk_score": 75,
            "risk_level": "HIGH",
            "detected_signals": ["REQUEST_FOR_OTP"]
        }

        result = investigate_with_ai(text, evidence, risk_result)

        _assert_required_keys(result)
        assert result["summary"] == "This message is a potential phishing attempt targeting online credentials."
        assert len(result["why_suspicious"]) == 2
        assert result["evidence_explanation"][0]["signal_id"] == "REQUEST_FOR_OTP"


def test_missing_api_key_fallback(monkeypatch):
    """Test safe fallback response when FEATHERLESS_API_KEY environment variable is missing."""
    monkeypatch.delenv("FEATHERLESS_API_KEY", raising=False)

    text = "Verify your account by clicking this link."
    evidence = [{"id": "SUSPICIOUS_URL", "severity": "MEDIUM"}]
    risk_result = {
        "risk_score": 45,
        "risk_level": "MEDIUM",
        "detected_signals": ["SUSPICIOUS_URL"]
    }

    result = investigate_with_ai(text, evidence, risk_result)

    _assert_required_keys(result)
    assert "45" in result["summary"] or "MEDIUM" in result["summary"]
    assert len(result["recommended_actions"]) > 0


def test_api_failure_fallback(monkeypatch):
    """Test safe fallback response when Featherless API call raises an exception."""
    monkeypatch.setenv("FEATHERLESS_API_KEY", "fake-featherless-key-123")

    with patch("app.services.ai_investigator.OpenAI") as mock_openai_cls:
        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client
        # Simulate API network failure
        mock_client.chat.completions.create.side_effect = RuntimeError("Featherless API Connection Timeout")

        text = "Urgent: your account will be suspended in 24 hours."
        evidence = [{"id": "URGENCY_LANGUAGE", "severity": "MEDIUM"}]
        risk_result = {
            "risk_score": 50,
            "risk_level": "MEDIUM",
            "detected_signals": ["URGENCY_LANGUAGE"]
        }

        result = investigate_with_ai(text, evidence, risk_result)

        _assert_required_keys(result)
        assert len(result["evidence_explanation"]) > 0


def test_invalid_json_returned_by_ai(monkeypatch):
    """Test safe fallback response when Featherless AI returns malformed JSON."""
    monkeypatch.setenv("FEATHERLESS_API_KEY", "fake-featherless-key-123")

    with patch("app.services.ai_investigator.OpenAI") as mock_openai_cls:
        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client
        mock_response = MagicMock()
        # Return invalid non-JSON output
        mock_response.choices = [MagicMock(message=MagicMock(content="Sorry, I cannot process this request as JSON."))]
        mock_client.chat.completions.create.return_value = mock_response

        text = "Enter your password to claim $1000 prize."
        evidence = [{"id": "REQUEST_FOR_PASSWORD", "severity": "HIGH"}]
        risk_result = {
            "risk_score": 80,
            "risk_level": "CRITICAL",
            "detected_signals": ["REQUEST_FOR_PASSWORD"]
        }

        result = investigate_with_ai(text, evidence, risk_result)

        _assert_required_keys(result)


def test_risk_score_is_not_modified(monkeypatch):
    """Verify that investigate_with_ai does NOT alter the deterministic risk_score or risk_result object."""
    monkeypatch.delenv("FEATHERLESS_API_KEY", raising=False)

    text = "Send money via wire transfer now."
    evidence = [{"id": "REQUEST_FOR_PAYMENT", "severity": "HIGH"}]
    original_risk_result = {
        "risk_score": 88,
        "risk_level": "CRITICAL",
        "detected_signals": ["REQUEST_FOR_PAYMENT"]
    }

    result = investigate_with_ai(text, evidence, original_risk_result)

    _assert_required_keys(result)
    # Ensure original risk_result dict remains untouched
    assert original_risk_result["risk_score"] == 88
    assert original_risk_result["risk_level"] == "CRITICAL"
    # Ensure risk_score is not returned or overridden inside AI output
    assert "risk_score" not in result
