import sys
import os
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.services.investigation_service import investigate, _extract_urls


def test_url_extraction():
    """Test regex URL extraction for http, https, and www."""
    text = "Check http://example.com/login and https://secure-bank.tk or www.paypal-verify.xyz for info."
    urls = _extract_urls(text)
    assert len(urls) == 3
    assert "http://example.com/login" in urls
    assert "https://secure-bank.tk" in urls
    assert "www.paypal-verify.xyz" in urls


def test_empty_input_validation():
    """Test empty and invalid inputs return structured error."""
    res1 = investigate("")
    assert res1["status"] == "error"
    assert res1["risk_score"] == 0

    res2 = investigate("   ")
    assert res2["status"] == "error"

    res3 = investigate(None)
    assert res3["status"] == "error"


def test_investigate_end_to_end_mocked_ai():
    """Test end-to-end investigation pipeline execution."""
    text = "Urgent: Enter your password and OTP code at http://accounts-google.verify-secure-login.xyz/signin to claim your prize!"

    with patch("app.services.investigation_service.investigate_with_ai") as mock_ai:
        mock_ai.return_value = {
            "summary": "High risk phishing message detected.",
            "why_suspicious": ["Requests password and OTP."],
            "evidence_explanation": [],
            "recommended_actions": ["Do not enter credentials."],
            "user_safety_warning": "Potential account compromise."
        }

        result = investigate(text)

        assert result["status"] == "success"
        assert result["input_type"] == "text"
        assert len(result["urls_detected"]) == 1
        assert result["risk_score"] > 0
        assert result["risk_level"] in ("HIGH", "CRITICAL")
        assert len(result["evidence"]) > 0
        assert "ai_investigation" in result
        assert result["ai_investigation"]["summary"] == "High risk phishing message detected."
