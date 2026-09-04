import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.services.risk_engine import calculate_risk
from app.services.url_analyzer import analyze_url


def _sig(id_, category, description, severity, weight, risk_category=None, evidence_text=None):
    s = {
        "id": id_, "category": category, "description": description,
        "severity": severity, "weight": weight,
    }
    if risk_category:
        s["risk_category"] = risk_category
    if evidence_text:
        s["evidence_text"] = evidence_text
    return s


# --- 1. Legitimate delivery message -----------------------------------------

def test_legitimate_delivery_message_is_low():
    signals = []  # a clean "Your package will arrive Tuesday" message
    result = calculate_risk(signals)
    assert result["risk_score"] == 0
    assert result["risk_level"] == "LOW"
    assert result["detected_signals"] == []


# --- 2. Fake bank message ----------------------------------------------------

def test_fake_bank_message_is_high_or_critical():
    signals = [
        _sig("REQUEST_FOR_LOGIN_CREDENTIALS", "text",
             "Message asks user to re-enter online banking login and password",
             "critical", 9),
        _sig("BRAND_IMPERSONATION_CLAIM", "text",
             "Message claims to be from the user's bank", "high", 9),
        _sig("URGENCY_LANGUAGE", "text",
             "Message threatens account closure within 24 hours", "medium", 6),
        _sig("THREAT_LANGUAGE", "text",
             "Message threatens legal/account action if no response", "high", 7),
    ]
    url_result = analyze_url("http://secure-login.bankofamerica-verify.tk/account")
    signals += url_result["signals"]

    result = calculate_risk(signals)
    assert result["risk_level"] in ("HIGH", "CRITICAL")
    assert result["risk_score"] >= 51
    assert "REQUEST_FOR_LOGIN_CREDENTIALS" in result["detected_signals"]


# --- 3. Prize scam ------------------------------------------------------------

def test_prize_scam_is_medium_or_higher():
    signals = [
        _sig("PRIZE_CLAIM", "text", "Message claims user won a cash prize/lottery",
             "high", 8),
        _sig("REQUEST_FOR_PAYMENT", "text",
             "Message asks for a processing fee to claim the prize", "high", 8),
        _sig("URGENCY_LANGUAGE", "text",
             "Message pressures immediate response to claim prize", "medium", 6),
    ]
    result = calculate_risk(signals)
    assert result["risk_level"] in ("MEDIUM", "HIGH", "CRITICAL")
    assert result["risk_score"] >= 26


# --- 4. OTP scam ---------------------------------------------------------------

def test_otp_scam_is_high_or_critical():
    signals = [
        _sig("REQUEST_FOR_OTP", "text",
             "Message asks user to share a one-time verification code",
             "critical", 9),
        _sig("BRAND_IMPERSONATION_CLAIM", "text",
             "Message claims to be from a delivery/payment service", "high", 8),
        _sig("URGENCY_LANGUAGE", "text",
             "Message pressures user to respond immediately", "medium", 6),
    ]
    result = calculate_risk(signals)
    assert result["risk_level"] in ("HIGH", "CRITICAL")
    assert result["risk_score"] >= 51


# --- 5. Suspicious URL only -----------------------------------------------------

def test_suspicious_url_alone_is_at_least_medium():
    url_result = analyze_url("http://accounts-google.verify-secure-login.xyz/signin")
    result = calculate_risk(url_result["signals"])
    assert result["risk_level"] in ("MEDIUM", "HIGH", "CRITICAL")
    assert result["risk_score"] >= 26


def test_single_weak_url_signal_does_not_spike_to_critical():
    # A single low-severity signal (e.g. just a long URL) should NOT alone
    # push the score into CRITICAL — validates "no single-signal verdicts".
    url_result = analyze_url("https://example.com/" + "a" * 100)
    result = calculate_risk(url_result["signals"])
    assert result["risk_level"] in ("LOW", "MEDIUM")


# --- 6. Combination of multiple independent signals -----------------------------

def test_combination_of_many_signals_is_critical():
    signals = [
        _sig("REQUEST_FOR_LOGIN_CREDENTIALS", "text",
             "Message asks for login and password", "critical", 9),
        _sig("REQUEST_FOR_OTP", "text",
             "Message asks user to share OTP code", "critical", 9),
        _sig("REQUEST_FOR_PAYMENT", "text",
             "Message asks for a processing/gift card payment", "high", 8),
        _sig("BRAND_IMPERSONATION_CLAIM", "text",
             "Message claims to be from a known bank", "high", 9),
        _sig("URGENCY_LANGUAGE", "text",
             "Message threatens immediate account suspension", "medium", 6),
        _sig("THREAT_LANGUAGE", "text",
             "Message threatens legal consequences", "high", 7),
    ]
    url_result = analyze_url("http://192.168.1.5@secure-paypa1-verify.tk/login")
    signals += url_result["signals"]

    result = calculate_risk(signals)
    assert result["risk_level"] == "CRITICAL"
    assert result["risk_score"] >= 76
    assert len(result["score_breakdown"]) >= len(signals)


# --- Structural / explainability checks -----------------------------------------

def test_risk_score_is_not_labeled_as_probability():
    # This is a documentation-level guard: ensure no key in the output
    # implies a calibrated probability (e.g. "probability", "percent_chance").
    result = calculate_risk([_sig("URGENCY_LANGUAGE", "text", "urgent", "medium", 6)])
    forbidden_keys = {"probability", "percent_chance", "chance_of_scam"}
    assert forbidden_keys.isdisjoint(result.keys())


def test_ocr_low_confidence_downweights_ocr_signals():
    ocr_signal = _sig("URGENCY_LANGUAGE", "ocr",
                       "Urgent phrasing detected in screenshot text", "medium", 8)
    high_conf = calculate_risk([ocr_signal], ocr_confidence=0.95)
    low_conf = calculate_risk([ocr_signal], ocr_confidence=0.2)
    assert low_conf["risk_score"] < high_conf["risk_score"]


if __name__ == "__main__":
    test_functions = [v for k, v in list(globals().items()) if k.startswith("test_")]
    for fn in test_functions:
        fn()
    print(f"All {len(test_functions)} risk_engine tests passed.")