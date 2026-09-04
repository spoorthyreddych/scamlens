"""
ScamLens — tests for app.services.text_analyzer

Run from the `backend/` directory with:
    python -m pytest tests/test_text_analyzer.py -v

These tests are independent of FastAPI — they import and call
`analyze_text` directly, matching the requirement that the analyzer
module stays decoupled from route code.

Each category required by the spec gets at least one SCAM example
(signal must be present) and one LEGITIMATE example (signal must be
absent), for well over 15 total test cases.
"""

import sys
from pathlib import Path

# Ensure `app` is importable when running pytest from backend/ directly,
# even without a conftest.py.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.services.text_analyzer import analyze_text  # noqa: E402


def _signals(text: str) -> set:
    """Helper: returns the set of signal ids found in `text`."""
    return {f["signal"] for f in analyze_text(text)}


def _assert_finding_shape(finding: dict) -> None:
    assert set(finding.keys()) == {"signal", "severity", "evidence_text", "reason"}
    assert finding["severity"] in {"LOW", "MEDIUM", "HIGH"}
    assert isinstance(finding["evidence_text"], str) and finding["evidence_text"]
    assert isinstance(finding["reason"], str) and finding["reason"]


# ---------------------------------------------------------------------
# 1. OTP requests
# ---------------------------------------------------------------------

def test_otp_request_scam_detected():
    text = "Please share your OTP code with us to verify the transaction."
    findings = analyze_text(text)
    assert "otp_request" in _signals(text)
    match = next(f for f in findings if f["signal"] == "otp_request")
    _assert_finding_shape(match)
    assert match["evidence_text"] == "share your OTP"


def test_otp_mention_legitimate_not_flagged():
    text = "I got an OTP from my bank today, no big deal."
    assert "otp_request" not in _signals(text)


# ---------------------------------------------------------------------
# 2. Password requests
# ---------------------------------------------------------------------

def test_password_request_scam_detected():
    text = "Kindly send your password immediately to avoid suspension."
    assert "password_request" in _signals(text)


def test_password_mention_legitimate_not_flagged():
    text = "I forgot my password and need to reset it via the app."
    assert "password_request" not in _signals(text)


# ---------------------------------------------------------------------
# 3. PIN requests
# ---------------------------------------------------------------------

def test_pin_request_scam_detected():
    text = "Enter your PIN now to confirm the transfer."
    assert "pin_request" in _signals(text)


def test_pin_mention_legitimate_not_flagged():
    text = "My ATM PIN is private, I never share it with anyone."
    assert "pin_request" not in _signals(text)


# ---------------------------------------------------------------------
# 4. Payment requests
# ---------------------------------------------------------------------

def test_payment_request_scam_detected():
    text = "Please pay a small processing fee immediately to release your parcel."
    assert "payment_request" in _signals(text)


def test_payment_mention_legitimate_not_flagged():
    text = "I paid my electricity bill yesterday using the utility app."
    assert "payment_request" not in _signals(text)


# ---------------------------------------------------------------------
# 5. Money transfer requests
# ---------------------------------------------------------------------

def test_money_transfer_scam_detected():
    text = "Transfer money immediately using Western Union to claim your prize."
    assert "money_transfer_request" in _signals(text)


def test_money_transfer_legitimate_not_flagged():
    text = "I transferred money to my friend for rent last week."
    assert "money_transfer_request" not in _signals(text)


# ---------------------------------------------------------------------
# 6. Urgent language
# ---------------------------------------------------------------------

def test_urgent_language_scam_detected():
    text = "Act now! This offer expires within 24 hours."
    findings = analyze_text(text)
    urgent_findings = [f for f in findings if f["signal"] == "urgent_language"]
    assert len(urgent_findings) == 2  # "Act now" and "within 24 hours"


def test_urgent_language_legitimate_not_flagged():
    text = "Let's meet for coffee sometime this week, no rush."
    assert "urgent_language" not in _signals(text)


# ---------------------------------------------------------------------
# 7. Threats
# ---------------------------------------------------------------------

def test_threats_scam_detected():
    text = "Legal action will be taken if you do not comply immediately."
    assert "threats" in _signals(text)


def test_threats_legitimate_not_flagged():
    text = "Our legal team reviewed the contract yesterday."
    assert "threats" not in _signals(text)


# ---------------------------------------------------------------------
# 8. Account closure threats
# ---------------------------------------------------------------------

def test_account_closure_threat_scam_detected():
    text = "Your account will be suspended unless you verify immediately."
    assert "account_closure_threat" in _signals(text)


def test_account_closure_legitimate_not_flagged():
    text = "Your package will be delivered tomorrow between 9am and 5pm."
    assert "account_closure_threat" not in _signals(text)


# ---------------------------------------------------------------------
# 9. Prize / reward bait
# ---------------------------------------------------------------------

def test_prize_reward_bait_scam_detected():
    text = "Congratulations, you have been selected to receive a free gift!"
    assert "prize_reward_bait" in _signals(text)


def test_prize_reward_legitimate_not_flagged():
    text = "Congratulations on your promotion, well deserved!"
    assert "prize_reward_bait" not in _signals(text)


# ---------------------------------------------------------------------
# 10. Verification requests
# ---------------------------------------------------------------------

def test_verification_request_scam_detected():
    text = "Please verify your account by clicking the link below."
    assert "verification_request" in _signals(text)


def test_verification_legitimate_not_flagged():
    text = "Thanks for verifying my reservation over the phone."
    assert "verification_request" not in _signals(text)


# ---------------------------------------------------------------------
# 11. Suspicious link language
# ---------------------------------------------------------------------

def test_suspicious_link_language_scam_detected():
    text = "Click here to claim your reward now."
    assert "suspicious_link_language" in _signals(text)


def test_suspicious_link_legitimate_not_flagged():
    text = "Here is the link to our public blog: https://example.com/blog"
    assert "suspicious_link_language" not in _signals(text)


# ---------------------------------------------------------------------
# 12. Install application requests
# ---------------------------------------------------------------------

def test_install_app_request_scam_detected():
    text = "You must install this app to continue using our service."
    assert "install_app_request" in _signals(text)


def test_install_app_legitimate_not_flagged():
    text = "I downloaded a new photo editing app yesterday."
    assert "install_app_request" not in _signals(text)


# ---------------------------------------------------------------------
# 13. Personal information requests
# ---------------------------------------------------------------------

def test_personal_info_request_scam_detected():
    text = "Please provide your social security number and date of birth to proceed."
    assert "personal_info_request" in _signals(text)


def test_personal_info_legitimate_not_flagged():
    text = "My social security card is safely stored at home."
    assert "personal_info_request" not in _signals(text)


# ---------------------------------------------------------------------
# 14. Impersonation claims
# ---------------------------------------------------------------------

def test_impersonation_claim_scam_detected():
    text = "This is the IRS, you owe back taxes and must pay immediately."
    assert "impersonation_claim" in _signals(text)


def test_impersonation_legitimate_not_flagged():
    text = "This is Sarah from the marketing team, following up on your request."
    assert "impersonation_claim" not in _signals(text)


# ---------------------------------------------------------------------
# 15. Secrecy / pressure language
# ---------------------------------------------------------------------

def test_secrecy_pressure_language_scam_detected():
    text = "Do not tell anyone about this transaction, keep this confidential."
    assert "secrecy_pressure_language" in _signals(text)


def test_secrecy_pressure_legitimate_not_flagged():
    text = "Let's keep this project confidential until launch day, per the NDA."
    assert "secrecy_pressure_language" not in _signals(text)


# ---------------------------------------------------------------------
# Additional structural / behavioral tests
# ---------------------------------------------------------------------

def test_empty_text_returns_empty_list():
    assert analyze_text("") == []
    assert analyze_text("   ") == []


def test_completely_benign_message_has_no_findings():
    text = "Hi Mom, I'll call you back in about 10 minutes, just finishing lunch."
    assert analyze_text(text) == []


def test_single_keyword_alone_does_not_trigger_a_finding():
    # Bare keywords with no contextual request phrase must not fire.
    text = "otp password pin urgent verify link app"
    assert analyze_text(text) == []


def test_multi_signal_scam_message_detects_several_signals():
    text = (
        "URGENT: This is your bank. Your account will be suspended within 24 hours. "
        "Click here to verify your account and share your OTP immediately. "
        "Do not tell anyone about this message."
    )
    signals = _signals(text)
    assert "account_closure_threat" in signals
    assert "urgent_language" in signals
    assert "verification_request" in signals
    assert "suspicious_link_language" in signals
    assert "otp_request" in signals
    assert "secrecy_pressure_language" in signals
    # Every finding must still preserve valid structure and exact evidence text.
    for finding in analyze_text(text):
        _assert_finding_shape(finding)
        assert finding["evidence_text"] in text


def test_evidence_text_preserves_exact_original_casing():
    text = "PLEASE Share Your OTP Code Right Now."
    findings = analyze_text(text)
    otp_finding = next(f for f in findings if f["signal"] == "otp_request")
    assert otp_finding["evidence_text"] == "Share Your OTP"
    assert otp_finding["evidence_text"] in text


def test_finding_shape_matches_required_contract():
    text = "Please share your OTP code with us to verify the transaction."
    findings = analyze_text(text)
    assert len(findings) >= 1
    for finding in findings:
        _assert_finding_shape(finding)