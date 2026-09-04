"""
ScamLens — Deterministic text analyzer.

INDEPENDENT ANALYSIS MODULE.

This module detects contextual scam-indicator SIGNALS in free text
using deterministic pattern matching only. It performs NO scoring,
NO risk classification, and makes NO final scam/not-scam decision —
it only surfaces structured, evidence-backed findings. The
deterministic risk engine (a later phase) is responsible for turning
these findings into a numeric risk_score / risk_level. The AI
interpretation layer (a later phase) is responsible for turning them
into a human-facing explanation and category.

Design rules followed here:
  - NO LLM / AI calls of any kind. Pure Python `re` pattern matching.
  - NO single bare keyword is enough to raise a finding. Every pattern
    requires a contextual phrase (an action/intent verb combined with
    a sensitive noun, or a multi-word phrase), not an isolated word
    like "urgent" or "password" on its own.
  - Every finding preserves the EXACT substring of the input text that
    triggered it (original casing/spacing), never a paraphrase.
  - This module has zero dependency on FastAPI, Pydantic, or any route
    code, so it can be unit tested and reused independently.

Public API:
    analyze_text(text: str) -> list[dict]

Each returned dict has the shape:
    {
        "signal": str,               # stable machine-readable signal id
        "severity": "LOW"|"MEDIUM"|"HIGH",
        "evidence_text": str,        # exact triggering substring
        "reason": str,                # human-readable explanation
    }
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Pattern


@dataclass(frozen=True)
class SignalRule:
    signal: str
    severity: str
    reason: str
    pattern: Pattern[str]


def _compile(pattern: str) -> Pattern[str]:
    return re.compile(pattern, re.IGNORECASE)


# ---------------------------------------------------------------------
# Signal rules.
#
# Every pattern below requires a contextual phrase: a sensitive noun
# (OTP, password, PIN, ...) combined with a request/action verb
# (share, send, enter, provide, ...) within a short span of the same
# sentence-ish fragment, OR a fixed multi-word idiom (e.g. "act now",
# "you have won"). No rule fires on a single bare keyword.
# ---------------------------------------------------------------------
_SIGNAL_RULES: List[SignalRule] = [

    # ---- OTP requests -------------------------------------------------
    SignalRule(
        signal="otp_request",
        severity="HIGH",
        reason=(
            "Message asks the recipient to share, send, or enter an OTP / "
            "one-time verification code — a common account-takeover tactic. "
            "Legitimate services never ask you to share this code."
        ),
        pattern=_compile(
            r"\b(share|send|provide|give|tell (?:us|me)|enter|read out|reply with)\s+"
            r"(?:us\s+|me\s+|it\s+)?(?:with\s+)?(?:your\s+|the\s+|my\s+)?"
            r"(otp|one[- ]time password|one[- ]time code|verification code|security code)\b"
        ),
    ),

    # ---- Password requests --------------------------------------------
    SignalRule(
        signal="password_request",
        severity="HIGH",
        reason=(
            "Message asks the recipient to share, send, or enter their "
            "password or login credentials. Legitimate organizations never "
            "ask for your password."
        ),
        pattern=_compile(
            r"\b(share|send|provide|give|enter|confirm)\s+"
            r"(?:your\s+|the\s+|my\s+)?(password|login credentials|account password)\b"
        ),
    ),

    # ---- PIN requests ---------------------------------------------------
    SignalRule(
        signal="pin_request",
        severity="HIGH",
        reason=(
            "Message asks the recipient to share or enter a PIN. Sharing a "
            "banking or card PIN with anyone is a strong fraud indicator."
        ),
        pattern=_compile(
            r"\b(share|send|provide|give|enter|tell (?:us|me))\s+"
            r"(?:us\s+|me\s+)?(?:your\s+|the\s+|my\s+)?(pin|pin code|atm pin|card pin)\b"
        ),
    ),

    # ---- Payment requests -----------------------------------------------
    SignalRule(
        signal="payment_request",
        severity="MEDIUM",
        reason=(
            "Message pressures the recipient to make a payment or pay a fee "
            "to avoid a consequence or unlock something, a common advance-fee "
            "scam pattern."
        ),
        pattern=_compile(
            r"\b(pay|payment|processing fee|advance fee|small fee|release fee|"
            r"clearance fee|handling fee)\b[^.\n]{0,50}\b(immediately|now|within|"
            r"to (?:release|unlock|receive|claim|avoid)|before)\b"
        ),
    ),

    # ---- Money transfer requests ------------------------------------------
    SignalRule(
        signal="money_transfer_request",
        severity="HIGH",
        reason=(
            "Message requests an urgent money transfer or wire payment via a "
            "hard-to-reverse channel, commonly used in wire-fraud and "
            "romance/impersonation scams."
        ),
        pattern=_compile(
            r"\b(transfer|wire|send)\b[^.\n]{0,40}\b(money|funds|cash)\b[^.\n]{0,40}"
            r"\b(immediately|now|urgently|right away|today)\b"
            r"|"
            r"\b(western union|moneygram|gift cards?|bitcoin|crypto wallet)\b[^.\n]{0,40}"
            r"\b(send|purchase|buy|transfer)\b"
        ),
    ),

    # ---- Urgent language -----------------------------------------------
    SignalRule(
        signal="urgent_language",
        severity="LOW",
        reason=(
            "Message uses high-pressure urgency phrasing designed to rush "
            "the recipient into acting without verifying first."
        ),
        pattern=_compile(
            r"\b(act now|act immediately|respond immediately|urgent action required|"
            r"within (?:24|1|2|3|6|12) hours?|before it'?s too late|last chance|"
            r"final notice|immediate action is required|do this right now)\b"
        ),
    ),

    # ---- Threats ----------------------------------------------------------
    SignalRule(
        signal="threats",
        severity="HIGH",
        reason=(
            "Message threatens a negative legal or financial consequence to "
            "pressure compliance, a common scare tactic in scam messages."
        ),
        pattern=_compile(
            r"\b(legal action will be taken|you will be arrested|a warrant (?:has been|will be) issued|"
            r"failure to comply|you will face (?:legal )?consequences|"
            r"penalt(?:y|ies) will apply|you will be prosecuted)\b"
        ),
    ),

    # ---- Account closure threats -------------------------------------------
    SignalRule(
        signal="account_closure_threat",
        severity="MEDIUM",
        reason=(
            "Message threatens that an account will be closed, suspended, or "
            "locked unless the recipient takes immediate action — a common "
            "phishing pressure tactic."
        ),
        pattern=_compile(
            r"\b(your account will be|account (?:has been|will be))\b[^.\n]{0,30}"
            r"\b(closed|suspended|terminated|locked|deactivated|restricted)\b"
        ),
    ),

    # ---- Prize / reward bait -----------------------------------------------
    SignalRule(
        signal="prize_reward_bait",
        severity="MEDIUM",
        reason=(
            "Message claims the recipient has won a prize, lottery, or reward "
            "they did not enter — a classic prize-scam lure."
        ),
        pattern=_compile(
            r"\b(you have won|you'?ve won|congratulations,? you have been selected|"
            r"claim your prize|you are (?:the )?winner|lottery winner|"
            r"you are eligible for a (?:free )?reward|you have been selected to receive)\b"
        ),
    ),

    # ---- Verification requests ---------------------------------------------
    SignalRule(
        signal="verification_request",
        severity="MEDIUM",
        reason=(
            "Message asks the recipient to verify their account or confirm "
            "identity/details, often used to lead into a credential-harvesting "
            "page."
        ),
        pattern=_compile(
            r"\b(verify your account|confirm your identity|verify your identity|"
            r"verify your details|confirm your details|update your information to avoid|"
            r"re-?verify your account)\b"
        ),
    ),

    # ---- Suspicious link language --------------------------------------------
    SignalRule(
        signal="suspicious_link_language",
        severity="MEDIUM",
        reason=(
            "Message uses pressured click-through language pointing to a link, "
            "commonly paired with phishing pages."
        ),
        pattern=_compile(
            r"\b(click here|click below|click this link|click the link below|"
            r"tap here|follow this link)\b"
        ),
    ),

    # ---- Install application requests -----------------------------------------
    SignalRule(
        signal="install_app_request",
        severity="MEDIUM",
        reason=(
            "Message asks the recipient to install or download an application, "
            "sometimes used to install remote-access or credential-stealing "
            "tools."
        ),
        pattern=_compile(
            r"\b(install (?:this|the|our) app|download (?:this|the|our) app|"
            r"download (?:this|the) application|install this apk|download the apk)\b"
        ),
    ),

    # ---- Personal information requests -----------------------------------------
    SignalRule(
        signal="personal_info_request",
        severity="MEDIUM",
        reason=(
            "Message requests sensitive personal information such as an ID "
            "number, date of birth, or banking details."
        ),
        pattern=_compile(
            r"\b(provide|share|send|confirm)\s+(?:your\s+|the\s+|my\s+)?"
            r"(social security number|ssn|date of birth|bank account details|"
            r"card number|full address and (?:date of birth|id))\b"
        ),
    ),

    # ---- Impersonation claims ---------------------------------------------------
    SignalRule(
        signal="impersonation_claim",
        severity="HIGH",
        reason=(
            "Message claims to be from a specific bank, government agency, or "
            "well-known company — impersonation is a core tactic in phishing "
            "and fraud."
        ),
        pattern=_compile(
            r"\b(this is (?:the )?(?:irs|hmrc|amazon|paypal|microsoft|apple support|"
            r"your bank|the bank|social security administration|fedex|dhl|ups))\b"
            r"|"
            r"\bwe are (?:from|contacting you from) (?:the )?[a-z ]{2,30}(?:department|team|support)\b"
        ),
    ),

    # ---- Secrecy / pressure language ---------------------------------------------
    SignalRule(
        signal="secrecy_pressure_language",
        severity="HIGH",
        reason=(
            "Message asks the recipient to keep the conversation secret or not "
            "discuss it with anyone else, a tactic used to prevent victims from "
            "seeking a second opinion."
        ),
        pattern=_compile(
            r"\b(do not tell anyone|don'?t tell anyone|keep this (?:confidential|"
            r"between us|a secret)|don'?t discuss this with|this is (?:strictly )?confidential,? "
            r"do not share|between (?:us|you and me) only)\b"
        ),
    ),
]


def analyze_text(text: str) -> List[dict]:
    """
    Run all deterministic signal rules against `text` and return a list
    of structured findings.

    - No LLM is used; this is pure regex pattern matching.
    - No single bare keyword triggers a finding; every rule requires a
      contextual phrase (see _SIGNAL_RULES above).
    - `evidence_text` always preserves the exact substring (original
      casing/spacing) from `text` that triggered the finding.
    - Overlapping/duplicate matches of the same signal with identical
      evidence text are de-duplicated; distinct matches of the same
      signal (different evidence) are all kept.

    Args:
        text: Raw input text to analyze. Safe to call with empty string.

    Returns:
        List of finding dicts: {signal, severity, evidence_text, reason}.
        Empty list if no signals were detected or text is blank.
    """
    if not text or not text.strip():
        return []

    findings: List[dict] = []
    seen: set[tuple[str, str]] = set()

    for rule in _SIGNAL_RULES:
        for match in rule.pattern.finditer(text):
            evidence_text = match.group(0).strip()
            if not evidence_text:
                continue

            dedup_key = (rule.signal, evidence_text.lower())
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            findings.append(
                {
                    "signal": rule.signal,
                    "severity": rule.severity,
                    "evidence_text": evidence_text,
                    "reason": rule.reason,
                }
            )

    return findings