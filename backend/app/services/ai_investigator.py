"""
ScamLens — AI Investigator Service.

This module provides AI-powered explanation layer using Featherless AI.
It translates evidence signals and deterministic risk scores into human-readable explanations.

IMPORTANT SAFETY RULES FOLLOWED HERE:
  - The deterministic risk engine determines all risk scores and levels.
  - Featherless AI MUST NOT calculate or modify risk scores.
  - Featherless AI MUST NOT describe risk scores as "probabilities" or "chances".
  - Featherless AI MUST NOT claim something is "definitely a scam".
  - Featherless AI MUST NOT invent evidence or signals not supplied by the pipeline.
  - If API key is missing, API fails, or JSON is invalid, a safe fallback response is returned.

Public API:
    investigate_with_ai(
        original_text: str,
        evidence: Any,
        risk_result: Dict[str, Any],
        url_findings: Optional[Any] = None
    ) -> Dict[str, Any]
"""

import json
import os
from typing import Any, Dict, List, Optional

try:
    from openai import OpenAI
except ImportError:
    OpenAI = None  # Handled safely if openai package is not installed


# Fallback model to use if FEATHERLESS_MODEL environment variable is not set
DEFAULT_MODEL = "meta-llama/Meta-Llama-3.1-8B-Instruct"

# Base URL for Featherless AI API
FEATHERLESS_BASE_URL = "https://api.featherless.ai/v1"


def _get_fallback_response(
    original_text: str,
    evidence: Any,
    risk_result: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Generate a safe fallback dictionary response when Featherless AI is unavailable,
    unconfigured, or fails to return valid JSON.
    """
    risk_level = "UNKNOWN"
    risk_score = 0
    detected_signals = []

    if isinstance(risk_result, dict):
        risk_level = str(risk_result.get("risk_level", "UNKNOWN")).upper()
        risk_score = risk_result.get("risk_score", 0)
        detected_signals = risk_result.get("detected_signals", [])

    # Extract detected signal IDs if not found directly in risk_result
    if not detected_signals:
        if isinstance(evidence, list):
            for item in evidence:
                if isinstance(item, dict):
                    sig_id = item.get("id") or item.get("signal")
                    if sig_id:
                        detected_signals.append(str(sig_id))
                elif isinstance(item, str):
                    detected_signals.append(item)

    evidence_explanations = [
        {
            "signal_id": str(sig),
            "explanation": f"Signal '{sig}' was detected during pipeline analysis."
        }
        for sig in detected_signals
    ]

    return {
        "summary": f"Deterministic analysis assigned a {risk_level} risk score of {risk_score}/100.",
        "why_suspicious": [
            f"The message contains risk indicators corresponding to a {risk_level} threat level."
        ] if risk_level not in ("LOW", "UNKNOWN") else ["No immediate high-risk threat indicators were found."],
        "evidence_explanation": evidence_explanations,
        "recommended_actions": [
            "Do not share OTPs, passwords, or personal credentials.",
            "Verify the identity of the sender through official independent channels.",
            "Avoid clicking on unverified links or downloading unexpected attachments."
        ],
        "user_safety_warning": "Treat unsolicited messages requesting immediate action or credentials with extreme caution."
    }


def _clean_json_text(text: str) -> str:
    """
    Clean markdown code block wrappers (e.g. ```json ... ```) from LLM output.
    """
    text = text.strip()
    if text.startswith("```json"):
        text = text[7:]
    elif text.startswith("```"):
        text = text[3:]
    
    if text.endswith("```"):
        text = text[:-3]
        
    return text.strip()


def investigate_with_ai(
    original_text: str,
    evidence: Any,
    risk_result: Dict[str, Any],
    url_findings: Optional[Any] = None
) -> Dict[str, Any]:
    """
    Use Featherless AI to generate a human-facing explanation of existing evidence.

    Args:
        original_text: The original user input message.
        evidence: Evidence signals collected by evidence_builder.
        risk_result: Deterministic risk output from risk_engine.
        url_findings: Optional URL analyzer results.

    Returns:
        Structured Python dictionary matching the required JSON schema.
    """
    # 1. Safely check for API key in environment
    api_key = os.getenv("FEATHERLESS_API_KEY")
    if not api_key or not api_key.strip() or OpenAI is None:
        return _get_fallback_response(original_text, evidence, risk_result)

    model_name = os.getenv("FEATHERLESS_MODEL", DEFAULT_MODEL)

    # 2. Extract deterministic risk details safely
    risk_score = 0
    risk_level = "UNKNOWN"
    detected_signals = []

    if isinstance(risk_result, dict):
        risk_score = risk_result.get("risk_score", 0)
        risk_level = risk_result.get("risk_level", "UNKNOWN")
        detected_signals = risk_result.get("detected_signals", [])

    # Format evidence context string for prompt
    evidence_context = json.dumps(evidence, indent=2) if evidence else "[]"
    url_context = json.dumps(url_findings, indent=2) if url_findings else "None"

    # 3. Construct system prompt with strict safety instructions
    system_prompt = (
        "You are an AI security investigator for ScamLens. Your job is ONLY to explain existing "
        "evidence and risk analysis to the user in simple, objective language.\n\n"
        "STRICT SAFETY RULES YOU MUST FOLLOW AT ALL TIMES:\n"
        "1. Do NOT calculate, recalculate, or modify the risk score or risk level. "
        "The deterministic system has already determined the risk.\n"
        "2. Do NOT refer to the risk score as a 'probability', 'chance', or 'percentage likelihood'. "
        "It is a deterministic score.\n"
        "3. Do NOT claim anything is 'definitely a scam' or '100% fake'. Use terms like 'suspicious', "
        "'potential scam', or 'high-risk indicator'.\n"
        "4. Do NOT invent extra evidence, signals, or facts not provided in the inputs.\n"
        "5. Explain ONLY the provided evidence signals and text context.\n"
        "6. Output MUST be STRICT JSON matching the required schema with no extra commentary.\n"
    )

    # 4. Construct user prompt with clear data inputs
    user_prompt = f"""
Input Context:
- User Original Message: {json.dumps(original_text)}
- Deterministic Risk Score: {risk_score} / 100
- Deterministic Risk Level: {risk_level}
- Detected Signal IDs: {json.dumps(detected_signals)}
- Aggregated Evidence Signals: {evidence_context}
- URL Findings: {url_context}

Respond ONLY in strict JSON format with the following exact keys:
{{
    "summary": "short investigation summary",
    "why_suspicious": [
        "reason 1",
        "reason 2"
    ],
    "evidence_explanation": [
        {{
            "signal_id": "signal id",
            "explanation": "human readable explanation"
        }}
    ],
    "recommended_actions": [
        "action 1",
        "action 2"
    ],
    "user_safety_warning": "short warning"
}}
"""

    try:
        # 5. Initialize OpenAI client for Featherless AI
        client = OpenAI(
            base_url=FEATHERLESS_BASE_URL,
            api_key=api_key
        )

        # 6. Make request to Featherless API
        response = client.chat.completions.create(
            model=model_name,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            temperature=0.2,
            max_tokens=1000
        )

        # 7. Extract message content safely
        if not response.choices or not response.choices[0].message:
            return _get_fallback_response(original_text, evidence, risk_result)

        raw_content = response.choices[0].message.content or ""
        cleaned_json = _clean_json_text(raw_content)

        # 8. Parse JSON response
        parsed_data = json.loads(cleaned_json)

        # 9. Verify required keys exist
        required_keys = [
            "summary",
            "why_suspicious",
            "evidence_explanation",
            "recommended_actions",
            "user_safety_warning"
        ]

        if not isinstance(parsed_data, dict) or not all(k in parsed_data for k in required_keys):
            return _get_fallback_response(original_text, evidence, risk_result)

        return parsed_data

    except Exception:
        # If any network error, API failure, or JSON decode error occurs, return safe fallback
        return _get_fallback_response(original_text, evidence, risk_result)
