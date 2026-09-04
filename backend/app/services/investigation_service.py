"""
ScamLens — Central Investigation Service Orchestrator.

This service orchestrates the complete end-to-end scam detection pipeline:
1. Input validation
2. Text analysis (text_analyzer.py)
3. URL extraction & analysis (url_analyzer.py)
4. Deterministic evidence aggregation (evidence_builder.py)
5. Deterministic risk calculation (risk_engine.py)
6. AI evidence explanation (ai_investigator.py)
7. Consolidated result formatting

IMPORTANT PIPELINE RULES:
- Deterministic risk engine calculates all risk scores and levels.
- AI investigator only explains existing evidence and never alters risk scores.
- Defensive error handling ensures failure in one module does not break the pipeline.

Public API:
    investigate(input_text: str) -> dict
"""

import re
from typing import Any, Dict, List

from app.services.text_analyzer import analyze_text
from app.services.url_analyzer import analyze_url
from app.services.evidence_builder import build_evidence
from app.services.risk_engine import calculate_risk
from app.services.ai_investigator import investigate_with_ai


def _extract_urls(text: str) -> List[str]:
    """
    Extract unique URLs starting with http://, https://, or www. using Python standard regex.
    Deduplicates URLs while preserving appearance order.
    """
    if not text or not isinstance(text, str):
        return []

    # Match URLs starting with http://, https://, or www.
    url_pattern = re.compile(r'\b(?:https?://|www\.)[^\s<>"\'\]\}]+', re.IGNORECASE)
    matches = url_pattern.findall(text)

    seen = set()
    unique_urls = []

    for match in matches:
        # Clean trailing punctuation from prose
        cleaned = match.rstrip(".,;!?:)'\"")
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            unique_urls.append(cleaned)

    return unique_urls


def investigate(input_text: str) -> Dict[str, Any]:
    """
    Main orchestration entry point for ScamLens investigation.

    Args:
        input_text: The user-submitted text string to analyze.

    Returns:
        Clean, structured dictionary containing detection findings,
        deterministic risk score, and AI explanations.
    """
    # =========================================================================
    # STEP 1: Validate input_text
    # =========================================================================
    if not input_text or not isinstance(input_text, str) or not input_text.strip():
        return {
            "status": "error",
            "message": "Invalid or empty input text.",
            "input_type": "text",
            "input_text": input_text if isinstance(input_text, str) else "",
            "urls_detected": [],
            "evidence": [],
            "total_signals": 0,
            "risk_score": 0,
            "risk_level": "LOW",
            "risk_breakdown": [],
            "ai_investigation": {
                "summary": "No input provided for investigation.",
                "why_suspicious": [],
                "evidence_explanation": [],
                "recommended_actions": ["Please provide valid message text to analyze."],
                "user_safety_warning": "No text analyzed."
            }
        }

    clean_text = input_text.strip()

    # =========================================================================
    # STEP 2: Run text_analyzer
    # =========================================================================
    text_findings = []
    try:
        text_findings = analyze_text(clean_text)
    except Exception as e:
        # Fall back gracefully to empty list if text analysis fails
        text_findings = []

    # =========================================================================
    # STEP 3: Extract URLs from input text
    # =========================================================================
    urls_detected = _extract_urls(clean_text)

    # =========================================================================
    # STEP 4: Run url_analyzer for every extracted URL
    # =========================================================================
    url_findings = []
    for url in urls_detected:
        try:
            # Ensure URL has scheme for accurate structural analysis
            url_to_analyze = url
            if url.lower().startswith("www."):
                url_to_analyze = "https://" + url

            result = analyze_url(url_to_analyze)
            if isinstance(result, dict):
                url_findings.append(result)
        except Exception:
            # Continue safely if one URL analysis fails
            continue

    # =========================================================================
    # STEP 5: Build aggregated evidence signals
    # =========================================================================
    evidence = {"signals": [], "total_signals": 0, "sources_used": []}
    try:
        evidence = build_evidence(
            text=text_findings,
            url=url_findings
        )
    except Exception:
        # Fallback to simple signal list if evidence builder encounters issue
        evidence = {
            "signals": text_findings,
            "total_signals": len(text_findings),
            "sources_used": ["text"] if text_findings else []
        }

    signals = evidence.get("signals", [])
    total_signals = evidence.get("total_signals", len(signals))

    # =========================================================================
    # STEP 6: Calculate risk using deterministic risk engine
    # =========================================================================
    risk_result = {
        "risk_score": 0,
        "risk_level": "LOW",
        "score_breakdown": [],
        "detected_signals": []
    }
    try:
        risk_result = calculate_risk(signals)
    except Exception:
        # Defensive fallback for risk calculation
        risk_result = {
            "risk_score": 0,
            "risk_level": "LOW",
            "score_breakdown": [],
            "detected_signals": [s.get("id", "") for s in signals if isinstance(s, dict)]
        }

    # =========================================================================
    # STEP 7: Call Featherless AI investigator to generate evidence explanations
    # =========================================================================
    ai_investigation = {}
    try:
        ai_investigation = investigate_with_ai(
            original_text=clean_text,
            evidence=signals,
            risk_result=risk_result,
            url_findings=url_findings
        )
    except Exception:
        ai_investigation = {
            "summary": f"Deterministic risk assessment: {risk_result.get('risk_level', 'LOW')} ({risk_result.get('risk_score', 0)}/100).",
            "why_suspicious": ["Analysis detected potential threat indicators."],
            "evidence_explanation": [],
            "recommended_actions": ["Do not share sensitive credentials or click suspicious links."],
            "user_safety_warning": "Exercise caution with unsolicited messages."
        }

    # =========================================================================
    # STEP 8: Return clean final result dictionary
    # =========================================================================
    return {
        "status": "success",
        "input_type": "text",
        "input_text": clean_text,
        "urls_detected": urls_detected,
        "evidence": signals,
        "total_signals": total_signals,
        "risk_score": risk_result.get("risk_score", 0),
        "risk_level": risk_result.get("risk_level", "LOW"),
        "risk_breakdown": risk_result.get("score_breakdown", []),
        "ai_investigation": ai_investigation
    }
