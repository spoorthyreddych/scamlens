"""
ScamLens — Deterministic Evidence Builder.

PHASE 8: EVIDENCE BUILDER.

This module aggregates, normalizes, and deduplicates signals from multiple
independent analyzer outputs (e.g., text analyzer, URL analyzer, OCR analyzer).

Design & Safety Rules:
  - NO LLM / AI calls. Pure deterministic Python logic.
  - NO risk scoring here — risk calculation belongs strictly to risk_engine.py.
  - Deduplicates signals by signal ID while preserving provenance (source,
    sources, category, description, severity, weight).
  - Handles missing, malformed, or unexpected analyzer inputs safely.
  - Outputs a structured dictionary containing:
        {
            "signals": [...],
            "total_signals": int,
            "sources_used": [...]
        }
    fully compatible with risk_engine.calculate_risk().

Public API:
    build_evidence(*args, **kwargs) -> Dict[str, Any]
    aggregate_signals(*args, **kwargs) -> Dict[str, Any]  # Alias for build_evidence
"""

from typing import Any, Dict, List, Optional, Set

# Priority ranking for severities when deduplicating signals
SEVERITY_ORDER = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def _normalize_severity(severity: Any) -> str:
    """Normalize severity value to uppercase string ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')."""
    if not severity:
        return "LOW"

    sev_str = str(severity).strip().upper()
    if sev_str in SEVERITY_ORDER:
        return sev_str

    if sev_str.startswith("CRIT"):
        return "CRITICAL"
    if sev_str.startswith("HIGH"):
        return "HIGH"
    if sev_str.startswith("MED"):
        return "MEDIUM"

    return "LOW"


def _normalize_weight(weight: Any) -> float:
    """Safely parse weight into a non-negative float."""
    if weight is None:
        return 0.0
    try:
        val = float(weight)
        return max(0.0, val)
    except (TypeError, ValueError):
        return 0.0


def _extract_signal_id(item: Dict[str, Any]) -> Optional[str]:
    """Extract and normalize a signal ID from a dictionary item."""
    if not isinstance(item, dict):
        return None

    val = (
        item.get("id")
        or item.get("signal")
        or item.get("name")
        or item.get("type")
    )
    if val is None:
        return None

    cleaned = str(val).strip().upper()
    return cleaned if cleaned else None


def _get_container_source_hint(container: Any) -> Optional[str]:
    """Infer source from analyzer response container object."""
    if not isinstance(container, dict):
        return None
    if "url" in container or "components" in container:
        return "url"
    if "ocr_text" in container or "ocr_confidence" in container:
        return "ocr"
    if "text" in container or "message" in container:
        return "text"
    source_val = container.get("source") or container.get("analyzer")
    if source_val and isinstance(source_val, str) and source_val.strip():
        return source_val.strip().lower()
    return None


def _infer_source(
    source_hint: Optional[str],
    item: Dict[str, Any],
    container_hint: Optional[str] = None,
) -> str:
    """Determine the source string for a signal item."""
    if isinstance(item, dict):
        item_source = item.get("source") or item.get("analyzer")
        if item_source and isinstance(item_source, str) and item_source.strip():
            return item_source.strip().lower()

    if source_hint and isinstance(source_hint, str) and source_hint.strip():
        hint = source_hint.strip().lower()
        for suffix in [
            "_analyzer",
            "_analysis",
            "_results",
            "_output",
            "_data",
            "_findings",
        ]:
            if hint.endswith(suffix):
                hint = hint[: -len(suffix)]
        return hint

    if container_hint:
        return container_hint

    if isinstance(item, dict):
        item_cat = item.get("category")
        if item_cat and isinstance(item_cat, str) and item_cat.strip():
            return item_cat.strip().lower()

    return "unknown"


def _extract_signal_items(data: Any) -> List[Dict[str, Any]]:
    """Extract a list of raw signal dicts from an arbitrary analyzer output data object."""
    if data is None:
        return []

    if isinstance(data, list):
        items = []
        for elem in data:
            if isinstance(elem, dict):
                items.extend(_extract_signal_items(elem))
        return items

    if isinstance(data, dict):
        # Check if data is itself a single signal dict
        signal_id = _extract_signal_id(data)
        if signal_id is not None and (
            "severity" in data
            or "reason" in data
            or "description" in data
            or "weight" in data
        ):
            return [data]

        # Check container keys
        for key in ["signals", "findings", "detected_signals", "evidence", "results"]:
            container = data.get(key)
            if isinstance(container, list):
                extracted = []
                for item in container:
                    if isinstance(item, dict):
                        extracted.append(item)
                return extracted

    return []


def build_evidence(*args: Any, **kwargs: Any) -> Dict[str, Any]:
    """
    Aggregate signals from multiple analyzer outputs into a normalized evidence dictionary.

    Args:
        *args: Analyzer outputs passed positionally (lists of signal dicts, analyzer response dicts, etc.)
        **kwargs: Analyzer outputs passed by keyword (e.g., text_analysis=..., url_analysis=...)

    Returns:
        Dict containing:
            "signals": List of aggregated and deduplicated signal dicts
            "total_signals": int count of unique signals
            "sources_used": List of unique sources that contributed signals
    """
    data_sources: List[tuple[Any, Optional[str]]] = []

    # 1. Process kwargs (named analyzers e.g., text_analyzer=..., url_results=...)
    for kw_name, kw_val in kwargs.items():
        data_sources.append((kw_val, kw_name))

    # 2. Process args
    for arg in args:
        if isinstance(arg, dict):
            # Check if arg is a dictionary wrapper of multiple analyzer results (e.g. {"text": ..., "url": ...})
            is_analyzer_dict_wrapper = (
                _extract_signal_id(arg) is None
                and not any(
                    k in arg
                    for k in [
                        "signals",
                        "findings",
                        "detected_signals",
                        "evidence",
                    ]
                )
            )
            if is_analyzer_dict_wrapper:
                for k, v in arg.items():
                    if isinstance(k, str):
                        data_sources.append((v, k))
                continue

        if isinstance(arg, list) and len(args) == 1 and not kwargs:
            # Check if single list passed contains analyzer outputs
            has_nested_structures = any(
                (
                    isinstance(elem, dict)
                    and any(
                        k in elem
                        for k in [
                            "signals",
                            "findings",
                            "detected_signals",
                            "evidence",
                        ]
                    )
                )
                or isinstance(elem, list)
                for elem in arg
            )
            if has_nested_structures:
                for elem in arg:
                    data_sources.append((elem, None))
                continue

        data_sources.append((arg, None))

    aggregated: Dict[str, Dict[str, Any]] = {}
    all_sources: Set[str] = set()

    for data, source_hint in data_sources:
        if data is None:
            continue

        container_hint = _get_container_source_hint(data)
        signal_items = _extract_signal_items(data)

        for item in signal_items:
            if not isinstance(item, dict):
                continue

            signal_id = _extract_signal_id(item)
            if not signal_id:
                continue

            source = _infer_source(source_hint, item, container_hint)
            category = item.get("category") or item.get("risk_category") or source
            category_str = str(category).strip().lower() if category else source

            description = (
                item.get("description")
                or item.get("reason")
                or item.get("message")
                or item.get("evidence_text")
                or f"Signal {signal_id} detected"
            )
            description_str = str(description).strip()

            severity_str = _normalize_severity(item.get("severity"))
            weight_val = _normalize_weight(item.get("weight"))
            evidence_text = item.get("evidence_text")
            risk_category = item.get("risk_category")

            if source != "unknown":
                all_sources.add(source)

            if signal_id not in aggregated:
                signal_entry = {
                    "id": signal_id,
                    "signal": signal_id,
                    "source": source,
                    "sources": [source] if source != "unknown" else [],
                    "category": category_str,
                    "description": description_str,
                    "reason": description_str,
                    "severity": severity_str,
                    "weight": weight_val,
                }
                if evidence_text:
                    signal_entry["evidence_text"] = str(evidence_text)
                if risk_category:
                    signal_entry["risk_category"] = str(risk_category)

                aggregated[signal_id] = signal_entry
            else:
                existing = aggregated[signal_id]

                # Preserve all sources that detected this signal
                if source != "unknown" and source not in existing["sources"]:
                    existing["sources"].append(source)
                    existing["source"] = ", ".join(existing["sources"])

                # Keep highest severity
                if SEVERITY_ORDER.get(severity_str, 1) > SEVERITY_ORDER.get(
                    existing["severity"], 1
                ):
                    existing["severity"] = severity_str

                # Keep maximum weight
                if weight_val > existing["weight"]:
                    existing["weight"] = weight_val

                # Preserve longer / clearer description if available
                if description_str and (
                    not existing["description"]
                    or len(description_str) > len(existing["description"])
                ):
                    existing["description"] = description_str
                    existing["reason"] = description_str

                # Retain evidence_text if newly available
                if evidence_text and not existing.get("evidence_text"):
                    existing["evidence_text"] = str(evidence_text)

                # Retain risk_category if newly available
                if risk_category and not existing.get("risk_category"):
                    existing["risk_category"] = str(risk_category)

    sources_used = sorted(list(all_sources))
    signals_list = list(aggregated.values())

    return {
        "signals": signals_list,
        "total_signals": len(signals_list),
        "sources_used": sources_used,
    }


# Public alias for build_evidence
aggregate_signals = build_evidence
