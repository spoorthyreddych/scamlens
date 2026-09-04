"""
ScamLens — Deterministic URL analyzer.

INDEPENDENT ANALYSIS MODULE.

This module parses a URL into its structural components and detects
suspicious SIGNALS using deterministic, rule-based checks only. It
performs NO scoring, NO risk classification, and makes NO final
scam/not-scam decision — it only surfaces structured, evidence-backed
findings for the (later) deterministic risk engine to weigh.

CRITICAL SAFETY RULE: this module NEVER makes a network request. It
never visits, fetches, resolves DNS for, or follows redirects on the
URL it analyzes. All analysis is pure string/structural parsing.

Design rules followed here:
  - NO LLM / AI calls of any kind.
  - NO single signal is treated as proof of malice — every check is
    reported as an independent, individually-labeled finding; the
    decision about how much any one signal matters belongs to the
    (later) deterministic risk engine, not this module.
  - Findings preserve the exact substring of evidence where practical.
  - Zero dependency on FastAPI, Pydantic, or route code.

Public API:
    analyze_url(url: str) -> dict

Return shape:
    {
        "url": <original input string>,
        "components": {
            "scheme": str,
            "hostname": str,
            "registered_domain": str,
            "subdomain": str,
            "path": str,
            "query": str,
            "url_length": int,
        },
        "findings": [
            {
                "signal": str,
                "severity": "LOW"|"MEDIUM"|"HIGH",
                "evidence_text": str,
                "reason": str,
            },
            ...
        ],
    }
"""

from __future__ import annotations

import ipaddress
import re
from typing import List, Optional
from urllib.parse import urlsplit

# ---------------------------------------------------------------------
# Reference data
# ---------------------------------------------------------------------

# Common two-label public suffixes where the "registered domain" needs
# three labels (e.g. "example.co.uk", not "co.uk"). Not exhaustive —
# good enough for MVP heuristics, not a full public-suffix-list parser.
_TWO_PART_SUFFIXES = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "ltd.uk", "plc.uk",
    "co.in", "co.jp", "co.kr", "co.nz", "co.za", "co.il", "co.id", "co.th",
    "com.au", "net.au", "org.au", "com.br", "com.cn", "com.sg", "com.mx",
    "com.tw", "com.hk", "com.tr", "com.ar",
}

# Known URL shortener domains. Shorteners are not inherently malicious,
# but they hide the true destination, which is relevant evidence.
_KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "tiny.cc", "rb.gy", "s.id",
    "shorte.st", "adf.ly", "bl.ink", "lnkd.in", "soo.gd", "v.gd",
}

# Small curated set of frequently-impersonated brands and their real
# registered domain, for brand-impersonation / typosquatting checks.
# Not exhaustive — intended as an MVP heuristic, not a trademark DB.
_BRAND_DOMAINS = {
    "paypal": "paypal.com",
    "amazon": "amazon.com",
    "google": "google.com",
    "microsoft": "microsoft.com",
    "apple": "apple.com",
    "facebook": "facebook.com",
    "netflix": "netflix.com",
    "instagram": "instagram.com",
    "linkedin": "linkedin.com",
    "ebay": "ebay.com",
    "chase": "chase.com",
    "wellsfargo": "wellsfargo.com",
    "bankofamerica": "bankofamerica.com",
    "irs": "irs.gov",
    "outlook": "outlook.com",
    "whatsapp": "whatsapp.com",
}

_SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "verification", "secure", "security",
    "account", "update", "confirm", "authenticate", "banking", "password",
    "unlock", "billing",
]

_LONG_URL_THRESHOLD = 100  # characters


# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------

def _levenshtein(a: str, b: str) -> int:
    """Standard edit-distance implementation (pure Python, no deps)."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)

    prev_row = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        curr_row = [i] + [0] * len(b)
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            curr_row[j] = min(
                prev_row[j] + 1,       # deletion
                curr_row[j - 1] + 1,   # insertion
                prev_row[j - 1] + cost,  # substitution
            )
        prev_row = curr_row
    return prev_row[-1]


def _is_ip_address(hostname: str) -> bool:
    candidate = hostname
    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]
    try:
        ipaddress.ip_address(candidate)
        return True
    except ValueError:
        return False


def _split_registered_domain(hostname: str) -> tuple[str, str]:
    """
    Returns (registered_domain, subdomain) for a given hostname using a
    simple heuristic public-suffix approximation. Not a full PSL parser.
    """
    if not hostname or _is_ip_address(hostname):
        return hostname, ""

    labels = hostname.split(".")
    if len(labels) <= 2:
        return hostname, ""

    last_two = ".".join(labels[-2:])
    if last_two in _TWO_PART_SUFFIXES and len(labels) >= 3:
        registered_domain = ".".join(labels[-3:])
        subdomain = ".".join(labels[:-3])
    else:
        registered_domain = last_two
        subdomain = ".".join(labels[:-2])

    return registered_domain, subdomain


# ---------------------------------------------------------------------
# Component extraction
# ---------------------------------------------------------------------

def parse_url(url: str) -> dict:
    """
    Parse `url` into structural components WITHOUT visiting it.

    If the URL has no scheme (e.g. "example.com/login"), "http://" is
    assumed for parsing purposes only, so hostname/path can still be
    extracted; the ORIGINAL string is preserved separately for evidence.
    """
    raw = url.strip()
    parse_target = raw
    if "://" not in parse_target:
        parse_target = "http://" + parse_target

    split = urlsplit(parse_target)

    hostname = split.hostname or ""
    registered_domain, subdomain = _split_registered_domain(hostname)

    return {
        "scheme": split.scheme or "",
        "hostname": hostname,
        "registered_domain": registered_domain,
        "subdomain": subdomain,
        "path": split.path or "",
        "query": split.query or "",
        "url_length": len(raw),
        # internal use only, not part of the public contract:
        "_netloc": split.netloc or "",
    }


# ---------------------------------------------------------------------
# Signal detection
# ---------------------------------------------------------------------

def _finding(signal: str, severity: str, evidence_text: str, reason: str) -> dict:
    return {
        "signal": signal,
        "severity": severity,
        "evidence_text": evidence_text,
        "reason": reason,
    }


def _detect_http_not_https(components: dict) -> Optional[dict]:
    if components["scheme"].lower() == "http":
        return _finding(
            "http_not_https",
            "MEDIUM",
            f"{components['scheme']}://",
            "URL uses unencrypted HTTP instead of HTTPS, so any data submitted "
            "could be intercepted in transit.",
        )
    return None


def _detect_ip_address_hostname(components: dict) -> Optional[dict]:
    if components["hostname"] and _is_ip_address(components["hostname"]):
        return _finding(
            "ip_address_hostname",
            "HIGH",
            components["hostname"],
            "URL uses a raw IP address instead of a domain name, which is "
            "unusual for legitimate services and common in scam infrastructure.",
        )
    return None


def _detect_excessive_subdomains(components: dict) -> Optional[dict]:
    subdomain = components["subdomain"]
    if not subdomain:
        return None
    label_count = len([label for label in subdomain.split(".") if label])
    if label_count >= 3:
        return _finding(
            "excessive_subdomains",
            "MEDIUM",
            subdomain,
            f"URL hostname has {label_count} subdomain labels, a pattern "
            "sometimes used to bury a suspicious domain or mimic a "
            "legitimate-looking address.",
        )
    return None


def _detect_suspicious_url_encoding(url: str) -> Optional[dict]:
    pattern = re.compile(
        r"%00|%0d%0a|%25(?:25)+|(?:%[0-9a-fA-F]{2}){4,}", re.IGNORECASE
    )
    match = pattern.search(url)
    if match:
        return _finding(
            "suspicious_url_encoding",
            "MEDIUM",
            match.group(0),
            "URL contains unusual or repeated percent-encoding, a pattern "
            "sometimes used to obscure the true destination or payload.",
        )
    return None


def _detect_suspicious_characters(components: dict, url: str) -> Optional[dict]:
    hostname = components["hostname"]

    if hostname.startswith("xn--") or ".xn--" in hostname:
        return _finding(
            "suspicious_characters",
            "MEDIUM",
            hostname,
            "Hostname uses punycode (internationalized domain encoding), "
            "which can be used to visually spoof a trusted domain with "
            "look-alike characters.",
        )

    control_char_match = re.search(r"[\x00-\x1f]", url)
    if control_char_match:
        return _finding(
            "suspicious_characters",
            "HIGH",
            repr(control_char_match.group(0)),
            "URL contains control characters, which are never expected in a "
            "legitimate link.",
        )

    if hostname.count("-") >= 4:
        return _finding(
            "suspicious_characters",
            "LOW",
            hostname,
            "Hostname contains an unusually high number of hyphens, a "
            "pattern common in generated scam domains.",
        )

    return None


def _detect_at_symbol(components: dict) -> Optional[dict]:
    netloc = components["_netloc"]
    if "@" in netloc:
        return _finding(
            "at_symbol_in_url",
            "HIGH",
            netloc,
            "URL contains an '@' symbol before the hostname. Browsers treat "
            "everything before '@' as login info and connect to what comes "
            "after it — a classic technique to disguise the real destination.",
        )
    return None


def _detect_unusually_long_url(components: dict, url: str) -> Optional[dict]:
    if components["url_length"] > _LONG_URL_THRESHOLD:
        return _finding(
            "unusually_long_url",
            "LOW",
            f"{components['url_length']} characters",
            f"URL is {components['url_length']} characters long, well beyond "
            "typical link length, sometimes used to hide suspicious "
            "parameters or obscure the real destination.",
        )
    return None


def _detect_suspicious_keywords(components: dict) -> List[dict]:
    findings = []
    haystack = f"{components['hostname']}{components['path']}?{components['query']}".lower()
    found_keywords = set()
    for keyword in _SUSPICIOUS_KEYWORDS:
        if re.search(rf"\b{re.escape(keyword)}\b", haystack) and keyword not in found_keywords:
            found_keywords.add(keyword)
            findings.append(
                _finding(
                    "suspicious_keyword",
                    "LOW",
                    keyword,
                    f"URL contains the keyword '{keyword}', commonly used in "
                    "phishing links that impersonate login or account-"
                    "verification pages.",
                )
            )
    return findings


def _detect_url_shortener(components: dict) -> Optional[dict]:
    if components["registered_domain"].lower() in _KNOWN_SHORTENERS:
        return _finding(
            "url_shortener",
            "MEDIUM",
            components["registered_domain"],
            "URL uses a known link-shortening service, which hides the true "
            "destination until the link is opened.",
        )
    return None


def _detect_brand_impersonation(components: dict) -> Optional[dict]:
    hostname = components["hostname"].lower()
    registered_domain = components["registered_domain"].lower()

    for brand, official_domain in _BRAND_DOMAINS.items():
        if brand in hostname and registered_domain != official_domain:
            return _finding(
                "brand_impersonation",
                "HIGH",
                hostname,
                f"Hostname contains the brand name '{brand}' but the "
                f"registered domain is '{registered_domain}', not the "
                f"official domain '{official_domain}'. This is a common "
                "phishing impersonation pattern.",
            )
    return None


def _hostname_tokens_excluding_suffix(hostname: str) -> List[str]:
    """
    Splits hostname into meaningful word tokens for brand comparison,
    excluding the public-suffix labels (e.g. 'com', 'co.uk') so a TLD
    label is never compared against a brand name, and splitting each
    remaining label on hyphens/underscores so compound domains like
    'paypa1-secure-login.com' are compared word-by-word rather than as
    one long string.
    """
    labels = [label for label in hostname.split(".") if label]
    if not labels:
        return []

    last_two = ".".join(labels[-2:]) if len(labels) >= 2 else ""
    if last_two in _TWO_PART_SUFFIXES and len(labels) >= 2:
        meaningful_labels = labels[:-2]
    else:
        meaningful_labels = labels[:-1] if len(labels) >= 2 else labels

    tokens: List[str] = []
    for label in meaningful_labels:
        tokens.extend(part for part in re.split(r"[-_]", label) if part)
    return tokens


def _detect_typosquatting(components: dict) -> Optional[dict]:
    hostname = components["hostname"].lower()
    registered_domain = components["registered_domain"].lower()
    tokens = _hostname_tokens_excluding_suffix(hostname)

    for brand, official_domain in _BRAND_DOMAINS.items():
        if registered_domain == official_domain:
            continue  # exact legitimate match, not typosquatting

        max_allowed_distance = 1 if len(brand) <= 6 else 2

        for token in tokens:
            if token == brand:
                continue  # exact brand word present verbatim is impersonation, not a typo
            distance = _levenshtein(token, brand)
            if 0 < distance <= max_allowed_distance and abs(len(token) - len(brand)) <= 2:
                return _finding(
                    "typosquatting",
                    "HIGH",
                    hostname,
                    f"Hostname token '{token}' closely resembles the brand "
                    f"'{brand}' (official domain '{official_domain}') with "
                    f"only {distance} character difference(s) — a classic "
                    "typosquatting pattern.",
                )
    return None


# ---------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------

def analyze_url(url: str) -> dict:
    """
    Analyze `url` structurally and for suspicious signals, WITHOUT ever
    visiting, fetching, or resolving it.

    Args:
        url: Raw URL string as provided by the user.

    Returns:
        {
            "url": <original input>,
            "components": {scheme, hostname, registered_domain,
                            subdomain, path, query, url_length},
            "findings": [ {signal, severity, evidence_text, reason}, ... ],
        }
        `findings` is [] if the URL is blank or no signals were detected.
        No single finding is a verdict — combine with the deterministic
        risk engine (a later phase) to reach an overall conclusion.
    """
    raw = (url or "").strip()

    if not raw:
        return {
            "url": raw,
            "components": {
                "scheme": "",
                "hostname": "",
                "registered_domain": "",
                "subdomain": "",
                "path": "",
                "query": "",
                "url_length": 0,
            },
            "findings": [],
        }

    parsed = parse_url(raw)
    public_components = {
        "scheme": parsed["scheme"],
        "hostname": parsed["hostname"],
        "registered_domain": parsed["registered_domain"],
        "subdomain": parsed["subdomain"],
        "path": parsed["path"],
        "query": parsed["query"],
        "url_length": parsed["url_length"],
    }

    findings: List[dict] = []

    single_checks = [
        _detect_http_not_https(parsed),
        _detect_ip_address_hostname(parsed),
        _detect_excessive_subdomains(parsed),
        _detect_suspicious_url_encoding(raw),
        _detect_suspicious_characters(parsed, raw),
        _detect_at_symbol(parsed),
        _detect_unusually_long_url(parsed, raw),
        _detect_url_shortener(parsed),
        _detect_brand_impersonation(parsed),
        _detect_typosquatting(parsed),
    ]
    for finding in single_checks:
        if finding is not None:
            findings.append(finding)

    findings.extend(_detect_suspicious_keywords(parsed))

    return {
        "url": raw,
        "components": public_components,
        "findings": findings,
    }