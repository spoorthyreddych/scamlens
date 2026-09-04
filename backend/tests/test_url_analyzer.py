"""
ScamLens — tests for app.services.url_analyzer

Run from the `backend/` directory with:
    python -m pytest tests/test_url_analyzer.py -v

Independent of FastAPI — imports and calls `analyze_url` directly.
Covers: component extraction, every required detection signal, and
legitimate URLs that must NOT trigger false positives.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.services.url_analyzer import analyze_url, parse_url  # noqa: E402


def _signals(url: str) -> set:
    return {f["signal"] for f in analyze_url(url)["findings"]}


def _assert_finding_shape(finding: dict) -> None:
    assert set(finding.keys()) == {"signal", "severity", "evidence_text", "reason"}
    assert finding["severity"] in {"LOW", "MEDIUM", "HIGH"}
    assert isinstance(finding["evidence_text"], str) and finding["evidence_text"]
    assert isinstance(finding["reason"], str) and finding["reason"]


# ---------------------------------------------------------------------
# Component extraction
# ---------------------------------------------------------------------

def test_extracts_all_required_components():
    result = analyze_url("https://accounts.google.com/o/oauth2/auth?client=1")
    components = result["components"]
    assert set(components.keys()) == {
        "scheme", "hostname", "registered_domain", "subdomain",
        "path", "query", "url_length",
    }
    assert components["scheme"] == "https"
    assert components["hostname"] == "accounts.google.com"
    assert components["registered_domain"] == "google.com"
    assert components["subdomain"] == "accounts"
    assert components["path"] == "/o/oauth2/auth"
    assert components["query"] == "client=1"
    assert components["url_length"] == len("https://accounts.google.com/o/oauth2/auth?client=1")


def test_parse_url_handles_missing_scheme():
    components = parse_url("example.com/path")
    assert components["hostname"] == "example.com"
    assert components["registered_domain"] == "example.com"


def test_empty_url_returns_empty_components_and_no_findings():
    result = analyze_url("")
    assert result["findings"] == []
    assert result["components"]["hostname"] == ""


# ---------------------------------------------------------------------
# HTTP instead of HTTPS
# ---------------------------------------------------------------------

def test_http_scheme_flagged():
    assert "http_not_https" in _signals("http://example.com/login")


def test_https_scheme_not_flagged():
    assert "http_not_https" not in _signals("https://example.com/login")


# ---------------------------------------------------------------------
# IP address hostname
# ---------------------------------------------------------------------

def test_ip_address_hostname_flagged():
    assert "ip_address_hostname" in _signals("http://192.168.1.5/login")


def test_domain_hostname_not_flagged_as_ip():
    assert "ip_address_hostname" not in _signals("https://example.com/login")


# ---------------------------------------------------------------------
# Excessive subdomains
# ---------------------------------------------------------------------

def test_excessive_subdomains_flagged():
    url = "https://secure.login.verify.account.example-bank-update.com/verify"
    assert "excessive_subdomains" in _signals(url)


def test_normal_subdomain_not_flagged():
    assert "excessive_subdomains" not in _signals("https://accounts.google.com/login")


# ---------------------------------------------------------------------
# Suspicious URL encoding
# ---------------------------------------------------------------------

def test_suspicious_url_encoding_flagged():
    url = "https://example.com/redirect?next=%2e%2e%2f%2e%2e%2fadmin"
    assert "suspicious_url_encoding" in _signals(url)


def test_normal_query_encoding_not_flagged():
    url = "https://example.com/search?q=hello%20world"
    assert "suspicious_url_encoding" not in _signals(url)


# ---------------------------------------------------------------------
# Suspicious characters
# ---------------------------------------------------------------------

def test_punycode_hostname_flagged_suspicious_characters():
    assert "suspicious_characters" in _signals("http://xn--pple-43d.com/verify")


def test_many_hyphens_flagged_suspicious_characters():
    url = "https://secure-account-login-verify-update.com/"
    assert "suspicious_characters" in _signals(url)


def test_normal_hostname_not_flagged_suspicious_characters():
    assert "suspicious_characters" not in _signals("https://my-shop.com/products")


# ---------------------------------------------------------------------
# @ symbol
# ---------------------------------------------------------------------

def test_at_symbol_flagged():
    assert "at_symbol_in_url" in _signals("https://user@evil-site.com/login")


def test_no_at_symbol_not_flagged():
    assert "at_symbol_in_url" not in _signals("https://example.com/login")


# ---------------------------------------------------------------------
# Unusually long URLs
# ---------------------------------------------------------------------

def test_unusually_long_url_flagged():
    url = "https://" + "a" * 130 + ".com/path"
    assert "unusually_long_url" in _signals(url)


def test_normal_length_url_not_flagged():
    assert "unusually_long_url" not in _signals("https://example.com/path")


# ---------------------------------------------------------------------
# Suspicious keywords
# ---------------------------------------------------------------------

def test_suspicious_keywords_flagged():
    url = "https://example.com/account/verify?redirect=security"
    findings = analyze_url(url)["findings"]
    keyword_findings = [f for f in findings if f["signal"] == "suspicious_keyword"]
    keywords_found = {f["evidence_text"] for f in keyword_findings}
    assert {"account", "verify", "security"}.issubset(keywords_found)


def test_no_suspicious_keywords_not_flagged():
    assert "suspicious_keyword" not in _signals("https://example.com/products/shoes")


# ---------------------------------------------------------------------
# URL shortener patterns
# ---------------------------------------------------------------------

def test_url_shortener_flagged():
    assert "url_shortener" in _signals("https://bit.ly/3xYzT12")


def test_non_shortener_domain_not_flagged():
    assert "url_shortener" not in _signals("https://example.com/3xYzT12")


# ---------------------------------------------------------------------
# Brand impersonation
# ---------------------------------------------------------------------

def test_brand_impersonation_flagged():
    url = "https://microsoft-secure-signin.com/office365/login"
    assert "brand_impersonation" in _signals(url)


def test_official_brand_domain_not_flagged_as_impersonation():
    assert "brand_impersonation" not in _signals("https://www.microsoft.com/office365/login")


# ---------------------------------------------------------------------
# Typosquatting
# ---------------------------------------------------------------------

def test_typosquatting_flagged_for_character_substitution():
    assert "typosquatting" in _signals("http://paypa1-secure-login.com/confirm")


def test_typosquatting_flagged_for_zero_letter_substitution():
    url = "https://amaz0n-support.security-check.com/account/verify"
    assert "typosquatting" in _signals(url)


def test_official_domain_not_flagged_as_typosquat():
    assert "typosquatting" not in _signals("https://www.paypal.com/signin")


def test_unrelated_domain_not_flagged_as_typosquat():
    assert "typosquatting" not in _signals("https://en.wikipedia.org/wiki/Phishing")


# ---------------------------------------------------------------------
# "No single signal = malicious" structural guarantee
# ---------------------------------------------------------------------

def test_module_never_returns_an_aggregate_verdict():
    """
    This module must only return components + individual findings —
    never a combined malicious/safe verdict. That decision belongs to
    the deterministic risk engine (a later phase).
    """
    result = analyze_url("http://paypa1-secure-login.com/confirm")
    assert set(result.keys()) == {"url", "components", "findings"}
    for finding in result["findings"]:
        assert "is_malicious" not in finding
        assert "risk_score" not in finding


def test_single_weak_signal_url_only_produces_that_one_finding():
    # A single suspicious keyword on an otherwise clean, legitimate,
    # HTTPS domain should not cascade into unrelated findings.
    result = analyze_url("https://example.com/account")
    signals = {f["signal"] for f in result["findings"]}
    assert signals == {"suspicious_keyword"}


# ---------------------------------------------------------------------
# Legitimate URLs — should produce no findings at all
# ---------------------------------------------------------------------

def test_clean_legitimate_url_has_no_findings():
    assert analyze_url("https://example.com/") == analyze_url("https://example.com/")
    assert analyze_url("https://example.com/")["findings"] == []


def test_wikipedia_url_has_no_findings():
    assert analyze_url("https://en.wikipedia.org/wiki/Phishing")["findings"] == []


def test_government_url_has_no_findings():
    assert analyze_url("https://www.gov.uk/apply-tax")["findings"] == []


# ---------------------------------------------------------------------
# Finding shape / evidence integrity
# ---------------------------------------------------------------------

def test_all_findings_match_required_contract():
    result = analyze_url("http://user@paypa1-secure-login.com/verify?x=%2e%2e%2f%2e%2e%2f")
    assert len(result["findings"]) >= 1
    for finding in result["findings"]:
        _assert_finding_shape(finding)


def test_url_never_visited_no_network_call(monkeypatch):
    """
    Guardrail test: analyze_url must not attempt any network I/O.
    We patch socket.create_connection to raise if ever called, then
    run analysis on a suspicious URL and confirm no exception occurs.
    """
    import socket

    def _blow_up(*args, **kwargs):
        raise AssertionError("analyze_url attempted a network connection")

    monkeypatch.setattr(socket, "create_connection", _blow_up)
    result = analyze_url("http://paypa1-secure-login.com/confirm")
    assert result["findings"]  # still analyzed successfully, no network needed