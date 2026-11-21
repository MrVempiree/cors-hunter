"""Detection-logic tests for cors-hunter. All HTTP is mocked."""

import pytest

from cors_hunter import scanner
from cors_hunter.scanner import Response

URL = "https://api.example.com/data"


def make_fetch(acao=None, acac=None, acah=None, status=200):
    """Build a fake fetch that answers based on the request's Origin."""
    def _fetch(url, headers, method):
        origin = headers.get("Origin", "")
        resp_headers = {}
        if callable(acao):
            value = acao(origin)
        else:
            value = acao
        if value is not None:
            resp_headers["Access-Control-Allow-Origin"] = value
        if acac is not None:
            resp_headers["Access-Control-Allow-Credentials"] = acac
        if acah is not None:
            resp_headers["Access-Control-Allow-Headers"] = acah
        return Response(status=status, headers=resp_headers, body="{}")
    return _fetch


def reflect(origin):
    return origin


# --- reflected origin -------------------------------------------------------

def test_reflected_origin_with_credentials_is_critical():
    finding = scanner.check_reflected_origin(URL, make_fetch(reflect, "true"))
    assert finding is not None
    assert finding.severity == "critical"
    assert finding.evidence["request_origin"] == scanner.ATTACKER_ORIGIN


def test_reflected_origin_without_credentials_is_high():
    finding = scanner.check_reflected_origin(URL, make_fetch(reflect, "false"))
    assert finding is not None
    assert finding.severity == "high"


def test_no_reflection_no_finding():
    fetch = make_fetch(lambda origin: "https://app.example.com", "true")
    assert scanner.check_reflected_origin(URL, fetch) is None


def test_missing_acao_header_no_finding():
    assert scanner.check_reflected_origin(URL, make_fetch(None)) is None


# --- null origin ------------------------------------------------------------

def test_null_origin_with_credentials_is_high():
    fetch = make_fetch(lambda o: "null" if o == "null" else None, "true")
    finding = scanner.check_null_origin(URL, fetch)
    assert finding is not None
    assert finding.severity == "high"


def test_null_origin_without_credentials_is_medium():
    fetch = make_fetch(lambda o: "null" if o == "null" else None, None)
    finding = scanner.check_null_origin(URL, fetch)
    assert finding is not None
    assert finding.severity == "medium"


def test_null_origin_not_trusted():
    fetch = make_fetch(lambda o: "https://app.example.com", "true")
    assert scanner.check_null_origin(URL, fetch) is None


# --- wildcard ---------------------------------------------------------------

def test_wildcard_with_credentials_is_high():
    finding = scanner.check_wildcard(URL, make_fetch("*", "true"))
    assert finding is not None
    assert finding.severity == "high"


def test_wildcard_without_credentials_is_low():
    finding = scanner.check_wildcard(URL, make_fetch("*", None))
    assert finding is not None
    assert finding.severity == "low"


def test_specific_origin_is_not_wildcard():
    fetch = make_fetch("https://app.example.com", "true")
    assert scanner.check_wildcard(URL, fetch) is None


# --- subdomain trust --------------------------------------------------------

def test_subdomain_trust_detected():
    fetch = make_fetch(lambda o: o if o.endswith(".example.com") else None,
                       "true")
    finding = scanner.check_subdomain_trust(URL, fetch)
    assert finding is not None
    assert finding.check == "subdomain-trust"
    assert finding.severity == "high"


def test_subdomain_not_trusted_when_exact_allowlist():
    fetch = make_fetch(lambda o: "https://app.example.com", "true")
    assert scanner.check_subdomain_trust(URL, fetch) is None


# --- lookalike origins ------------------------------------------------------

def test_lookalike_suffix_domain_trusted():
    def policy(origin):
        # buggy startswith("https://api.example.com") style check
        if origin.startswith("https://api.example.com"):
            return origin
        return None
    finding = scanner.check_lookalike_origins(URL, make_fetch(policy, "true"))
    assert finding is not None
    assert finding.check == "lookalike-origin"


def test_lookalike_domains_rejected_by_strict_server():
    fetch = make_fetch(lambda o: "https://api.example.com", "true")
    assert scanner.check_lookalike_origins(URL, fetch) is None


# --- preflight ---------------------------------------------------------------

def test_preflight_reflection_detected():
    def _fetch(url, headers, method):
        if method == "OPTIONS":
            return Response(status=204, headers={
                "Access-Control-Allow-Origin": headers.get("Origin", ""),
                "Access-Control-Allow-Headers":
                    headers.get("Access-Control-Request-Headers", ""),
                "Access-Control-Allow-Credentials": "true",
            })
        return Response(status=200, headers={})
    finding = scanner.check_preflight(URL, _fetch)
    assert finding is not None
    assert finding.severity == "high"


def test_preflight_strict_server_no_finding():
    def _fetch(url, headers, method):
        return Response(status=204, headers={
            "Access-Control-Allow-Origin": "https://app.example.com",
            "Access-Control-Allow-Headers": "Content-Type",
        })
    assert scanner.check_preflight(URL, _fetch) is None


# --- aggregation --------------------------------------------------------------

def test_scan_url_collects_and_sorts_findings():
    fetch = make_fetch(reflect, "true",
                       acah="X-Attacker-Header, Authorization")
    findings = scanner.scan_url(URL, fetch)
    checks = {f.check for f in findings}
    assert "reflected-origin" in checks
    assert "preflight-reflection" in checks
    assert findings[0].severity == "critical"  # worst first


def test_scan_url_clean_server_returns_empty():
    fetch = make_fetch(lambda o: "https://app.example.com", "true")
    assert scanner.scan_url(URL, fetch) == []


def test_scan_urls_multiple_targets():
    fetch = make_fetch(reflect, "true")
    findings = scanner.scan_urls([URL, "https://api2.example.com/x"], fetch)
    assert len(findings) >= 2
    assert {f.url for f in findings} == {URL, "https://api2.example.com/x"}


def test_findings_always_have_remediation():
    fetch = make_fetch(reflect, "true")
    for finding in scanner.scan_url(URL, fetch):
        assert finding.remediation
        assert finding.detail
        assert finding.evidence


def test_response_header_lookup_is_case_insensitive():
    resp = Response(status=200,
                    headers={"access-control-allow-origin": "*"})
    assert resp.header("Access-Control-Allow-Origin") == "*"
    assert resp.header("X-Missing") is None
