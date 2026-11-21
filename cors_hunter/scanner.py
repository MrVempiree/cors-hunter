"""Core CORS misconfiguration detection logic.

Every check sends a crafted ``Origin`` (or preflight) request to the target
and inspects the ``Access-Control-Allow-Origin`` /
``Access-Control-Allow-Credentials`` response headers. The HTTP layer is a
single injectable ``fetch`` callable so the whole engine can be unit-tested
with mocked responses — no live network is ever needed in tests.
"""

from __future__ import annotations

import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional
from urllib.parse import urlparse

ATTACKER_ORIGIN = "https://evil.attacker.example"
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class Response:
    """Minimal HTTP response used by the scanner (headers case-insensitive)."""

    status: int
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""

    def header(self, name: str) -> Optional[str]:
        for key, value in self.headers.items():
            if key.lower() == name.lower():
                return value
        return None


# A fetch callable: (url, headers, method) -> Response
FetchFn = Callable[[str, Dict[str, str], str], Response]


def fetch(url: str, headers: Optional[Dict[str, str]] = None,
          method: str = "GET", timeout: int = 10) -> Response:
    """Default HTTP implementation built on urllib (no third-party deps)."""
    req = urllib.request.Request(url, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(4096).decode("utf-8", errors="replace")
            return Response(status=resp.status,
                            headers=dict(resp.headers.items()), body=body)
    except urllib.error.HTTPError as exc:  # server answered with an error code
        body = exc.read(4096).decode("utf-8", errors="replace") if exc.fp else ""
        hdrs = dict(exc.headers.items()) if exc.headers else {}
        return Response(status=exc.code, headers=hdrs, body=body)
    except Exception:  # unreachable host, TLS error, timeout, ...
        return Response(status=0, headers={}, body="")


@dataclass
class Finding:
    url: str
    check: str
    severity: str
    title: str
    detail: str
    evidence: Dict[str, str]
    remediation: str

    def to_dict(self) -> Dict[str, object]:
        return {
            "url": self.url,
            "check": self.check,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "evidence": self.evidence,
            "remediation": self.remediation,
        }


def _acao(resp: Response) -> Optional[str]:
    value = resp.header("Access-Control-Allow-Origin")
    return value.strip() if value else None


def _credentials_allowed(resp: Response) -> bool:
    value = resp.header("Access-Control-Allow-Credentials")
    return bool(value) and value.strip().lower() == "true"


def _host(url: str) -> str:
    return urlparse(url).hostname or ""


GENERIC_REMEDIATION = (
    "Replace dynamic Origin reflection with a strict server-side allowlist of "
    "trusted origins. Never combine a reflected/wildcard "
    "Access-Control-Allow-Origin with Access-Control-Allow-Credentials: true."
)


def check_reflected_origin(url: str, fetch_fn: FetchFn) -> Optional[Finding]:
    """Any Origin is reflected back — with credentials this is critical."""
    resp = fetch_fn(url, {"Origin": ATTACKER_ORIGIN}, "GET")
    acao = _acao(resp)
    if acao != ATTACKER_ORIGIN:
        return None
    creds = _credentials_allowed(resp)
    severity = "critical" if creds else "high"
    detail = (
        "The server reflects an arbitrary Origin header in "
        "Access-Control-Allow-Origin"
        + (" and allows credentials, so any website can read authenticated "
           "responses from a victim's browser." if creds else
           ", letting any website read responses cross-origin.")
    )
    return Finding(
        url=url, check="reflected-origin", severity=severity,
        title="Arbitrary Origin reflected",
        detail=detail,
        evidence={"request_origin": ATTACKER_ORIGIN,
                  "access_control_allow_origin": acao,
                  "access_control_allow_credentials": str(creds).lower()},
        remediation=GENERIC_REMEDIATION,
    )


def check_null_origin(url: str, fetch_fn: FetchFn) -> Optional[Finding]:
    """Origin: null is trusted — exploitable from sandboxed iframes/redirects."""
    resp = fetch_fn(url, {"Origin": "null"}, "GET")
    acao = _acao(resp)
    if acao != "null":
        return None
    creds = _credentials_allowed(resp)
    severity = "high" if creds else "medium"
    return Finding(
        url=url, check="null-origin", severity=severity,
        title="Null origin trusted",
        detail=(
            "The server returns Access-Control-Allow-Origin: null"
            + (" with credentials allowed. " if creds else ". ")
            + "Attackers can obtain a null origin from a sandboxed iframe or "
              "a redirect and use it to read cross-origin responses."),
        evidence={"request_origin": "null",
                  "access_control_allow_origin": acao,
                  "access_control_allow_credentials": str(creds).lower()},
        remediation=(
            "Never allowlist the null origin. Treat it like any other "
            "untrusted origin and reject it unless there is a documented, "
            "narrow business need."),
    )


def check_wildcard(url: str, fetch_fn: FetchFn) -> Optional[Finding]:
    """Wildcard ACAO — dangerous when combined with credentials or auth APIs."""
    resp = fetch_fn(url, {"Origin": ATTACKER_ORIGIN}, "GET")
    acao = _acao(resp)
    if acao != "*":
        return None
    creds = _credentials_allowed(resp)
    severity = "high" if creds else "low"
    detail = (
        "The server returns Access-Control-Allow-Origin: *"
        + (" together with Access-Control-Allow-Credentials: true. "
           "Browsers reject credentialed reads for wildcard origins, but the "
           "combination signals a broken policy and some non-browser clients "
           "will honour it." if creds else
           ". Any website can read responses. This is acceptable only for "
           "genuinely public, unauthenticated data.")
    )
    return Finding(
        url=url, check="wildcard-origin", severity=severity,
        title="Wildcard Access-Control-Allow-Origin",
        detail=detail,
        evidence={"request_origin": ATTACKER_ORIGIN,
                  "access_control_allow_origin": acao,
                  "access_control_allow_credentials": str(creds).lower()},
        remediation=(
            "Use a wildcard only for public, unauthenticated resources. For "
            "anything behind login, echo back only allowlisted origins."),
    )


def check_subdomain_trust(url: str, fetch_fn: FetchFn) -> Optional[Finding]:
    """Any subdomain of the target is trusted — one XSS/subdomain takeover
    anywhere under the domain then defeats the CORS policy."""
    host = _host(url)
    if not host:
        return None
    origin = f"https://anything.{host}"
    resp = fetch_fn(url, {"Origin": origin}, "GET")
    if _acao(resp) != origin:
        return None
    creds = _credentials_allowed(resp)
    severity = "high" if creds else "medium"
    return Finding(
        url=url, check="subdomain-trust", severity=severity,
        title="All subdomains trusted via Origin suffix match",
        detail=(
            f"The server trusts any subdomain of {host}. A single XSS or a "
            "dangling subdomain anywhere under the domain gives an attacker a "
            "trusted origin to read authenticated responses."),
        evidence={"request_origin": origin,
                  "access_control_allow_origin": origin,
                  "access_control_allow_credentials": str(creds).lower()},
        remediation=(
            "Allowlist exact origins (scheme + host + port) instead of "
            "suffix-matching the host. Keep the list of trusted subdomains "
            "explicit and minimal."),
    )


def check_lookalike_origins(url: str, fetch_fn: FetchFn) -> Optional[Finding]:
    """Weak string matching: prefix/suffix lookalike domains are trusted."""
    host = _host(url)
    if not host:
        return None
    candidates = [
        f"https://{host}.attacker.example",   # target.com.attacker.tld
        f"https://attacker-{host}",           # attacker-target.com style
        f"https://{host}attacker.example".replace("https://", "https://", 1),
    ]
    for origin in candidates:
        resp = fetch_fn(url, {"Origin": origin}, "GET")
        if _acao(resp) == origin:
            creds = _credentials_allowed(resp)
            return Finding(
                url=url, check="lookalike-origin",
                severity="high" if creds else "medium",
                title="Lookalike domain trusted by weak Origin matching",
                detail=(
                    f"The server trusted the lookalike origin {origin}, "
                    "which indicates substring/prefix matching on the Origin "
                    "header. An attacker only needs to register a similar "
                    "domain to obtain a trusted origin."),
                evidence={"request_origin": origin,
                          "access_control_allow_origin": origin,
                          "access_control_allow_credentials":
                              str(creds).lower()},
                remediation=(
                    "Parse the Origin header and compare the full origin "
                    "(scheme, host, port) against an exact allowlist. Never "
                    "use substring, prefix or suffix checks."),
            )
    return None


def check_preflight(url: str, fetch_fn: FetchFn) -> Optional[Finding]:
    """Preflight reflects arbitrary requested headers/methods with creds."""
    headers = {
        "Origin": ATTACKER_ORIGIN,
        "Access-Control-Request-Method": "PUT",
        "Access-Control-Request-Headers": "X-Attacker-Header, Authorization",
    }
    resp = fetch_fn(url, headers, "OPTIONS")
    acao = _acao(resp)
    acah = resp.header("Access-Control-Allow-Headers") or ""
    reflects_origin = acao == ATTACKER_ORIGIN
    reflects_headers = "x-attacker-header" in acah.lower()
    if not (reflects_origin and reflects_headers):
        return None
    creds = _credentials_allowed(resp)
    return Finding(
        url=url, check="preflight-reflection",
        severity="high" if creds else "medium",
        title="Preflight reflects arbitrary origin and headers",
        detail=(
            "The OPTIONS preflight handler reflects an arbitrary Origin and "
            "arbitrary Access-Control-Request-Headers, so cross-origin "
            "requests with custom headers (including Authorization) pass the "
            "preflight check from any website."),
        evidence={"request_origin": ATTACKER_ORIGIN,
                  "access_control_allow_origin": acao or "",
                  "access_control_allow_headers": acah,
                  "access_control_allow_credentials": str(creds).lower()},
        remediation=(
            "Answer preflights from the same strict origin allowlist as "
            "actual requests, and allow only the headers/methods the API "
            "genuinely needs."),
    )


ALL_CHECKS = [
    check_reflected_origin,
    check_null_origin,
    check_wildcard,
    check_subdomain_trust,
    check_lookalike_origins,
    check_preflight,
]


def scan_url(url: str, fetch_fn: Optional[FetchFn] = None) -> List[Finding]:
    """Run every check against one URL and return findings, worst first."""
    if fetch_fn is None:
        fetch_fn = fetch
    findings: List[Finding] = []
    for check in ALL_CHECKS:
        finding = check(url, fetch_fn)
        if finding is not None:
            findings.append(finding)
    findings.sort(key=lambda f: SEVERITY_ORDER[f.severity], reverse=True)
    return findings


def scan_urls(urls: List[str],
              fetch_fn: Optional[FetchFn] = None) -> List[Finding]:
    """Scan several URLs and return all findings, worst first."""
    if fetch_fn is None:
        fetch_fn = fetch
    findings: List[Finding] = []
    for url in urls:
        findings.extend(scan_url(url, fetch_fn))
    findings.sort(key=lambda f: SEVERITY_ORDER[f.severity], reverse=True)
    return findings
