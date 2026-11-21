# cors-hunter

> A CORS misconfiguration scanner for authorised web security testing — finds reflected origins, trusted `null` origins, wildcard-with-credentials, subdomain trust and broken preflight handling, and explains exactly how to fix each one.

![CI](https://github.com/MrVempiree/cors-hunter/actions/workflows/ci.yml/badge.svg)
![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)
![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)

## Features

- **Six targeted checks** — no noisy generic probing:
  - Arbitrary `Origin` reflection (critical when credentials are allowed)
  - Trusted `null` origin (sandboxed-iframe / redirect exploitation)
  - Wildcard `Access-Control-Allow-Origin: *`, escalated when combined with credentials
  - Whole-subdomain trust via suffix matching (one dangling subdomain = game over)
  - Lookalike-domain trust from substring/prefix `Origin` matching
  - Preflight (`OPTIONS`) reflection of arbitrary origins and headers
- **Severity with reasoning** — every finding explains *why* it matters, shows the request/response evidence, and gives concrete remediation.
- **Three report formats** — terminal, JSON and Markdown.
- **CI-friendly** — `--fail-on` exit codes let you gate pipelines on new CORS flaws.
- **Zero dependencies** — pure standard library; the detection engine is fully unit-tested with mocked HTTP.

## Installation

```bash
git clone https://github.com/MrVempiree/cors-hunter.git
cd cors-hunter
pip install .
```

Or run it in place:

```bash
python -m cors_hunter.cli https://api.example.com
```

## Usage

```bash
# Single target
cors-hunter https://api.example.com/data

# Many targets from a file, Markdown report saved to disk
cors-hunter --file targets.txt --format markdown -o cors-report.md

# JSON for tooling, fail the pipeline only on critical findings
cors-hunter https://api.example.com --format json --fail-on critical
```

## Sample output

```text
[CRITICAL] Arbitrary Origin reflected
    URL:    https://api.example.com/data
    Detail: The server reflects an arbitrary Origin header in
            Access-Control-Allow-Origin and allows credentials, so any
            website can read authenticated responses from a victim's browser.
    request_origin: https://evil.attacker.example
    access_control_allow_origin: https://evil.attacker.example
    access_control_allow_credentials: true
    Fix:    Replace dynamic Origin reflection with a strict server-side
            allowlist of trusted origins. Never combine a reflected/wildcard
            Access-Control-Allow-Origin with
            Access-Control-Allow-Credentials: true.

1 finding(s) total.
```

## How it works

For each target, cors-hunter sends a series of requests with attacker-controlled `Origin` values (plus one `OPTIONS` preflight) and inspects the `Access-Control-Allow-Origin`, `Access-Control-Allow-Credentials` and `Access-Control-Allow-Headers` response headers. Each check maps to a well-known CORS weakness class documented by OWASP and PortSwigger Web Security Academy research. The HTTP layer is a single injectable function, which is why the entire engine can be tested offline against mocked responses.

## Development

```bash
pip install -e ".[dev]"
python -m pytest
```

## ⚠️ Authorised use only

cors-hunter is a security testing tool. Use it **only** on systems you own or have explicit, written permission to test (for example, an in-scope bug-bounty target). Unauthorised scanning may be illegal in your jurisdiction. The author accepts no liability for misuse.

## Author

Created by **Lavish Gangwar** ([MrVempiree](https://github.com/MrVempiree)) — Cybersecurity Researcher & Web Pentester.

## License

MIT — see [LICENSE](LICENSE).
