# Contributing to cors-hunter

Thanks for helping improve cors-hunter. This tool exists for **authorised**
security testing and defence: only ever scan systems you own or have explicit
written permission to test.

## Getting set up

```bash
git clone https://github.com/MrVempiree/cors-hunter.git
cd cors-hunter
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest
```

Python 3.9+ is required. The test suite runs fully offline — the scanner is
tested against mocked responses, never against live third-party sites.

## How the code is organised

- `cors_hunter/scanner.py` — the CORS checks themselves
- `cors_hunter/report.py` — severity, evidence and remediation formatting
- `cors_hunter/cli.py` — command-line interface (`cors-hunter`)
- `tests/test_scanner.py`, `tests/test_report_cli.py` — the test suite

## Adding a new check

1. Add the check to `scanner.py`, following the existing checks' shape: a
   probe, the response evidence that proves the issue, a severity, and a
   remediation note.
2. Judge severity by exploitability, not by how interesting the header looks —
   a reflected `Access-Control-Allow-Origin` with credentials is critical;
   a wildcard origin on a public, credential-less API usually is not.
3. Add tests in `tests/test_scanner.py` for the positive case (misconfigured)
   and the negative case (correctly configured), using mocked responses.
4. Run the full suite before opening the pull request.

## Pull requests

- One check or one fix per PR, with a short description of the
  misconfiguration it detects and why the severity is what it is.
- All tests must pass (`pytest` green) and new behaviour must be covered by
  tests.
- No live targets in tests, screenshots or examples — use `example.com` and
  mocked responses.

## Reporting bugs

Open an issue with the command you ran, the (sanitised) response headers
involved, and what you expected instead. Do not include headers or results
from systems you do not own.
