"""Report rendering and CLI tests for cors-hunter."""

import json

import pytest

from cors_hunter import cli, report, scanner
from cors_hunter.scanner import Finding, Response

URL = "https://api.example.com/data"


def sample_finding():
    return Finding(
        url=URL, check="reflected-origin", severity="critical",
        title="Arbitrary Origin reflected",
        detail="Server reflects any origin with credentials.",
        evidence={"request_origin": scanner.ATTACKER_ORIGIN,
                  "access_control_allow_origin": scanner.ATTACKER_ORIGIN},
        remediation="Use a strict allowlist.",
    )


# --- reports ------------------------------------------------------------------

def test_json_report_structure():
    data = json.loads(report.to_json([sample_finding()]))
    assert data["tool"] == "cors-hunter"
    assert data["findings_count"] == 1
    assert data["findings"][0]["severity"] == "critical"
    assert data["findings"][0]["check"] == "reflected-origin"


def test_json_report_empty():
    data = json.loads(report.to_json([]))
    assert data["findings"] == []
    assert data["findings_count"] == 0


def test_markdown_report_contains_key_fields():
    md = report.to_markdown([sample_finding()])
    assert "# cors-hunter report" in md
    assert "CRITICAL" in md
    assert URL in md
    assert "Use a strict allowlist." in md


def test_markdown_report_no_findings():
    assert "No CORS misconfigurations found" in report.to_markdown([])


def test_terminal_report_contains_severity_and_fix():
    out = report.to_terminal([sample_finding()])
    assert "CRITICAL" in out
    assert "Fix:" in out


def test_terminal_report_clean():
    assert "No CORS misconfigurations" in report.to_terminal([])


# --- CLI ----------------------------------------------------------------------

def reflect_fetch(url, headers, method):
    return Response(status=200, headers={
        "Access-Control-Allow-Origin": headers.get("Origin", ""),
        "Access-Control-Allow-Credentials": "true",
    })


def clean_fetch(url, headers, method):
    return Response(status=200, headers={
        "Access-Control-Allow-Origin": "https://app.example.com",
        "Access-Control-Allow-Credentials": "true",
    })


def test_cli_json_output_and_exit_code(monkeypatch, capsys):
    monkeypatch.setattr(scanner, "fetch", reflect_fetch)
    code = cli.main([URL, "--format", "json"])
    data = json.loads(capsys.readouterr().out)
    assert code == 1  # critical >= default fail-on=high
    assert data["findings_count"] >= 1


def test_cli_clean_target_exit_zero(monkeypatch, capsys):
    monkeypatch.setattr(scanner, "fetch", clean_fetch)
    code = cli.main([URL])
    assert code == 0
    assert "No CORS misconfigurations" in capsys.readouterr().out


def test_cli_fail_on_never(monkeypatch):
    monkeypatch.setattr(scanner, "fetch", reflect_fetch)
    assert cli.main([URL, "--fail-on", "never"]) == 0


def test_cli_targets_from_file(monkeypatch, tmp_path, capsys):
    target_file = tmp_path / "targets.txt"
    target_file.write_text(f"# comment\n{URL}\n\n", encoding="utf-8")
    monkeypatch.setattr(scanner, "fetch", clean_fetch)
    code = cli.main(["--file", str(target_file)])
    assert code == 0


def test_cli_writes_output_file(monkeypatch, tmp_path):
    monkeypatch.setattr(scanner, "fetch", reflect_fetch)
    out_file = tmp_path / "report.md"
    cli.main([URL, "--format", "markdown", "-o", str(out_file)])
    assert "cors-hunter report" in out_file.read_text(encoding="utf-8")


def test_cli_no_targets_errors():
    with pytest.raises(SystemExit):
        cli.main([])
