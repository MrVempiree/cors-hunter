"""Report rendering for cors-hunter: terminal, JSON and Markdown."""

from __future__ import annotations

import json
from typing import List

from .scanner import Finding

SEVERITY_LABEL = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "info": "INFO",
}


def to_json(findings: List[Finding]) -> str:
    payload = {
        "tool": "cors-hunter",
        "findings_count": len(findings),
        "findings": [f.to_dict() for f in findings],
    }
    return json.dumps(payload, indent=2)


def to_markdown(findings: List[Finding]) -> str:
    lines = ["# cors-hunter report", ""]
    if not findings:
        lines.append("No CORS misconfigurations found.")
        return "\n".join(lines) + "\n"
    lines.append(f"**{len(findings)} finding(s)**")
    lines.append("")
    for f in findings:
        lines.append(f"## [{SEVERITY_LABEL[f.severity]}] {f.title}")
        lines.append("")
        lines.append(f"- **URL:** {f.url}")
        lines.append(f"- **Check:** {f.check}")
        lines.append(f"- **Detail:** {f.detail}")
        evidence = ", ".join(f"{k}={v}" for k, v in f.evidence.items())
        lines.append(f"- **Evidence:** {evidence}")
        lines.append(f"- **Remediation:** {f.remediation}")
        lines.append("")
    return "\n".join(lines)


def to_terminal(findings: List[Finding]) -> str:
    if not findings:
        return "[+] No CORS misconfigurations found."
    out = []
    for f in findings:
        out.append(f"[{SEVERITY_LABEL[f.severity]}] {f.title}")
        out.append(f"    URL:    {f.url}")
        out.append(f"    Detail: {f.detail}")
        for key, value in f.evidence.items():
            out.append(f"    {key}: {value}")
        out.append(f"    Fix:    {f.remediation}")
        out.append("")
    out.append(f"{len(findings)} finding(s) total.")
    return "\n".join(out)
