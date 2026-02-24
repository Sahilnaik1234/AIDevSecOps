"""
scripts/normalize.py
====================
PLUG-AND-PLAY report normalizer.

Reads per-tool JSON artifacts and merges them into a single
`final-security-report.json` with a consistent schema.

To add a new tool:
  1. Have the tool's CI job upload an artifact with a known name
  2. Add a new `process_<toolname>()` function below
  3. Call it from main()

Artifact layout after `actions/download-artifact@v4` with path=scan-artifacts/:
  scan-artifacts/
    gitleaks-report/
      gitleaks-report.json
    semgrep-report/
      semgrep-report.json
    dependency-report/
      dependency-report.json
"""

import json
import os
import sys

# Support running from repo root (CI) or scripts/ directory (local)
ARTIFACTS_DIR = os.environ.get("ARTIFACTS_DIR", "scan-artifacts")

# ---------------------------------------------------------------
# Canonical report structure
# ---------------------------------------------------------------
final_report = {
    "scan_summary": {
        "total":    0,
        "critical": 0,
        "high":     0,
        "medium":   0,
        "low":      0,
        "info":     0,
    },
    "findings": [],
}

# ---------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------
SEVERITY_MAP = {
    "critical": "CRITICAL",
    "high":     "HIGH",
    "error":    "HIGH",       # Semgrep uses "error"
    "warning":  "MEDIUM",     # Semgrep uses "warning"
    "medium":   "MEDIUM",
    "low":      "LOW",
    "info":     "INFO",
    "note":     "INFO",
}

def normalize_severity(raw: str) -> str:
    if not raw:
        return "MEDIUM"
    return SEVERITY_MAP.get(raw.lower(), "MEDIUM")


def load_json(path: str):
    """Load JSON file; return None if missing or unreadable."""
    if not os.path.isfile(path):
        print(f"[SKIP] Artifact not found: {path}")
        return None
    try:
        with open(path) as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        print(f"[WARN] Could not parse {path}: {e}")
        return None


def add_finding(finding: dict):
    final_report["findings"].append(finding)


# ---------------------------------------------------------------
# Tool parsers — each function is self-contained
# ---------------------------------------------------------------

def process_gitleaks():
    """
    Parse Gitleaks JSON report.
    Schema: https://github.com/gitleaks/gitleaks#report-formats
    """
    path = os.path.join(ARTIFACTS_DIR, "gitleaks-report", "gitleaks-report.json")
    data = load_json(path)
    if data is None:
        return

    count = 0
    for item in data:
        add_finding({
            "tool":        "gitleaks",
            "category":    "secret",
            "severity":    "HIGH",          # secrets are always high
            "rule_id":     item.get("RuleID", ""),
            "file":        item.get("File", ""),
            "line":        item.get("StartLine"),
            "description": item.get("Description", "Secret detected"),
            "match":       item.get("Match", ""),   # redacted by --redact flag
        })
        count += 1

    print(f"[Gitleaks]     {count} finding(s)")


def process_semgrep():
    """
    Parse Semgrep JSON report.
    Schema: semgrep scan --json produces { results: [...], errors: [...] }
    """
    path = os.path.join(ARTIFACTS_DIR, "semgrep-report", "semgrep-report.json")
    data = load_json(path)
    if data is None:
        return

    results = data.get("results", [])
    count = 0
    for item in results:
        extra    = item.get("extra", {})
        metadata = extra.get("metadata", {})
        severity = extra.get("severity") or metadata.get("severity", "warning")

        add_finding({
            "tool":        "semgrep",
            "category":    "sast",
            "severity":    normalize_severity(severity),
            "rule_id":     item.get("check_id", ""),
            "file":        item.get("path", ""),
            "line":        item.get("start", {}).get("line"),
            "description": extra.get("message", ""),
            "cwe":         metadata.get("cwe", []),
            "owasp":       metadata.get("owasp", []),
        })
        count += 1

    errors = data.get("errors", [])
    if errors:
        print(f"[Semgrep]      {len(errors)} parse/rule error(s) (see semgrep-report.json)")

    print(f"[Semgrep]      {count} finding(s)")


def process_dependabot():
    """
    Parse Dependabot alerts fetched from GitHub API.
    Schema: https://docs.github.com/en/rest/dependabot/alerts
    """
    path = os.path.join(ARTIFACTS_DIR, "dependency-report", "dependency-report.json")
    data = load_json(path)
    if data is None:
        return

    count = 0
    for alert in data:
        advisory  = alert.get("security_advisory", {})
        vuln      = alert.get("security_vulnerability", {})
        dep       = alert.get("dependency", {})
        severity  = advisory.get("severity", "medium")

        add_finding({
            "tool":              "dependabot",
            "category":         "dependency",
            "severity":         normalize_severity(severity),
            "rule_id":          advisory.get("ghsa_id", ""),
            "file":             dep.get("manifest_path", ""),
            "line":             None,
            "description":      advisory.get("summary", ""),
            "package":          dep.get("package", {}).get("name", ""),
            "vulnerable_range": vuln.get("vulnerable_version_range", ""),
            "fixed_in":         vuln.get("first_patched_version", {}).get("identifier"),
            "cve":              advisory.get("cve_id", ""),
        })
        count += 1

    print(f"[Dependabot]   {count} finding(s)")


# ---------------------------------------------------------------
# Main
# ---------------------------------------------------------------
def main():
    print("=== Normalizing security scan reports ===")
    print(f"Artifacts directory: {ARTIFACTS_DIR}")
    print()

    # ── Add new tool parsers here ──
    process_gitleaks()
    process_semgrep()
    process_dependabot()

    # Build summary
    summary = final_report["scan_summary"]
    for finding in final_report["findings"]:
        sev = finding["severity"].lower()
        if sev in summary:
            summary[sev] += 1
    summary["total"] = len(final_report["findings"])

    print()
    print(f"Total findings: {summary['total']}  "
          f"(CRITICAL={summary['critical']} HIGH={summary['high']} "
          f"MEDIUM={summary['medium']} LOW={summary['low']} INFO={summary['info']})")

    output_path = "final-security-report.json"
    with open(output_path, "w") as f:
        json.dump(final_report, f, indent=2)

    print(f"\nReport written to: {output_path}")


if __name__ == "__main__":
    main()