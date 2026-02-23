import json
import glob
import os

final_report = {
    "scan_summary": {
        "total": 0,
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0
    },
    "findings": []
}

def normalize_severity(sev):
    if not sev:
        return "MEDIUM"

    sev = sev.lower()

    if sev in ["critical"]:
        return "CRITICAL"
    if sev in ["high", "error"]:
        return "HIGH"
    if sev in ["medium", "warning"]:
        return "MEDIUM"
    if sev in ["low"]:
        return "LOW"

    return "MEDIUM"


# 🔐 Process Gitleaks
# After artifact download, file will be inside folder: gitleaks-report/
gitleaks_path = "gitleaks-report/gitleaks-report.json"

if os.path.isfile(gitleaks_path):
    with open(gitleaks_path) as f:
        data = json.load(f)
        for item in data:
            finding = {
                "tool": "gitleaks",
                "category": "secret",
                "severity": "HIGH",
                "file": item.get("File"),
                "line": item.get("StartLine"),
                "description": item.get("Description")
            }
            final_report["findings"].append(finding)


# 🔍 Process CodeQL SARIF
# Artifacts are downloaded into folder: codeql-report/
for sarif_file in glob.glob("codeql-report/**/*.sarif", recursive=True):

    if os.path.isfile(sarif_file):   # ✅ Prevent directory error
        with open(sarif_file) as f:
            sarif = json.load(f)

            for run in sarif.get("runs", []):
                for result in run.get("results", []):
                    sev = normalize_severity(result.get("level"))

                    finding = {
                        "tool": "codeql",
                        "category": "sast",
                        "severity": sev,
                        "file": result.get("locations", [{}])[0]
                                .get("physicalLocation", {})
                                .get("artifactLocation", {})
                                .get("uri"),
                        "line": result.get("locations", [{}])[0]
                                .get("physicalLocation", {})
                                .get("region", {})
                                .get("startLine"),
                        "description": result.get("message", {}).get("text")
                    }

                    final_report["findings"].append(finding)


# 📊 Calculate Summary
for f in final_report["findings"]:
    sev = f["severity"].lower()
    if sev in final_report["scan_summary"]:
        final_report["scan_summary"][sev] += 1

final_report["scan_summary"]["total"] = len(final_report["findings"])


# 💾 Write Final Report
with open("final-security-report.json", "w") as f:
    json.dump(final_report, f, indent=2)

print("Final report generated successfully.")