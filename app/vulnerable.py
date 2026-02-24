# app/vulnerable.py
#
# ⚠️  THIS FILE IS INTENTIONALLY VULNERABLE FOR TESTING PURPOSES ONLY
# It is designed to trigger findings in all three security scans:
#   - Gitleaks   → hardcoded secrets / API keys
#   - Semgrep    → SAST: injection, XSS, SSRF, insecure deserialization, etc.
#   - Dependabot → triggered via old flask==0.5 in requirements.txt
#
# DO NOT deploy this to production.

import os
import pickle
import subprocess
import sqlite3
import hashlib
import yaml
from flask import Flask, request, render_template_string

app = Flask(__name__)

# ---------------------------------------------------------------
# 🔑 GITLEAKS TRIGGERS — Hardcoded secrets
# ---------------------------------------------------------------

# Hardcoded AWS credentials — test dummy values, triggers Gitleaks pattern match
# gitleaks:allow — comment this line out to let Gitleaks fail the CI scan
AWS_ACCESS_KEY_ID     = "AKIA-TEST-KEY-FOR-DEVSECOPS-SCAN"
AWS_SECRET_ACCESS_KEY = "test/FakeSecretKey+DevSecOpsDemo/NotReal"

# Hardcoded DB password (triggers Gitleaks custom rule)
DB_PASSWORD = "db_password=SuperSecret123!"

# Hardcoded JWT secret (triggers Gitleaks)
JWT_SECRET = "jwt_secret=my-very-secret-jwt-token-do-not-share"

# Hardcoded internal API token (triggers .gitleaks.toml custom rule)
INTERNAL_API_TOKEN = "IAT=devSecOpsTestTokenFakeValue12345"


# ---------------------------------------------------------------
# 💉 SEMGREP SAST TRIGGERS
# ---------------------------------------------------------------

# [VULN-1] Command Injection — subprocess with shell=True and user input
@app.route("/run")
def run_command():
    """Runs arbitrary OS commands from user input. Classic CI."""
    cmd = request.args.get("cmd", "")
    result = subprocess.check_output(cmd, shell=True)   # semgrep: subprocess-shell-true
    return result


# [VULN-2] SQL Injection — string-formatted query, no parameterization
@app.route("/user")
def get_user():
    """Fetches user by name using a raw SQL query."""
    username = request.args.get("name", "")
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # Directly formatting user input into query (semgrep: python.lang.security.audit.formatted-sql-query)
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    rows = cursor.fetchall()
    conn.close()
    return str(rows)


# [VULN-3] XSS — user input reflected directly into HTML without escaping
@app.route("/greet")
def greet():
    """Greets user by name — but reflects raw HTML."""
    name = request.args.get("name", "World")
    # User-controlled data injected into HTML (semgrep: python.flask.security.xss.audit.direct-use-of-jinja2)
    template = f"<h1>Hello, {name}!</h1>"
    return render_template_string(template)


# [VULN-4] Insecure Deserialization — pickle.loads on user-supplied data
@app.route("/deserialize", methods=["POST"])
def deserialize():
    """Deserializes arbitrary user-supplied pickle data."""
    data = request.get_data()
    # Arbitrary code execution via pickle (semgrep: python.lang.security.deserialization.avoid-pickle)
    obj = pickle.loads(data)
    return str(obj)


# [VULN-5] Path Traversal — reading arbitrary files from user input
@app.route("/file")
def read_file():
    """Reads a file by name from the server's filesystem."""
    filename = request.args.get("name", "")
    # No sanitization — can escape the web root (semgrep: python.lang.security.audit.path-traversal)
    with open(f"/var/www/files/{filename}") as f:
        return f.read()


# [VULN-6] Weak hashing — MD5 used for password hashing
def hash_password(password: str) -> str:
    # MD5 is cryptographically broken (semgrep: python.lang.security.audit.use-defusedxml / hashlib)
    return hashlib.md5(password.encode()).hexdigest()


# [VULN-7] YAML unsafe load — arbitrary code execution via YAML input
@app.route("/parse-yaml", methods=["POST"])
def parse_yaml():
    """Parses YAML from POST body — uses unsafe yaml.load."""
    raw = request.get_data(as_text=True)
    # yaml.load without Loader is unsafe (semgrep: python.lang.security.audit.dangerous-yaml-load)
    data = yaml.load(raw)
    return str(data)


# [VULN-8] Debug mode enabled — exposes interactive console in production
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")  # semgrep: python.flask.security.audit.app-run-security-risk
