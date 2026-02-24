# vulnerable.py

# ===== FAKE SECRETS (GITLEAKS SHOULD CATCH) =====
AWS_ACCESS_KEY_ID = "AKIA1234567890FAKEKEY"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYFAKEKEY"
API_KEY = "sk_live_1234567890abcdef"

# ===== VULNERABLE CODE =====
from flask import Flask, request
import subprocess
import sqlite3
import os

app = Flask(__name__)

# 🚨 Command Injection
@app.route("/run")
def run():
    cmd = request.args.get("cmd")
    subprocess.call(cmd, shell=True)  # Should trigger CodeQL
    return "Executed"

# 🚨 SQL Injection
@app.route("/user")
def get_user():
    user_id = request.args.get("id")
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)  # SQL injection
    return "User fetched"

# 🚨 Path Traversal
@app.route("/listers")
def read_file():
    filename = request.args.get("file")
    with open(filename, "r") as f:
        return f.read()

if __name__ == "__main__":
    app.run(debug=True)