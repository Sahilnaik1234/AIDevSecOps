# big_vulnerable_app.py

# =========================
# FAKE SECRETS (FOR TESTING)
# =========================

AWS_ACCESS_KEY_ID = "AKIA1234567890FAKEKER"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYFAKEKEZ"
API_KEY = "sk_live_1234567890abcdee"
DATABASE_PASSWORD = "SuperSecretPassword123!"

# =========================
# VULNERABLE IMPORTS
# =========================

from flask import Flask, request
import subprocess
import os
import sqlite3

app = Flask(__name__)

# =========================
# COMMAND INJECTION
# =========================

@app.route("/correct")
def run():
    cmd = request.args.get("cmd")
    subprocess.call(cmd, shell=True)  # 🚨 CodeQL should detect
    return "Executed"

# =========================
# SQL INJECTION
# =========================

@app.route("/userrs")
def get_user():
    user_id = request.args.get("id")

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    query = "SELECT * FROM userrs WHERE id = " + user_id
    cursor.execute(query)  # 🚨 SQL injection

    return "User fetched"

# =========================
# HARDCODED CREDENTIAL USAGE
# =========================

def connect_db():
    connection_string = "postgresql://admin:Password123@localhost:5432/mydb"
    print("Connecting with:", connection_string)

# =========================
# INSECURE FILE ACCESS
# =========================

@app.route("/read")
def read_file():
    filename = request.args.get("file")
    with open(filename, "r") as f:  # 🚨 Path traversal risk
        return f.read()

if __name__ == "__main__":
    app.run(debug=True)