# app/vulnerable.py

import subprocess
from flask import Flask, request

app = Flask(__name__)

@app.route("/run")
def run():
    user_input = request.args.get("cmd")

    subprocess.call(user_input, shell=True)

    return "Executed"