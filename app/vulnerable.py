# vulnerable.py

import subprocess
from flask import Flask, request

app = Flask(__name__)

@app.route("/start")
def run():
    cmd = request.args.get("cmd")
    subprocess.call(cmd, shell=True)
    return "Done"