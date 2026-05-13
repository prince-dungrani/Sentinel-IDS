"""
attack_lab/targets/vulnerable_flask_app.py
==========================================
Vulnerable Localhost Target Application

Deliberately insecure Flask app that serves as a target for:
  - SQL Injection attacks
  - XSS attacks
  - Command Injection attacks
  - Brute Force attacks
  - Path Traversal attacks
  - Slowloris attacks

⚠️  FOR EDUCATIONAL / LAB USE ONLY — DO NOT EXPOSE TO INTERNET
Runs on http://127.0.0.1:5001
"""

import sys
import os
import logging
import time
from datetime import datetime

# Add parent dir to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

try:
    from flask import Flask, request, jsonify, Response
except ImportError:
    print("[!] Flask not installed. Run: pip install flask")
    sys.exit(1)

log = logging.getLogger("sentinel.target")

app = Flask(__name__)
app.config["DEBUG"] = False  # Keep logs clean

# =====================================================
# Simulated "database" (in-memory for lab only)
# =====================================================
FAKE_DB = {
    "users": [
        {"id": 1, "username": "admin", "password": "admin123"},
        {"id": 2, "username": "user1", "password": "pass1"},
        {"id": 3, "username": "john",  "password": "secret"},
    ]
}

REQUEST_COUNT = {"total": 0, "start_time": time.time()}


def count_request():
    REQUEST_COUNT["total"] += 1


# =====================================================
# Home Page
# =====================================================
@app.route("/", methods=["GET"])
def home():
    count_request()
    search = request.args.get("search", "")
    cmd    = request.args.get("cmd", "")
    q      = request.args.get("q", "")

    # Deliberately vulnerable: reflects parameters directly
    html = f"""
    <!DOCTYPE html>
    <html>
    <head><title>Vulnerable Target App - Lab</title></head>
    <body>
        <h1>⚠️ Vulnerable Lab Application</h1>
        <p>Search result for: {search}</p>
        <p>Query: {q}</p>
        <p>Command output: {cmd}</p>
        <p>Requests served: {REQUEST_COUNT['total']}</p>
    </body>
    </html>"""
    return html


# =====================================================
# SQL Injection Target
# =====================================================
@app.route("/login", methods=["GET", "POST"])
def login():
    count_request()
    user = request.args.get("user", request.form.get("user", ""))
    pwd  = request.args.get("pwd",  request.form.get("pwd", ""))

    # Deliberately vulnerable SQL-like logic
    for u in FAKE_DB["users"]:
        if u["username"] == user and u["password"] == pwd:
            return jsonify({"status": "success", "message": f"Welcome {user}"})

    return jsonify({"status": "failed", "message": f"Invalid credentials for user '{user}'"}), 401


@app.route("/search", methods=["GET"])
def search():
    count_request()
    q = request.args.get("q", "")
    # Reflect query (intentionally vulnerable for IDS testing)
    return jsonify({"query": q, "results": [], "message": f"Searched for: {q}"})


@app.route("/api/users", methods=["GET"])
def get_users():
    count_request()
    user_id = request.args.get("id", "1")
    return jsonify({"user_id": user_id, "data": FAKE_DB["users"][:1]})


# =====================================================
# Brute Force Target
# =====================================================
@app.route("/admin", methods=["GET", "POST"])
def admin():
    count_request()
    auth = request.headers.get("Authorization", "")
    user = request.form.get("username", request.args.get("username", ""))
    pwd  = request.form.get("password", request.args.get("password", ""))

    if user == "admin" and pwd == "admin123":
        return jsonify({"status": "authenticated", "role": "admin"})
    return jsonify({"status": "denied", "attempt": user}), 401


# =====================================================
# Path Traversal Target
# =====================================================
@app.route("/file", methods=["GET"])
def read_file():
    count_request()
    filename = request.args.get("name", "readme.txt")
    return jsonify({"filename": filename, "content": "File content would appear here"})


# =====================================================
# DNS/Data exfil-like endpoint
# =====================================================
@app.route("/api/data", methods=["GET", "POST"])
def data_endpoint():
    count_request()
    data = request.args.get("data", "")
    return jsonify({"received": len(data), "status": "ok"})


# =====================================================
# Status endpoint (for IDS to check target health)
# =====================================================
@app.route("/health", methods=["GET"])
def health():
    uptime = time.time() - REQUEST_COUNT["start_time"]
    return jsonify({
        "status": "running",
        "uptime_seconds": round(uptime, 1),
        "requests_served": REQUEST_COUNT["total"],
        "timestamp": datetime.now().isoformat(),
    })


# =====================================================
# Slow endpoint (for Slowloris testing)
# =====================================================
@app.route("/slow", methods=["GET"])
def slow_endpoint():
    count_request()
    def generate():
        yield "Starting...\n"
        time.sleep(2)
        yield "Still here...\n"
    return Response(generate(), mimetype="text/plain")


if __name__ == "__main__":
    import warnings
    warnings.filterwarnings("ignore")

    print("=" * 55)
    print("  ⚠️  VULNERABLE LAB TARGET — FOR LAB USE ONLY")
    print("  Listening on: http://127.0.0.1:5001")
    print("  Endpoints:")
    print("    GET  /           — Home (XSS, params)")
    print("    GET  /login      — SQL Injection target")
    print("    GET  /search     — Search injection target")
    print("    POST /admin      — Brute force target")
    print("    GET  /file       — Path traversal target")
    print("    GET  /slow       — Slowloris target")
    print("    GET  /health     — Health check")
    print("=" * 55)

    logging.basicConfig(level=logging.WARNING)
    app.run(host="127.0.0.1", port=5001, debug=False, use_reloader=False, threaded=True)
