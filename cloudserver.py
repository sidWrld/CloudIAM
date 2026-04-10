"""
server.py — Cloud fraud detection microservice.
Deploy:
    pip install flask gunicorn
    gunicorn -w 2 -b 0.0.0.0:5000 server:app
Run locally:
    python server.py
"""

from flask import Flask, request, jsonify
from datetime import datetime
import database as db

app = Flask(__name__)

MAX_RISK        = 100
FRAUD_THRESHOLD = 60

def calculate_risk(username, payload):
    history = db.get_history(username)
    risk    = 0
    reasons = []

    known_ips       = {r["ip"]      for r in history}
    known_devices   = {r["device"]  for r in history}
    known_countries = {r["country"] for r in history}

    ip      = payload.get("ip", "")
    device  = payload.get("device", "")
    country = payload.get("country", "")
    hour    = datetime.now().hour
    now     = datetime.now()

    if history and ip not in known_ips:
        risk += 25
        reasons.append("new IP address")

    if history and device not in known_devices:
        risk += 20
        reasons.append("new device")

    if history and country not in known_countries:
        risk += 30
        reasons.append(f"new country ({country})")

    if 0 <= hour < 5:
        risk += 15
        reasons.append("unusual hour")

    recent_attempts = [
        r for r in history
        if (now - datetime.fromisoformat(r["time"])).total_seconds() <= 10
    ]
    if len(recent_attempts) >= 3:
        risk += 35
        reasons.append(f"{len(recent_attempts)} attempts in last 10 seconds (bot-like speed)")

    fail_history = db.get_fail_history(username)
    recent_fails = len([
        r for r in fail_history
        if (now - datetime.fromisoformat(r["time"])).total_seconds() <= 300
    ])
    if recent_fails >= 3:
        risk += 20
        reasons.append(f"{recent_fails} failed password attempts in last 5 minutes")

    if not history:
        reasons.append("first login (no history)")

    return min(risk, MAX_RISK), reasons


@app.route("/verify", methods=["POST"])
def verify():
    payload = request.get_json()
    if not payload or "username" not in payload:
        return jsonify({"error": "missing username"}), 400

    username      = payload["username"]
    risk, reasons = calculate_risk(username, payload)
    fraudulent    = risk >= FRAUD_THRESHOLD

    db.add_login(username, {
        "ip":      payload.get("ip"),
        "device":  payload.get("device"),
        "country": payload.get("country"),
        "hour":    datetime.now().hour,
        "success": not fraudulent,
        "risk":    risk,
        "time":    datetime.now().isoformat()
    })

    return jsonify({
        "username":   username,
        "risk_score": risk,
        "fraudulent": fraudulent,
        "reasons":    reasons if reasons else ["all checks passed"]
    })


@app.route("/notify_fail", methods=["POST"])
def notify_fail():
    payload  = request.get_json()
    username = payload.get("username")
    if not username:
        return jsonify({"error": "missing username"}), 400

    db.add_fail(username, {
        "ip":     payload.get("ip"),
        "device": payload.get("device"),
        "time":   datetime.now().isoformat()
    })
    print(f"[server] Failed attempt recorded for: {username}")
    return jsonify({"status": "recorded"})


@app.route("/history/<username>", methods=["GET"])
def history(username):
    return jsonify({
        "logins":   db.get_history(username),
        "failures": db.get_fail_history(username)
    })


if __name__ == "__main__":
    print("Fraud Detection Server on http://0.0.0.0:5000")
    app.run(host="0.0.0.0", port=5000, debug=False)
