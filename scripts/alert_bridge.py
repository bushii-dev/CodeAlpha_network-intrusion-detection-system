"""
alert_bridge.py
Tiny local API that tails Suricata's eve.json and exposes recent
alerts as JSON so the browser dashboard (dashboard/ids_dashboard.html)
can poll real data instead of the built-in simulator.

Usage:
    pip install flask flask-cors
    python3 alert_bridge.py

Then in ids_dashboard.html, replace the simulator loop with a
fetch('http://localhost:5001/alerts') poll (see README for the snippet).
"""

from flask import Flask, jsonify
from flask_cors import CORS
import json

app = Flask(__name__)
CORS(app)

EVE_PATH = "/var/log/suricata/eve.json"
SEVERITY_MAP = {1: "crit", 2: "warn", 3: "info"}


@app.route("/alerts")
def alerts():
    events = []
    try:
        with open(EVE_PATH) as f:
            lines = f.readlines()[-200:]
    except FileNotFoundError:
        return jsonify({"error": f"{EVE_PATH} not found"}), 404

    for line in lines:
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if record.get("event_type") != "alert":
            continue
        alert = record.get("alert", {})
        events.append({
            "timestamp": record.get("timestamp"),
            "src_ip": record.get("src_ip"),
            "severity": SEVERITY_MAP.get(alert.get("severity"), "info"),
            "signature": alert.get("signature", "Unknown signature"),
        })

    return jsonify(events)


if __name__ == "__main__":
    app.run(port=5001)
