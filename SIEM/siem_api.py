#!/usr/bin/env python3
"""Simple REST API to ingest external alerts (e.g., FIM) into Silent Watcher SIEM.

- Endpoint: POST /webhook
- Stores incoming alerts into siem_logs.db used by dashboard
- Designed to be lightweight and tolerant to malformed input
"""

from flask import Flask, request, jsonify
from datetime import datetime
import json

from siem_hunter import SIEMDatabase

app = Flask(__name__)

db = SIEMDatabase(db_path='siem_logs.db')


def normalize_severity(value: str) -> str:
    """Map external severities to SIEM severities."""
    if not value:
        return 'info'
    value_upper = value.upper()
    mapping = {
        'CRITICAL': 'critical',
        'HIGH': 'high',
        'MEDIUM': 'medium',
        'LOW': 'info',
        'INFO': 'info'
    }
    return mapping.get(value_upper, 'info')


@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "ok"})


@app.route('/webhook', methods=['POST'])
def ingest_webhook():
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 400

    alert = request.get_json()

    log_entry = {
        "timestamp": alert.get("timestamp", datetime.now().isoformat()),
        "log_type": "fim",
        "severity": normalize_severity(alert.get("severity")),
        "source": alert.get("tool", "AutoSec_FIM"),
        "event_type": alert.get("event_type", "unknown"),
        "target_path": alert.get("target_path"),
        "message": alert.get("message"),
        "raw": alert
    }

    try:
        db.insert_log(log_entry)
    except Exception as exc:  # fail-safe, do not crash
        return jsonify({"error": "insert_failed", "detail": str(exc)}), 500

    return jsonify({"status": "success", "message": "alert ingested"}), 200


if __name__ == '__main__':
    print("[+] SIEM Ingest API listening on http://0.0.0.0:5000/webhook")
    app.run(host='0.0.0.0', port=5000)
