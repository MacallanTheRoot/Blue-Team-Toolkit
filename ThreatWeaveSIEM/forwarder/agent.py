"""Simple log forwarder (simulated) that posts JSON to ingestion API."""
import json
import time
import requests

API_URL = "http://localhost:8502/ingest"

LOG_SAMPLES = [
    {"timestamp": "2025-12-27T10:00:00", "severity": "high", "source": "fw01", "ip": "10.0.0.5", "msg": "failed login from 10.0.0.5", "risk_score": 70},
    {"timestamp": "2025-12-27T10:05:00", "severity": "medium", "source": "ids", "ip": "192.168.1.50", "msg": "port scan detected", "risk_score": 60},
]

def main():
    for log in LOG_SAMPLES:
        try:
            requests.post(API_URL, json=log, timeout=3)
            print("sent", json.dumps(log))
        except Exception as exc:
            print("error sending", exc)
        time.sleep(1)

if __name__ == "__main__":
    main()
