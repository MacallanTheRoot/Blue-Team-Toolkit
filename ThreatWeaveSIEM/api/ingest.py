"""FastAPI ingestion endpoint for logs."""
from __future__ import annotations
from fastapi import FastAPI
from pydantic import BaseModel
import sqlite3
from datetime import datetime

app = FastAPI(title="ThreatWeave SIEM Ingestion API")
DB_PATH = "threatweave_logs.db"

class LogIn(BaseModel):
    timestamp: str | None = None
    severity: str
    source: str
    ip: str
    msg: str
    risk_score: int = 0

@app.post("/ingest")
def ingest(log: LogIn):
    ts = log.timestamp or datetime.now().isoformat()
    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO logs (timestamp, severity, source, ip, msg, risk_score) VALUES (?, ?, ?, ?, ?, ?)",
            (ts, log.severity, log.source, log.ip, log.msg, log.risk_score),
        )
        conn.commit()
    return {"status": "ok"}
