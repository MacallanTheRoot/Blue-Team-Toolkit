"""SIEM domain işlemleri için repository pattern."""
from __future__ import annotations
import sqlite3
from typing import List, Dict, Any

class SIEMRepository:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    # Loglar
    def get_logs(self, limit: int = 1000) -> List[Dict[str, Any]]:
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM logs ORDER BY timestamp DESC LIMIT ?", (limit,))
        return [dict(row) for row in cur.fetchall()]

    def insert_log(self, log: Dict[str, Any]) -> None:
        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO logs (timestamp, severity, source, ip, msg, risk_score) VALUES (?, ?, ?, ?, ?, ?)",
            (
                log.get("timestamp"),
                log.get("severity"),
                log.get("source"),
                log.get("ip"),
                log.get("msg"),
                int(log.get("risk_score", 0)),
            ),
        )
        self.conn.commit()

    def top_ips(self, limit: int = 10) -> List[Dict[str, Any]]:
        cur = self.conn.cursor()
        cur.execute(
            "SELECT ip, SUM(risk_score) as total_risk FROM logs GROUP BY ip ORDER BY total_risk DESC LIMIT ?",
            (limit,),
        )
        return [dict(row) for row in cur.fetchall()]

    def severity_counts(self) -> List[Dict[str, Any]]:
        cur = self.conn.cursor()
        cur.execute("SELECT severity, COUNT(*) as count FROM logs GROUP BY severity")
        return [dict(row) for row in cur.fetchall()]

    # TI cache
    def upsert_ti(self, ind: Dict[str, Any]) -> None:
        cur = self.conn.cursor()
        cur.execute(
            """
            INSERT INTO ti_cache (indicator, type, status, score, first_seen, last_seen, source)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(indicator) DO UPDATE SET
                status=excluded.status,
                score=excluded.score,
                last_seen=excluded.last_seen,
                source=excluded.source
            """,
            (
                ind["indicator"], ind["type"], ind["status"], int(ind["score"]), ind["first_seen"], ind["last_seen"], ind["source"],
            ),
        )
        self.conn.commit()

    def ti_history(self, indicator: str) -> List[Dict[str, Any]]:
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM ti_cache WHERE indicator = ?", (indicator,))
        return [dict(row) for row in cur.fetchall()]

    # Assets
    def upsert_asset(self, asset: Dict[str, Any]) -> None:
        cur = self.conn.cursor()
        cur.execute(
            """
            INSERT INTO assets (id, hostname, ip, os, tags, importance, last_seen, health, risk)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                hostname=excluded.hostname,
                ip=excluded.ip,
                os=excluded.os,
                tags=excluded.tags,
                importance=excluded.importance,
                last_seen=excluded.last_seen,
                health=excluded.health,
                risk=excluded.risk
            """,
            (
                asset.get("id"), asset.get("hostname"), asset.get("ip"), asset.get("os"), asset.get("tags"), asset.get("importance"), asset.get("last_seen"), asset.get("health"), asset.get("risk"),
            ),
        )
        self.conn.commit()

    def list_assets(self) -> List[Dict[str, Any]]:
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM assets ORDER BY importance DESC, last_seen DESC")
        return [dict(row) for row in cur.fetchall()]

    # Incidents
    def create_incident(self, inc: Dict[str, Any]) -> int:
        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO incidents (title, severity, status, created_at, updated_at, tags) VALUES (?, ?, ?, ?, ?, ?)",
            (inc["title"], inc["severity"], inc.get("status", "open"), inc["created_at"], inc["updated_at"], inc.get("tags", "")),
        )
        self.conn.commit()
        return cur.lastrowid

    def add_note(self, incident_id: int, note: Dict[str, Any]) -> None:
        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO incident_notes (incident_id, author, note, created_at) VALUES (?, ?, ?, ?)",
            (incident_id, note["author"], note["note"], note["created_at"]),
        )
        self.conn.commit()

    def list_incidents(self) -> List[Dict[str, Any]]:
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM incidents ORDER BY created_at DESC")
        return [dict(row) for row in cur.fetchall()]

    def list_notes(self, incident_id: int) -> List[Dict[str, Any]]:
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM incident_notes WHERE incident_id = ? ORDER BY created_at DESC", (incident_id,))
        return [dict(row) for row in cur.fetchall()]

    # Attachments
    def add_attachment(self, incident_id: int, name: str, path: str, created_at: str) -> None:
        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO incident_attachments (incident_id, name, path, created_at) VALUES (?, ?, ?, ?)",
            (incident_id, name, path, created_at),
        )
        self.conn.commit()

    def list_attachments(self, incident_id: int) -> List[Dict[str, Any]]:
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM incident_attachments WHERE incident_id = ? ORDER BY created_at DESC", (incident_id,))
        return [dict(row) for row in cur.fetchall()]

    # Vulnerabilities
    def list_vulnerabilities(self) -> List[Dict[str, Any]]:
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM vulnerabilities ORDER BY detected_at DESC")
        return [dict(row) for row in cur.fetchall()]

    # FIM events
    def recent_fim_events(self, limit: int = 200) -> List[Dict[str, Any]]:
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM fim_events ORDER BY timestamp DESC LIMIT ?", (limit,))
        return [dict(row) for row in cur.fetchall()]

    # Ingestion queue
    def enqueue_event(self, payload: str, status: str, source: str) -> None:
        cur = self.conn.cursor()
        cur.execute("INSERT INTO ingestion_queue (received_at, payload, status, source) VALUES (datetime('now'), ?, ?, ?)", (payload, status, source))
        self.conn.commit()

    def fetch_queue(self, status: str = "pending", limit: int = 100) -> List[Dict[str, Any]]:
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM ingestion_queue WHERE status = ? ORDER BY received_at ASC LIMIT ?", (status, limit))
        return [dict(row) for row in cur.fetchall()]

    def update_queue_status(self, queue_id: int, status: str) -> None:
        cur = self.conn.cursor()
        cur.execute("UPDATE ingestion_queue SET status = ? WHERE id = ?", (status, queue_id))
        self.conn.commit()
