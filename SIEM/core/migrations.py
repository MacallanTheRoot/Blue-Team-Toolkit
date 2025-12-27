"""SIEM için şema başlatma ve migration'lar."""
from __future__ import annotations
import sqlite3
from typing import Iterable

MIGRATIONS: Iterable[str] = [
    # versiyon 1: temel tablolar
    """
    CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY);
    """,
    """
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY,
        timestamp TEXT,
        severity TEXT,
        source TEXT,
        ip TEXT,
        msg TEXT,
        risk_score INTEGER DEFAULT 0
    );
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp);
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_logs_severity ON logs(severity);
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_logs_ip ON logs(ip);
    """,
    # FIM
    """
    CREATE TABLE IF NOT EXISTS fim_baseline (
        path TEXT PRIMARY KEY,
        hash TEXT,
        last_seen TEXT
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS fim_events (
        id INTEGER PRIMARY KEY,
        timestamp TEXT,
        path TEXT,
        status TEXT, -- CREATED | MODIFIED | DELETED
        old_hash TEXT,
        new_hash TEXT
    );
    """,
    # Tehdit istihbaratı önbelleği
    """
    CREATE TABLE IF NOT EXISTS ti_cache (
        indicator TEXT PRIMARY KEY,
        type TEXT,
        status TEXT,
        score INTEGER,
        first_seen TEXT,
        last_seen TEXT,
        source TEXT
    );
    """,
    # Varlıklar
    """
    CREATE TABLE IF NOT EXISTS assets (
        id INTEGER PRIMARY KEY,
        hostname TEXT,
        ip TEXT,
        os TEXT,
        tags TEXT,
        importance INTEGER,
        last_seen TEXT,
        health INTEGER,
        risk INTEGER
    );
    """,
    # Zafiyetler
    """
    CREATE TABLE IF NOT EXISTS vulnerabilities (
        id INTEGER PRIMARY KEY,
        asset_id INTEGER,
        cve TEXT,
        cvss REAL,
        cwe TEXT,
        description TEXT,
        severity TEXT,
        status TEXT,
        recommendation TEXT,
        detected_at TEXT
    );
    """,
    # Olaylar ve notlar
    """
    CREATE TABLE IF NOT EXISTS incidents (
        id INTEGER PRIMARY KEY,
        title TEXT,
        severity TEXT,
        status TEXT,
        created_at TEXT,
        updated_at TEXT,
        tags TEXT
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS incident_notes (
        id INTEGER PRIMARY KEY,
        incident_id INTEGER,
        author TEXT,
        note TEXT,
        created_at TEXT
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS incident_attachments (
        id INTEGER PRIMARY KEY,
        incident_id INTEGER,
        name TEXT,
        path TEXT,
        created_at TEXT
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ingestion_queue (
        id INTEGER PRIMARY KEY,
        received_at TEXT,
        payload TEXT,
        status TEXT,
        source TEXT
    );
    """,
]

def run_sqlite_migrations(conn: sqlite3.Connection) -> None:
    cur = conn.cursor()
    # Temel migration'ları çalıştır, eski DB'lere izin vermek için hataları yoksay
    for stmt in MIGRATIONS:
        try:
            cur.execute(stmt)
        except Exception:
            pass

    # Eski tabloların gerekli sütunlara sahip olduğundan emin ol
    required_log_columns = {
        "timestamp": "TEXT",
        "severity": "TEXT",
        "source": "TEXT",
        "ip": "TEXT",
        "msg": "TEXT",
        "risk_score": "INTEGER DEFAULT 0",
    }
    cur.execute("PRAGMA table_info(logs)")
    existing = {row[1] for row in cur.fetchall()}
    for col, col_type in required_log_columns.items():
        if col not in existing:
            cur.execute(f"ALTER TABLE logs ADD COLUMN {col} {col_type}")

    # Sütunlar garanti edildikten sonra indeksleri yeniden oluştur
    index_statements = [
        "CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp)",
        "CREATE INDEX IF NOT EXISTS idx_logs_severity ON logs(severity)",
        "CREATE INDEX IF NOT EXISTS idx_logs_ip ON logs(ip)",
    ]
    for stmt in index_statements:
        try:
            cur.execute(stmt)
        except Exception:
            pass
    conn.commit()
