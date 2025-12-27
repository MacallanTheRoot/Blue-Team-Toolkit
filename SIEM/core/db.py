"""SQLite ve opsiyonel Postgres için veritabanı bağlantı yardımcıları."""
from __future__ import annotations
import sqlite3
from typing import Any, Iterable, Optional

try:
    import psycopg
except Exception:  # opsiyonel
    psycopg = None

class SQLiteDB:
    def __init__(self, path: str):
        self.path = path

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def execute(self, query: str, params: Optional[Iterable[Any]] = None):
        with self.connect() as conn:
            cur = conn.cursor()
            cur.execute(query, params or [])
            conn.commit()
            return cur

class PostgresDB:
    def __init__(self, dsn: str):
        if psycopg is None:
            raise RuntimeError("psycopg yüklü değil; Postgres kullanmak için yükleyin")
        self.dsn = dsn

    def connect(self):
        return psycopg.connect(self.dsn)
