"""File Integrity Monitoring service: incremental scan, baseline regen, diff, export."""
from __future__ import annotations
import os
import hashlib
from datetime import datetime
from typing import List, Dict

class FIMService:
    def __init__(self, conn, root: str):
        self.conn = conn
        self.root = root

    def _sha256(self, path: str) -> str | None:
        try:
            h = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return None

    def baseline_regen(self, target_dirs: List[str] = None) -> List[Dict]:
        """Scan directories for changes. If target_dirs is None, scan self.root."""
        cur = self.conn.cursor()
        report: List[Dict] = []
        
        dirs_to_scan = target_dirs if target_dirs else [self.root]
        
        for scan_root in dirs_to_scan:
            if not os.path.exists(scan_root):
                continue
            for root, _, files in os.walk(scan_root):
                for name in files:
                    full = os.path.join(root, name)
                    h = self._sha256(full)
                    cur.execute("SELECT hash FROM fim_baseline WHERE path = ?", (full,))
                    row = cur.fetchone()
                    if row is None:
                        cur.execute("INSERT INTO fim_baseline (path, hash, last_seen) VALUES (?, ?, ?)", (full, h, datetime.now().isoformat()))
                        report.append({"path": full, "status": "CREATED", "old_hash": None, "new_hash": h})
                    elif row[0] != h:
                        cur.execute("UPDATE fim_baseline SET hash = ?, last_seen = ? WHERE path = ?", (h, datetime.now().isoformat(), full))
                        report.append({"path": full, "status": "MODIFIED", "old_hash": row[0], "new_hash": h})
        self.conn.commit()
        # deletions
        cur.execute("SELECT path, hash FROM fim_baseline")
        for row in cur.fetchall():
            path = row[0]
            if not os.path.exists(path):
                cur.execute("DELETE FROM fim_baseline WHERE path = ?", (path,))
                report.append({"path": path, "status": "DELETED", "old_hash": row[1], "new_hash": None})
        self.conn.commit()
        # persist events
        cur.executemany(
            "INSERT INTO fim_events (timestamp, path, status, old_hash, new_hash) VALUES (?, ?, ?, ?, ?)",
            [ (datetime.now().isoformat(), r["path"], r["status"], r.get("old_hash"), r.get("new_hash")) for r in report ]
        )
        self.conn.commit()
        return report

    def export_report(self, events: List[Dict], out_path: str) -> str:
        import json
        with open(out_path, "w") as f:
            json.dump(events, f, indent=2)
        return out_path
