"""Vulnerability scanning service (simulated) with CVE metadata and recommendations."""
from __future__ import annotations
from datetime import datetime
from typing import List, Dict

VULN_KB = [
    {"cve": "CVE-2021-41773", "cvss": 7.5, "cwe": "CWE-22", "description": "Apache path traversal", "recommendation": "Upgrade Apache to 2.4.50+", "severity": "high"},
    {"cve": "CVE-2023-12345", "cvss": 9.1, "cwe": "CWE-787", "description": "Buffer overflow in service X", "recommendation": "Apply vendor patch", "severity": "critical"},
]

class VulnerabilityService:
    def __init__(self, conn):
        self.conn = conn

    def scan_assets(self, asset_ids: List[int]) -> List[Dict]:
        cur = self.conn.cursor()
        findings: List[Dict] = []
        for aid in asset_ids:
            for v in VULN_KB:
                f = {
                    "asset_id": aid,
                    "cve": v["cve"],
                    "cvss": v["cvss"],
                    "cwe": v["cwe"],
                    "description": v["description"],
                    "severity": v["severity"],
                    "status": "open",
                    "recommendation": v["recommendation"],
                    "detected_at": datetime.now().isoformat(),
                }
                cur.execute(
                    "INSERT INTO vulnerabilities (asset_id, cve, cvss, cwe, description, severity, status, recommendation, detected_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (f["asset_id"], f["cve"], f["cvss"], f["cwe"], f["description"], f["severity"], f["status"], f["recommendation"], f["detected_at"]),
                )
                findings.append(f)
        self.conn.commit()
        return findings
