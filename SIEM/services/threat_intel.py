"""Threat Intelligence multi-source enrichment with caching."""
from __future__ import annotations
from datetime import datetime
from typing import Dict
import requests

class ThreatIntelService:
    def __init__(self, repo, abuse_key: str = "", otx_key: str = "", vt_key: str = ""):
        self.repo = repo
        self.abuse_key = abuse_key
        self.otx_key = otx_key
        self.vt_key = vt_key

    def enrich_ip(self, ip: str) -> Dict:
        # Mockable sources; fall back to demo when keys missing
        result = {"indicator": ip, "type": "ip", "status": "TEMIZ", "score": 0, "source": "local", "first_seen": datetime.now().isoformat(), "last_seen": datetime.now().isoformat()}
        malicious_pool = {"192.168.1.50": 80, "45.33.22.11": 75, "185.234.10.5": 90}
        if ip in malicious_pool:
            result.update({"status": "ZARARLI", "score": malicious_pool[ip], "source": "demo"})
        # AbuseIPDB
        if self.abuse_key:
            try:
                res = requests.get("https://api.abuseipdb.com/api/v2/check", params={"ipAddress": ip}, headers={"Key": self.abuse_key, "Accept": "application/json"}, timeout=5)
                data = res.json().get("data", {})
                score = int(data.get("abuseConfidenceScore", 0))
                result.update({"score": max(result["score"], score), "status": "ZARARLI" if score > 50 else result["status"], "source": "abuseipdb"})
            except Exception:
                pass
        # AlienVault OTX (mocked)
        if self.otx_key:
            pass
        # VirusTotal (mocked)
        if self.vt_key:
            pass
        self.repo.upsert_ti(result)
        return result
