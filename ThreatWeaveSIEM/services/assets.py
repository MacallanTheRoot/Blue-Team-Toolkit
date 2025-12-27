"""Asset inventory service: discovery simulation and scoring."""
from __future__ import annotations
from datetime import datetime
from typing import List, Dict
import random

class AssetService:
    def __init__(self, repo):
        self.repo = repo

    def simulate_discovery(self) -> List[Dict]:
        assets = []
        os_types = ["Linux", "Windows", "macOS", "Network"]
        for i in range(1, 8):
            hostname = f"host{i:02d}"
            ip = f"10.0.0.{i}"
            os = random.choice(os_types)
            importance = random.randint(1, 10)
            health = random.randint(60, 100)
            risk = max(0, 100 - health + importance * 3)
            asset = {
                "id": i,
                "hostname": hostname,
                "ip": ip,
                "os": os,
                "tags": "prod" if importance > 7 else "dev",
                "importance": importance,
                "last_seen": datetime.now().isoformat(),
                "health": health,
                "risk": risk,
            }
            self.repo.upsert_asset(asset)
            assets.append(asset)
        return assets

    def list_assets(self) -> List[Dict]:
        """Return all assets ordered by importance/recency."""
        return self.repo.list_assets()
