"""Event ingestion pipeline service with queueing and normalization."""
from __future__ import annotations
import json
from typing import Dict, List
from utils.normalization import normalize_log

class IngestionService:
    def __init__(self, repo):
        self.repo = repo

    def ingest(self, log: Dict, source: str = "api") -> None:
        normalized = normalize_log(log)
        payload = json.dumps(normalized)
        self.repo.enqueue_event(payload, status="pending", source=source)

    def flush(self, limit: int = 100) -> int:
        processed = 0
        for item in self.repo.fetch_queue(status="pending", limit=limit):
            try:
                log = json.loads(item["payload"])
                self.repo.insert_log(log)
                self.repo.update_queue_status(item["id"], "processed")
                processed += 1
            except Exception:
                self.repo.update_queue_status(item["id"], "error")
        return processed
