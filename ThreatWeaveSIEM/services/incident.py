"""Incident response workflows: timeline, notes, attachments."""
from __future__ import annotations
from datetime import datetime
from typing import Dict, List

class IncidentService:
    def __init__(self, repo):
        self.repo = repo

    def create(self, title: str, severity: str, tags: str = "") -> int:
        now = datetime.now().isoformat()
        return self.repo.create_incident({"title": title, "severity": severity, "created_at": now, "updated_at": now, "tags": tags, "status": "open"})

    def add_note(self, incident_id: int, author: str, note: str) -> None:
        self.repo.add_note(incident_id, {"author": author, "note": note, "created_at": datetime.now().isoformat()})

    def add_attachment(self, incident_id: int, name: str, path: str) -> None:
        self.repo.add_attachment(incident_id, name, path, datetime.now().isoformat())

    def list(self) -> List[Dict]:
        return self.repo.list_incidents()

    def notes(self, incident_id: int) -> List[Dict]:
        return self.repo.list_notes(incident_id)

    def attachments(self, incident_id: int) -> List[Dict]:
        return self.repo.list_attachments(incident_id)
