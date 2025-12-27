"""ThreatWeave için merkezi konfigürasyon yönetimi.
DB yolu, API anahtarları, risk eşikleri ve özellik ayarlarını yükler ve saklar.
"""
from __future__ import annotations
import json
import os
from dataclasses import dataclass, asdict

DEFAULT_CONFIG = {
    "db_type": "sqlite",  # sqlite | postgres
    "db_path": "siem_logs.db",
    "postgres_dsn": "postgresql://user:pass@localhost:5432/siem",
    "fim_path": os.getcwd(),
    "fim_enabled": True,
    "fim_watched_dirs": [],
    "risk_threshold": 75,
    "abuseipdb_key": "",
    "otx_key": "",
    "virustotal_key": "",
    "auto_seed_demo": True,
}

CONFIG_FILE = "siem_config.json"

@dataclass
class SIEMConfig:
    db_type: str = DEFAULT_CONFIG["db_type"]
    db_path: str = DEFAULT_CONFIG["db_path"]
    postgres_dsn: str = DEFAULT_CONFIG["postgres_dsn"]
    fim_path: str = DEFAULT_CONFIG["fim_path"]
    fim_enabled: bool = DEFAULT_CONFIG["fim_enabled"]
    fim_watched_dirs: list = None
    risk_threshold: int = DEFAULT_CONFIG["risk_threshold"]
    abuseipdb_key: str = DEFAULT_CONFIG["abuseipdb_key"]
    otx_key: str = DEFAULT_CONFIG["otx_key"]
    virustotal_key: str = DEFAULT_CONFIG["virustotal_key"]
    auto_seed_demo: bool = DEFAULT_CONFIG["auto_seed_demo"]

    def __post_init__(self):
        if self.fim_watched_dirs is None:
            self.fim_watched_dirs = []

    @classmethod
    def load(cls) -> "SIEMConfig":
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, "r") as f:
                data = json.load(f)
            merged = {**DEFAULT_CONFIG, **data}
            return cls(**merged)
        return cls()

    def save(self) -> None:
        with open(CONFIG_FILE, "w") as f:
            json.dump(asdict(self), f, indent=4)
