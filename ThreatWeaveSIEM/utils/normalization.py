"""Normalization helpers for logs."""
from __future__ import annotations
from typing import Dict

SEVERITY_MAP = {"crit": "critical", "err": "high", "warn": "medium", "info": "low"}

def normalize_log(log: Dict) -> Dict:
    sev = (log.get("severity") or "").lower()
    log["severity"] = SEVERITY_MAP.get(sev, sev or "medium")
    log.setdefault("risk_score", 0)
    log.setdefault("timestamp", log.get("ts") or "")
    log.setdefault("source", log.get("host") or log.get("source") or "unknown")
    log.setdefault("ip", log.get("ip") or "unknown")
    log.setdefault("msg", log.get("msg") or "")
    return log
