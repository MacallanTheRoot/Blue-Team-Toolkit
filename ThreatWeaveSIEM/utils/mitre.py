"""MITRE ATT&CK mapping helpers."""
from __future__ import annotations
from typing import Dict

MITRE_MAP: Dict[str, str] = {
    "failed login": "T1078 - Valid Accounts",
    "port scan": "T1046 - Network Service Discovery",
    "lateral": "T1021 - Lateral Movement",
}

def map_msg_to_technique(msg: str) -> str:
    if not msg:
        return "Unknown Technique"
    for k, v in MITRE_MAP.items():
        if k in msg.lower():
            return v
    return "Unknown Technique"
