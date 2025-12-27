"""Rule-based detection using YAML rules."""
from __future__ import annotations
import yaml
import pandas as pd
from typing import List, Dict

class RulesEngine:
    def __init__(self, rules_path: str):
        self.rules_path = rules_path
        self.rules: List[Dict] = []
        try:
            with open(self.rules_path, "r") as f:
                data = yaml.safe_load(f) or {}
                self.rules = data.get("rules", [])
        except Exception:
            self.rules = []

    def evaluate(self, df: pd.DataFrame) -> List[Dict]:
        findings: List[Dict] = []
        for rule in self.rules:
            field = rule.get("field")
            contains = rule.get("contains", "")
            severity = rule.get("severity", "medium")
            name = rule.get("name", "rule")
            if field in df.columns:
                hits = df[df[field].str.contains(contains, case=False, na=False)]
                for _, row in hits.iterrows():
                    findings.append({"rule": name, "severity": severity, "timestamp": row.get("timestamp"), "ip": row.get("ip"), "msg": row.get("msg")})
        return findings
