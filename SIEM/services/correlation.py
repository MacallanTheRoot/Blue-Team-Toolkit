"""Simple correlation rules: failed logins, port scans, lateral movement."""
from __future__ import annotations
import pandas as pd

class CorrelationService:
    def detect_failed_logins(self, df: pd.DataFrame) -> pd.DataFrame:
        if df.empty:
            return pd.DataFrame()
        failed = df[df["msg"].str.contains("failed login", case=False, na=False)]
        return failed

    def detect_port_scans(self, df: pd.DataFrame) -> pd.DataFrame:
        if df.empty:
            return pd.DataFrame()
        scans = df[df["msg"].str.contains("port scan", case=False, na=False)]
        return scans

    def detect_lateral_movement(self, df: pd.DataFrame) -> pd.DataFrame:
        if df.empty:
            return pd.DataFrame()
        lateral = df[df["msg"].str.contains("lateral", case=False, na=False)]
        return lateral
