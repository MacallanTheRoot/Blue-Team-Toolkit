"""Analytics: severity heatmap, risk trends, simple anomaly detection."""
from __future__ import annotations
import pandas as pd

class AnalyticsService:
    def severity_heatmap(self, df: pd.DataFrame, time_col: str = "timestamp", sev_col: str = "severity") -> pd.DataFrame:
        if df.empty:
            return pd.DataFrame()
        df["hour"] = pd.to_datetime(df[time_col]).dt.floor("h")
        pivot = df.pivot_table(index="hour", columns=sev_col, values="risk_score", aggfunc="count", fill_value=0)
        return pivot

    def risk_trend(self, df: pd.DataFrame) -> pd.DataFrame:
        if df.empty:
            return pd.DataFrame()
        df["ts"] = pd.to_datetime(df["timestamp"]).dt.floor("min")
        trend = df.groupby("ts")["risk_score"].sum().reset_index()
        return trend

    def zscore_anomalies(self, df: pd.DataFrame, window: int = 30) -> pd.DataFrame:
        if df.empty:
            return pd.DataFrame()
        trend = self.risk_trend(df)
        if trend.empty:
            return pd.DataFrame()
        s = trend["risk_score"].rolling(window, min_periods=5).mean()
        sd = trend["risk_score"].rolling(window, min_periods=5).std()
        z = (trend["risk_score"] - s) / sd
        trend["zscore"] = z.fillna(0)
        return trend
