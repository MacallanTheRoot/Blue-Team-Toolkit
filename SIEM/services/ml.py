"""ML-based anomaly detection service (IsolationForest fallback to z-score)."""
from __future__ import annotations
import pandas as pd
from typing import Dict

try:
    from sklearn.ensemble import IsolationForest
except Exception:  # optional
    IsolationForest = None

class AnomalyDetectionService:
    def __init__(self, contamination: float = 0.05):
        self.contamination = contamination

    def score(self, df: pd.DataFrame) -> pd.DataFrame:
        if df.empty:
            return pd.DataFrame()
        features = df[["risk_score"]].copy()
        if IsolationForest:
            model = IsolationForest(contamination=self.contamination, random_state=42)
            preds = model.fit_predict(features)
            df = df.copy()
            df["anomaly"] = preds == -1
            return df
        # fallback simple z-score
        mean = features["risk_score"].mean()
        std = features["risk_score"].std() or 1
        df = df.copy()
        df["anomaly"] = (df["risk_score"] - mean).abs() > 3 * std
        return df

    def summarize(self, scored: pd.DataFrame) -> Dict:
        if scored.empty:
            return {"anomalies": 0}
        return {"anomalies": int(scored["anomaly"].sum())}
