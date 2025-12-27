"""SOC Analyst destekli ek özellikler: Alert triage, hunting, playbook."""
from __future__ import annotations
from datetime import datetime
from typing import Dict, List
import pandas as pd

class AlertTriageService:
    """Alert önceliklendirme ve triage servisi."""
    
    def __init__(self, repo):
        self.repo = repo
    
    def prioritize_alerts(self, df: pd.DataFrame) -> pd.DataFrame:
        """Alertleri önceliklendir ve triage skoru hesapla."""
        if df.empty:
            return df
        
        df = df.copy()
        # Basit triage skoru: severity + risk_score kombinasyonu
        severity_weight = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        df["severity_weight"] = df["severity"].map(severity_weight).fillna(1)
        df["triage_score"] = (df["severity_weight"] * 25 + df["risk_score"]) / 2
        df = df.sort_values("triage_score", ascending=False)
        return df
    
    def acknowledge_alert(self, log_id: int, analyst: str) -> None:
        """Alert onaylandı olarak işaretle."""
        # Basit implementasyon - gelecekte alert durumu için tablo eklenebilir
        pass


class ThreatHuntingService:
    """Proaktif tehdit avı servisi."""
    
    def __init__(self, repo):
        self.repo = repo
    
    def hunt_by_ioc(self, ioc: str, ioc_type: str = "ip") -> List[Dict]:
        """IOC bazlı hunting."""
        logs = self.repo.get_logs(limit=10000)
        results = []
        for log in logs:
            if ioc_type == "ip" and ioc in str(log.get("ip", "")):
                results.append(log)
            elif ioc_type == "hash" and ioc in str(log.get("msg", "")):
                results.append(log)
            elif ioc_type == "domain" and ioc in str(log.get("msg", "")):
                results.append(log)
        return results
    
    def hunt_suspicious_patterns(self, df: pd.DataFrame) -> Dict:
        """Şüpheli desenler ara."""
        if df.empty:
            return {}
        
        findings = {}
        
        # Aynı IP'den yüksek hacimli aktivite
        ip_counts = df["ip"].value_counts()
        suspicious_ips = ip_counts[ip_counts > 50].to_dict()
        if suspicious_ips:
            findings["high_volume_ips"] = suspicious_ips
        
        # Kısa sürede çok fazla failed login
        failed = df[df["msg"].str.contains("failed", case=False, na=False)]
        if len(failed) > 10:
            findings["failed_login_spike"] = len(failed)
        
        # Gece saatlerinde aktivite
        df["hour"] = pd.to_datetime(df["timestamp"]).dt.hour
        night_activity = df[(df["hour"] >= 22) | (df["hour"] <= 6)]
        if len(night_activity) > 0:
            findings["night_activity_count"] = len(night_activity)
        
        return findings


class PlaybookService:
    """Olay müdahale playbook'ları."""
    
    PLAYBOOKS = {
        "malware_detected": {
            "title": "Malware Tespit Edildi",
            "steps": [
                "1. İlgili makineyi ağdan izole et",
                "2. Volatilite analizi için RAM dump al",
                "3. Disk imajı oluştur",
                "4. IOC'leri çıkar ve TI platformlarında ara",
                "5. Diğer sistemlerde IOC taraması yap",
                "6. Etkilenen kullanıcı hesaplarını askıya al",
                "7. Incident kaydı oluştur ve yönetimi bilgilendir"
            ]
        },
        "data_exfiltration": {
            "title": "Veri Sızıntısı Şüphesi",
            "steps": [
                "1. Ağ trafiğini yakala ve analiz et",
                "2. Şüpheli bağlantıları kes",
                "3. Kullanıcı hesabını dondur",
                "4. DLP loglarını incele",
                "5. Hangi verilerin sızdığını tespit et",
                "6. Yasal ekibi bilgilendir",
                "7. Post-mortem raporu hazırla"
            ]
        },
        "brute_force_attack": {
            "title": "Brute Force Saldırısı",
            "steps": [
                "1. Kaynak IP'yi firewall'da engelle",
                "2. Hedef hesabı geçici kilitle",
                "3. Başarılı login olup olmadığını kontrol et",
                "4. MFA zorunluluğunu kontrol et",
                "5. Şifre sıfırlama prosedürünü başlat",
                "6. Benzer saldırılar için tarama yap"
            ]
        },
        "ransomware": {
            "title": "Ransomware Saldırısı",
            "steps": [
                "1. Etkilenen sistemleri hemen ağdan ayır",
                "2. Backup sistemlerini izole et",
                "3. Domain controller'ları koru",
                "4. Antivirüs/EDR taraması başlat",
                "5. Yayılma vektörünü belirle",
                "6. Kripto krizi ekibini aktive et",
                "7. Backup'tan restore planı hazırla",
                "8. FBI/siber güvenlik otoritelerini bilgilendir"
            ]
        }
    }
    
    def get_playbook(self, scenario: str) -> Dict:
        """Senaryo için playbook getir."""
        return self.PLAYBOOKS.get(scenario, {
            "title": "Genel Olay Müdahalesi",
            "steps": [
                "1. Olayı doğrula",
                "2. Kapsamı belirle",
                "3. Containment yap",
                "4. Kök neden analizi",
                "5. Eradication",
                "6. Recovery",
                "7. Lessons learned"
            ]
        })
    
    def list_playbooks(self) -> List[str]:
        """Mevcut playbook'ları listele."""
        return list(self.PLAYBOOKS.keys())


class MetricsService:
    """SOC metrikleri ve KPI servisi."""
    
    def __init__(self, repo):
        self.repo = repo
    
    def calculate_kpis(self, df: pd.DataFrame) -> Dict:
        """Temel SOC KPI'larını hesapla."""
        if df.empty:
            return {}
        
        kpis = {}
        
        # Mean Time to Detect (MTTD) - simulated
        kpis["total_events"] = len(df)
        kpis["critical_events"] = len(df[df["severity"] == "critical"])
        kpis["high_events"] = len(df[df["severity"] == "high"])
        
        # Event distribution by severity
        kpis["severity_distribution"] = df["severity"].value_counts().to_dict()
        
        # Top sources
        kpis["top_sources"] = df["source"].value_counts().head(5).to_dict()
        
        # Average risk score
        kpis["avg_risk_score"] = float(df["risk_score"].mean())
        kpis["max_risk_score"] = int(df["risk_score"].max())
        
        return kpis
