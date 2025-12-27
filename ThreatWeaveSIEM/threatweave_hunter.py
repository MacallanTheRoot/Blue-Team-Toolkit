#!/usr/bin/env python3
"""
ThreatWeave SIEM - Log Analiz & Tehdit Avcısı
Kurumsal Düzeyde Güvenlik Bilgi ve Olay Yönetimi Sistemi

Özellikler:
- Çoklu format log ayrıştırma (Syslog, Windows Event, Apache, Nginx, Auth, JSON)
- Tehdit tespiti için Sigma kural motoru
- ML tabanlı anomali tespiti (Isolation Forest)
- Özel sorgularla gelişmiş tehdit avı
- IOC tespiti (IP'ler, domainler, hash'ler, e-postalar)
- MITRE ATT&CK framework haritalama
- Gerçek zamanlı log izleme
- Alert korelasyonu ve önceliklendirme
- Zaman çizelgesi analizi
- Otomatik tehdit istihbaratı

Yazar: Macallan (Blue Team)
"""

import os
import sys
import json
import re
import sqlite3
import hashlib
import argparse
import yaml
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from collections import defaultdict, Counter
import threading
import queue
import time

# Machine Learning imports
try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    import numpy as np
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    print("[⚠️] scikit-learn mevcut değil. ML özellikleri devre dışı. Kurulum: pip install scikit-learn numpy")


class Colors:
    """Terminal çıktısı için ANSI renk kodları"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'


class LogParser:
    """Çeşitli log tiplerini destekleyen çoklu format log ayrıştırıcı"""
    
    def __init__(self):
        # Syslog paterni: Jan 1 00:00:00 hostname process[pid]: message
        self.syslog_pattern = re.compile(
            r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+'
            r'(?P<hostname>\S+)\s+'
            r'(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?\s*:\s*'
            r'(?P<message>.*)'
        )
        
        # Apache/Nginx access log: IP - - [timestamp] "method path protocol" status size "referer" "user-agent"
        self.apache_pattern = re.compile(
            r'(?P<ip>\S+)\s+-\s+-\s+\[(?P<timestamp>[^\]]+)\]\s+'
            r'"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<protocol>[^"]+)"\s+'
            r'(?P<status>\d+)\s+(?P<size>\S+)\s+'
            r'"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)"'
        )
        
        # Auth log patterns
        self.auth_failed_pattern = re.compile(
            r'Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)'
        )
        self.auth_success_pattern = re.compile(
            r'Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\S+)'
        )
        
        # Windows Event Log patterns (simplified)
        self.windows_pattern = re.compile(
            r'EventID:\s*(?P<event_id>\d+).*?'
            r'Level:\s*(?P<level>\S+).*?'
            r'Source:\s*(?P<source>[^,\n]+)',
            re.DOTALL
        )
        
        # IOC patterns
        self.ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        self.domain_pattern = re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b')
        self.email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
        self.hash_md5_pattern = re.compile(r'\b[a-fA-F0-9]{32}\b')
        self.hash_sha256_pattern = re.compile(r'\b[a-fA-F0-9]{64}\b')
    
    def parse_log(self, log_line: str, log_type: str = 'auto') -> Optional[Dict[str, Any]]:
        """Log satırını ayrıştır ve yapılandırılmış veri çıkar"""
        log_line = log_line.strip()
        if not log_line:
            return None
        
        # Try to parse as JSON first
        if log_line.startswith('{'):
            try:
                return json.loads(log_line)
            except json.JSONDecodeError:
                pass
        
        # Auto-detect log type
        if log_type == 'auto':
            log_type = self._detect_log_type(log_line)
        
        # Parse based on type
        if log_type == 'syslog':
            return self._parse_syslog(log_line)
        elif log_type == 'apache' or log_type == 'nginx':
            return self._parse_apache(log_line)
        elif log_type == 'auth':
            return self._parse_auth(log_line)
        elif log_type == 'windows':
            return self._parse_windows(log_line)
        else:
            return self._parse_generic(log_line)
    
    def _detect_log_type(self, log_line: str) -> str:
        """Log tipini otomatik tespit et"""
        if 'EventID:' in log_line or 'Event ID' in log_line:
            return 'windows'
        if self.apache_pattern.search(log_line):
            return 'apache'
        if 'Failed password' in log_line or 'Accepted password' in log_line:
            return 'auth'
        if self.syslog_pattern.search(log_line):
            return 'syslog'
        return 'generic'
    
    def _parse_syslog(self, log_line: str) -> Dict[str, Any]:
        """Syslog formatını ayrıştır"""
        match = self.syslog_pattern.search(log_line)
        if match:
            data = match.groupdict()
            data['log_type'] = 'syslog'
            data['raw'] = log_line
            data['iocs'] = self.extract_iocs(log_line)
            return data
        return self._parse_generic(log_line)
    
    def _parse_apache(self, log_line: str) -> Dict[str, Any]:
        """Apache/Nginx erişim logu ayrıştır"""
        match = self.apache_pattern.search(log_line)
        if match:
            data = match.groupdict()
            data['log_type'] = 'apache'
            data['raw'] = log_line
            data['iocs'] = self.extract_iocs(log_line)
            data['status_code'] = int(data.get('status', 0))
            return data
        return self._parse_generic(log_line)
    
    def _parse_auth(self, log_line: str) -> Dict[str, Any]:
        """Kimlik doğrulama loglarını ayrıştır"""
        data = {'log_type': 'auth', 'raw': log_line}
        
        # Check for failed login
        match = self.auth_failed_pattern.search(log_line)
        if match:
            data.update(match.groupdict())
            data['auth_result'] = 'failed'
            data['severity'] = 'high'
        else:
            # Check for successful login
            match = self.auth_success_pattern.search(log_line)
            if match:
                data.update(match.groupdict())
                data['auth_result'] = 'success'
                data['severity'] = 'info'
        
        data['iocs'] = self.extract_iocs(log_line)
        return data
    
    def _parse_windows(self, log_line: str) -> Dict[str, Any]:
        """Windows Event Log ayrıştır"""
        match = self.windows_pattern.search(log_line)
        if match:
            data = match.groupdict()
            data['log_type'] = 'windows'
            data['raw'] = log_line
            data['iocs'] = self.extract_iocs(log_line)
            return data
        return self._parse_generic(log_line)
    
    def _parse_generic(self, log_line: str) -> Dict[str, Any]:
        """Bilinmeyen formatlar için genel ayrıştırıcı"""
        return {
            'log_type': 'generic',
            'raw': log_line,
            'message': log_line,
            'iocs': self.extract_iocs(log_line),
            'timestamp': datetime.now().isoformat()
        }
    
    def extract_iocs(self, text: str) -> Dict[str, List[str]]:
        """Metinden İhlal Göstergelerini (IOC) çıkar"""
        iocs = {
            'ips': list(set(self.ip_pattern.findall(text))),
            'domains': list(set(self.domain_pattern.findall(text))),
            'emails': list(set(self.email_pattern.findall(text))),
            'md5': list(set(self.hash_md5_pattern.findall(text))),
            'sha256': list(set(self.hash_sha256_pattern.findall(text)))
        }
        # Filter out false positives
        # Yanlış pozitifleri filtrele
        iocs['domains'] = [d for d in iocs['domains'] if not d.endswith('.log') and not d.endswith('.txt')]
        return iocs


class SigmaRuleEngine:
    """Tehdit tespiti için Sigma kural motoru"""

    def __init__(self, rules_dir: Optional[str] = None):
        self.rules: List[Dict[str, Any]] = []
        self.rules_dir = rules_dir
        if rules_dir and os.path.exists(rules_dir):
            self.load_rules(rules_dir)

    def load_rules(self, rules_dir: str):
        """Dizinden Sigma kurallarını yükle"""
        for root, _, files in os.walk(rules_dir):
            for file in files:
                if file.endswith(('.yml', '.yaml')):
                    rule_path = os.path.join(root, file)
                    try:
                        with open(rule_path, 'r') as f:
                            rule = yaml.safe_load(f)
                            if rule and 'detection' in rule:
                                self.rules.append(rule)
                    except Exception as e:
                        print(f"[⚠️] Kural yüklenemedi {rule_path}: {e}")

    def create_default_rules(self) -> List[Dict[str, Any]]:
        """Varsayılan tespit kuralları oluştur"""
        return [
            {
                'title': 'Multiple Failed Login Attempts',
                'description': 'Olası brute force saldırısını tespit eder',
                'level': 'high',
                'detection': {
                    'selection': {
                        'log_type': 'auth',
                        'auth_result': 'failed'
                    },
                    'condition': 'threshold',
                    'threshold': {'count': 5, 'timeframe': 300}
                },
                'mitre': ['T1110.001', 'T1110.003']
            },
            {
                'title': 'Suspicious HTTP Status Codes',
                'description': 'Web tarama/saldırı denemelerini tespit eder',
                'level': 'medium',
                'detection': {
                    'selection': {
                        'log_type': 'apache',
                        'status_code': [400, 401, 403, 404, 500, 503]
                    },
                    'condition': 'threshold',
                    'threshold': {'count': 10, 'timeframe': 60}
                },
                'mitre': ['T1595.002']
            },
            {
                'title': 'SQL Injection Attempt',
                'description': 'Web isteklerinde olası SQL injection tespit eder',
                'level': 'critical',
                'detection': {
                    'selection': {
                        'log_type': 'apache',
                        'path_contains': ['union', 'select', 'drop', 'insert', '--', 'or 1=1', 'or 1 = 1']
                    }
                },
                'mitre': ['T1190']
            },
            {
                'title': 'XSS Attempt',
                'description': 'Olası Cross-Site Scripting saldırısını tespit eder',
                'level': 'high',
                'detection': {
                    'selection': {
                        'log_type': 'apache',
                        'path_contains': ['<script>', 'javascript:', 'onerror=', 'onload=']
                    }
                },
                'mitre': ['T1189']
            },
            {
                'title': 'Suspicious User-Agent',
                'description': 'Bilinen kötü amaçlı veya tarama araçlarını tespit eder',
                'level': 'medium',
                'detection': {
                    'selection': {
                        'log_type': 'apache',
                        'user_agent_contains': ['sqlmap', 'nmap', 'nikto', 'masscan', 'metasploit', 'burp']
                    }
                },
                'mitre': ['T1595']
            },
            {
                'title': 'Privilege Escalation Attempt',
                'description': 'Sudo/su kullanım desenlerini tespit eder',
                'level': 'high',
                'detection': {
                    'selection': {
                        'log_type': 'auth',
                        'message_contains': ['sudo', 'su:', 'COMMAND=']
                    }
                },
                'mitre': ['T1548', 'T1078']
            },
            {
                'title': 'Lateral Movement',
                'description': 'SSH üzerinden olası yanal hareketi tespit eder',
                'level': 'medium',
                'detection': {
                    'selection': {
                        'log_type': 'auth',
                        'auth_result': 'success',
                        'source_internal': True
                    },
                    'condition': 'threshold',
                    'threshold': {'count': 3, 'timeframe': 600}
                },
                'mitre': ['T1021.004']
            }
        ]

    def match_rule(self, log_entry: Dict[str, Any], rule: Dict[str, Any]) -> bool:
        """Log kaydının Sigma kuralıyla eşleşip eşleşmediğini kontrol et"""
        detection = rule.get('detection', {})
        selection = detection.get('selection', {})

        for key, value in selection.items():
            if key.endswith('_contains'):
                field = key.replace('_contains', '')
                log_value = str(log_entry.get(field, '')).lower()
                if isinstance(value, list):
                    if not any(str(v).lower() in log_value for v in value):
                        return False
                elif str(value).lower() not in log_value:
                    return False
            else:
                if key not in log_entry:
                    return False
                if isinstance(value, list):
                    if log_entry[key] not in value:
                        return False
                elif log_entry[key] != value:
                    return False

        return True


class AnomalyDetector:
    """Isolation Forest kullanarak ML tabanlı anomali tespiti"""
    
    def __init__(self):
        self.model = None
        self.scaler = None
        self.trained = False
        self.feature_names = []
    
    def extract_features(self, logs: List[Dict[str, Any]]) -> np.ndarray:
        """ML için loglardan sayısal özellikler çıkar"""
        if not ML_AVAILABLE:
            return np.array([])
        
        features = []
        for log in logs:
            feature_vector = [
                len(log.get('raw', '')),
                len(log.get('iocs', {}).get('ips', [])),
                len(log.get('iocs', {}).get('domains', [])),
                log.get('status_code', 0),
                1 if log.get('auth_result') == 'failed' else 0,
                len(log.get('message', '')),
            ]
            features.append(feature_vector)
        
        return np.array(features)
    
    def train(self, logs: List[Dict[str, Any]], contamination: float = 0.1):
        """Anomali tespit modelini eğit"""
        if not ML_AVAILABLE:
            print("[⚠️] ML not available. Skipping training.")
            return
        
        features = self.extract_features(logs)
        if len(features) < 10:
            print("[⚠️] Not enough data to train anomaly detector (need at least 10 samples)")
            return
        
        self.scaler = StandardScaler()
        features_scaled = self.scaler.fit_transform(features)
        
        self.model = IsolationForest(contamination=contamination, random_state=42)
        self.model.fit(features_scaled)
        self.trained = True
        print(f"[✅] Anomaly detector trained on {len(features)} samples")
    
    def predict(self, logs: List[Dict[str, Any]]) -> List[bool]:
        """Loglardaki anomalileri tahmin et"""
        if not self.trained or not ML_AVAILABLE:
            return [False] * len(logs)
        
        features = self.extract_features(logs)
        features_scaled = self.scaler.transform(features)
        predictions = self.model.predict(features_scaled)
        return [pred == -1 for pred in predictions]


class ThreatHunter:
    """Özel sorgular ile gelişmiş tehdit avı"""
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.conn = None
    
    def connect(self):
        """Veritabanına bağlan"""
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
    
    def close(self):
        """Veritabanı bağlantısını kapat"""
        if self.conn:
            self.conn.close()
    
    def hunt_failed_logins_by_ip(self, min_attempts: int = 3) -> List[Dict]:
        """Birden fazla başarısız login denemesi olan IP'leri avla"""
        query = """
        SELECT 
            json_extract(data, '$.ip') as ip,
            COUNT(*) as attempt_count,
            MIN(timestamp) as first_seen,
            MAX(timestamp) as last_seen
        FROM logs
        WHERE json_extract(data, '$.auth_result') = 'failed'
        GROUP BY ip
        HAVING attempt_count >= ?
        ORDER BY attempt_count DESC
        """
        cursor = self.conn.execute(query, (min_attempts,))
        return [dict(row) for row in cursor.fetchall()]
    
    def hunt_suspicious_user_agents(self) -> List[Dict]:
        """User agent'larda bilinen saldırı araçlarını avla"""
        suspicious_ua = ['sqlmap', 'nmap', 'nikto', 'masscan', 'metasploit', 'burp', 'curl', 'wget', 'python-requests']
        results = []
        
        for ua in suspicious_ua:
            query = """
            SELECT 
                json_extract(data, '$.ip') as ip,
                json_extract(data, '$.user_agent') as user_agent,
                timestamp,
                data
            FROM logs
            WHERE json_extract(data, '$.user_agent') LIKE ?
            ORDER BY timestamp DESC
            LIMIT 100
            """
            cursor = self.conn.execute(query, (f'%{ua}%',))
            results.extend([dict(row) for row in cursor.fetchall()])
        
        return results
    
    def hunt_web_attacks(self) -> List[Dict]:
        """Web saldırı desenlerini avla"""
        patterns = ['union', 'select', '<script>', 'javascript:', '../', 'etc/passwd', 'cmd.exe']
        results = []
        
        for pattern in patterns:
            query = """
            SELECT 
                json_extract(data, '$.ip') as ip,
                json_extract(data, '$.path') as path,
                json_extract(data, '$.method') as method,
                timestamp,
                data
            FROM logs
            WHERE json_extract(data, '$.path') LIKE ?
            ORDER BY timestamp DESC
            LIMIT 50
            """
            cursor = self.conn.execute(query, (f'%{pattern}%',))
            results.extend([dict(row) for row in cursor.fetchall()])
        
        return results
    
    def hunt_privilege_escalation(self) -> List[Dict]:
        """Yetki yükseltme denemelerini avla"""
        query = """
        SELECT 
            json_extract(data, '$.user') as user,
            json_extract(data, '$.message') as message,
            timestamp,
            data
        FROM logs
        WHERE json_extract(data, '$.message') LIKE '%sudo%'
           OR json_extract(data, '$.message') LIKE '%su:%'
        ORDER BY timestamp DESC
        LIMIT 100
        """
        cursor = self.conn.execute(query)
        return [dict(row) for row in cursor.fetchall()]
    
    def timeline_analysis(self, hours: int = 24) -> Dict[str, List[Dict]]:
        """Son N saat için zaman çizelgesi analizi yap"""
        cutoff = (datetime.now() - timedelta(hours=hours)).isoformat()
        
        timeline = {
            'failed_logins': [],
            'successful_logins': [],
            'http_errors': [],
            'suspicious_activity': []
        }
        
        # Failed logins

        query = """
        SELECT * FROM logs
        WHERE timestamp > ?
        AND json_extract(data, '$.auth_result') = 'failed'
        ORDER BY timestamp
        """
        cursor = self.conn.execute(query, (cutoff,))
        timeline['failed_logins'] = [dict(row) for row in cursor.fetchall()]
        
        # Successful logins

        query = """
        SELECT * FROM logs
        WHERE timestamp > ?
        AND json_extract(data, '$.auth_result') = 'success'
        ORDER BY timestamp
        """
        cursor = self.conn.execute(query, (cutoff,))
        timeline['successful_logins'] = [dict(row) for row in cursor.fetchall()]
        
        # HTTP errors

        query = """
        SELECT * FROM logs
        WHERE timestamp > ?
        AND json_extract(data, '$.status_code') >= 400
        ORDER BY timestamp
        """
        cursor = self.conn.execute(query, (cutoff,))
        timeline['http_errors'] = [dict(row) for row in cursor.fetchall()]
        
        return timeline


class AlertManager:
    """Alert korelasyonu ve yönetimi"""
    
    def __init__(self):
        self.alerts = []
        self.alert_id = 0
    
    def create_alert(self, rule_title: str, log_entry: Dict, severity: str, mitre_ids: List[str] = None):
        """Yeni bir alert oluştur"""
        self.alert_id += 1
        alert = {
            'id': self.alert_id,
            'timestamp': datetime.now().isoformat(),
            'rule': rule_title,
            'severity': severity,
            'log_entry': log_entry,
            'mitre_tactics': mitre_ids or [],
            'status': 'new'
        }
        self.alerts.append(alert)
        return alert
    
    def get_alerts(self, severity: Optional[str] = None, limit: int = 100) -> List[Dict]:
        """Önem seviyesine göre filtrelenmiş alertleri getir"""
        filtered = self.alerts
        if severity:
            filtered = [a for a in self.alerts if a['severity'] == severity]
        return sorted(filtered, key=lambda x: x['timestamp'], reverse=True)[:limit]
    
    def print_alert(self, alert: Dict):
        """Alert'i formatlı şekilde yazdır"""
        severity_colors = {
            'critical': Colors.RED,
            'high': Colors.YELLOW,
            'medium': Colors.CYAN,
            'info': Colors.BLUE
        }
        color = severity_colors.get(alert['severity'], Colors.END)
        
        print(f"\n{color}{'='*80}{Colors.END}")
        print(f"{color}[🚨 ALERT #{alert['id']}] {alert['rule']}{Colors.END}")
        print(f"Severity: {color}{alert['severity'].upper()}{Colors.END}")
        print(f"Time: {alert['timestamp']}")
        if alert.get('mitre_tactics'):
            print(f"MITRE ATT&CK: {', '.join(alert['mitre_tactics'])}")
        print(f"\nLog Entry:")
        print(json.dumps(alert['log_entry'], indent=2))
        print(f"{color}{'='*80}{Colors.END}\n")


class ThreatWeaveDatabase:
    """Log depolama için SQLite veritabanı"""
    
    def __init__(self, db_path: str = 'threatweave_logs.db'):
        self.db_path = db_path
        self.conn = None
        self.init_db()
    
    def init_db(self):
        """Veritabanı şemasını başlat"""
        db_dir = os.path.dirname(self.db_path)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)
        
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                log_type TEXT,
                severity TEXT,
                data TEXT NOT NULL,
                hash TEXT UNIQUE,
                is_anomaly INTEGER DEFAULT 0
            )
        ''')
        self.conn.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON logs(timestamp)')
        self.conn.execute('CREATE INDEX IF NOT EXISTS idx_log_type ON logs(log_type)')
        self.conn.execute('CREATE INDEX IF NOT EXISTS idx_severity ON logs(severity)')
        self.conn.commit()
        print(f"[✅] Database initialized: {self.db_path}")
    
    def insert_log(self, log_entry: Dict[str, Any], is_anomaly: bool = False):
        """Veritabanına log kaydı ekle"""
        log_hash = hashlib.sha256(json.dumps(log_entry, sort_keys=True).encode()).hexdigest()
        
        try:
            self.conn.execute('''
                INSERT INTO logs (timestamp, log_type, severity, data, hash, is_anomaly)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                log_entry.get('timestamp', datetime.now().isoformat()),
                log_entry.get('log_type', 'unknown'),
                log_entry.get('severity', 'info'),
                json.dumps(log_entry),
                log_hash,
                1 if is_anomaly else 0
            ))
            self.conn.commit()
        except sqlite3.IntegrityError:
            pass
    
    def get_recent_logs(self, limit: int = 100, log_type: Optional[str] = None) -> List[Dict]:
        """Veritabanından son logları getir"""
        query = "SELECT * FROM logs"
        params = []
        
        if log_type:
            query += " WHERE log_type = ?"
            params.append(log_type)
        
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        
        cursor = self.conn.execute(query, params)
        logs = []
        for row in cursor.fetchall():
            log_data = json.loads(row[4])
            log_data['db_id'] = row[0]
            log_data['is_anomaly'] = bool(row[6])
            logs.append(log_data)
        
        return logs
    
    def get_stats(self) -> Dict[str, Any]:
        """Veritabanı istatistiklerini getir"""
        cursor = self.conn.execute("SELECT COUNT(*) FROM logs")
        total = cursor.fetchone()[0]
        
        cursor = self.conn.execute("SELECT COUNT(*) FROM logs WHERE is_anomaly = 1")
        anomalies = cursor.fetchone()[0]
        
        cursor = self.conn.execute("SELECT log_type, COUNT(*) FROM logs GROUP BY log_type")
        by_type = dict(cursor.fetchall())
        
        cursor = self.conn.execute("SELECT severity, COUNT(*) FROM logs GROUP BY severity")
        by_severity = dict(cursor.fetchall())
        
        return {
            'total_logs': total,
            'anomalies': anomalies,
            'by_type': by_type,
            'by_severity': by_severity
        }
    
    def close(self):
        """Veritabanı bağlantısını kapat"""
        if self.conn:
            self.conn.close()


class ThreatWeaveEngine:
    """Tüm bileşenleri koordine eden ana ThreatWeave SIEM motoru"""
    
    def __init__(self, db_path: str = 'threatweave_logs.db', sigma_rules_dir: Optional[str] = None):
        self.parser = LogParser()
        self.sigma_engine = SigmaRuleEngine(sigma_rules_dir)
        self.anomaly_detector = AnomalyDetector()
        self.alert_manager = AlertManager()
        self.db = ThreatWeaveDatabase(db_path)
        self.threat_hunter = ThreatHunter(db_path)
        self.threat_hunter.connect()
        
        # Load default rules if no Sigma rules provided
        # Sigma kuralı sağlanmadıysa varsayılan kuralları yükle
        if not self.sigma_engine.rules:
            self.sigma_engine.rules = self.sigma_engine.create_default_rules()
            print(f"[ℹ️] Loaded {len(self.sigma_engine.rules)} default detection rules")
        
        # Threshold tracking for time-based rules
        # Zamana dayalı kurallar için eşik takibi
        self.threshold_tracker = defaultdict(list)
    
    def ingest_log(self, log_line: str, log_type: str = 'auto'):
        """Tek bir log satırını al ve işle"""
        log_entry = self.parser.parse_log(log_line, log_type)
        if not log_entry:
            return
        
        # Add timestamp if not present

        if 'timestamp' not in log_entry:
            log_entry['timestamp'] = datetime.now().isoformat()
        
        # Detect anomalies (if model trained)
        # Anomali tespit et (model eğitildiyse)
        is_anomaly = False
        if self.anomaly_detector.trained:
            is_anomaly = self.anomaly_detector.predict([log_entry])[0]
            if is_anomaly:
                log_entry['is_anomaly'] = True
        
        # Store in database
        # Veritabanına kaydet
        self.db.insert_log(log_entry, is_anomaly)
        
        # Check against Sigma rules
        # Sigma kurallarına karşı kontrol et
        for rule in self.sigma_engine.rules:
            if self.sigma_engine.match_rule(log_entry, rule):
                # Handle threshold-based rules
                # Eşik tabanlı kuralları işle
                detection = rule.get('detection', {})
                if detection.get('condition') == 'threshold':
                    if self._check_threshold(rule, log_entry):
                        self._create_alert(rule, log_entry)
                else:
                    self._create_alert(rule, log_entry)
    
    def _check_threshold(self, rule: Dict, log_entry: Dict) -> bool:
        """Eşik koşulunun karşılanıp karşılanmadığını kontrol et"""
        threshold_config = rule['detection']['threshold']
        count_limit = threshold_config['count']
        timeframe = threshold_config['timeframe']  # seconds
        
        rule_id = rule['title']
        now = datetime.now()
        
        # Track this event
        # Bu olayı takip et
        self.threshold_tracker[rule_id].append(now)
        
        # Remove old events outside timeframe
        # Zaman aralığı dışındaki eski olayları kaldır
        cutoff = now - timedelta(seconds=timeframe)
        self.threshold_tracker[rule_id] = [
            t for t in self.threshold_tracker[rule_id] if t > cutoff
        ]
        
        # Check if threshold exceeded
        # Eşik aşılıp aşılmadığını kontrol et
        return len(self.threshold_tracker[rule_id]) >= count_limit
    
    def _create_alert(self, rule: Dict, log_entry: Dict):
        """Kural eşleşmesinden alert oluştur"""
        alert = self.alert_manager.create_alert(
            rule_title=rule['title'],
            log_entry=log_entry,
            severity=rule.get('level', 'medium'),
            mitre_ids=rule.get('mitre', [])
        )
        self.alert_manager.print_alert(alert)
    
    def ingest_file(self, file_path: str, log_type: str = 'auto'):
        """Bir dosyadan logları al"""
        print(f"[*] Ingesting logs from: {file_path}")
        count = 0
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    self.ingest_log(line.strip(), log_type)
                    count += 1
                    if count % 1000 == 0:
                        print(f"  [+] Processed {count} lines...")
        except Exception as e:
            print(f"[❌] Error ingesting file: {e}")
            return
        
        print(f"[✅] Ingested {count} log entries")
    
    def train_anomaly_model(self, training_logs_path: Optional[str] = None):
        """Anomali tespit modelini eğit"""
        if not ML_AVAILABLE:
            print("[⚠️] ML libraries not available. Skipping training.")
            return
        
        print("[*] Training anomaly detection model...")
        
        # Get training data
        # Eğitim verisini al
        if training_logs_path:
            # Dosyadan yükle
            logs = []
            with open(training_logs_path, 'r') as f:
                for line in f:
                    parsed = self.parser.parse_log(line.strip())
                    if parsed:
                        logs.append(parsed)
        else:
            # Mevcut veritabanı loglarını kullan
            logs = self.db.get_recent_logs(limit=10000)
        
        if logs:
            self.anomaly_detector.train(logs)
        else:
            print("[⚠️] No training data available")
    
    def hunt_threats(self):
        """Tehdit avı sorgularını çalıştır"""
        print(f"\n{Colors.HEADER}{'='*80}")
        print(f"🔍 THREAT HUNTING REPORT")
        print(f"{'='*80}{Colors.END}\n")
        
        # Hunt failed logins

        print(f"{Colors.BOLD}[1] Failed Login Attempts by IP:{Colors.END}")
        failed_logins = self.threat_hunter.hunt_failed_logins_by_ip(min_attempts=3)
        if failed_logins:
            for result in failed_logins[:10]:
                print(f"  ⚠️  IP: {result['ip']} - Attempts: {result['attempt_count']} "
                      f"(First: {result['first_seen']}, Last: {result['last_seen']})")
        else:
            print("  ✅ No suspicious failed login patterns detected")
        
        # Hunt suspicious user agents

        print(f"\n{Colors.BOLD}[2] Suspicious User-Agents (Attack Tools):{Colors.END}")
        suspicious_ua = self.threat_hunter.hunt_suspicious_user_agents()
        if suspicious_ua:
            for result in suspicious_ua[:10]:
                print(f"  ⚠️  IP: {result['ip']} - UA: {result['user_agent'][:80]}")
        else:
            print("  ✅ No suspicious user-agents detected")
        
        # Hunt web attacks

        print(f"\n{Colors.BOLD}[3] Web Attack Patterns:{Colors.END}")
        web_attacks = self.threat_hunter.hunt_web_attacks()
        if web_attacks:
            for result in web_attacks[:10]:
                print(f"  ⚠️  IP: {result['ip']} - Path: {result['path'][:80]}")
        else:
            print("  ✅ No web attack patterns detected")
        
        # Hunt privilege escalation

        print(f"\n{Colors.BOLD}[4] Privilege Escalation Attempts:{Colors.END}")
        priv_esc = self.threat_hunter.hunt_privilege_escalation()
        if priv_esc:
            for result in priv_esc[:10]:
                print(f"  ⚠️  User: {result['user']} - {result['message'][:80]}")
        else:
            print("  ✅ No privilege escalation attempts detected")
        
        print(f"\n{Colors.HEADER}{'='*80}{Colors.END}\n")
    
    def generate_report(self):
        """Kapsamlı güvenlik raporu oluştur"""
        stats = self.db.get_stats()
        alerts = self.alert_manager.get_alerts()
        
        print(f"\n{Colors.HEADER}{'='*80}")
        print(f"📊 THREATWEAVE SIEM SECURITY REPORT")
        print(f"{'='*80}{Colors.END}\n")
        
        print(f"{Colors.BOLD}Database Statistics:{Colors.END}")
        print(f"  Total Logs: {stats['total_logs']}")
        print(f"  Anomalies Detected: {stats['anomalies']}")
        print(f"\n  Logs by Type:")
        for log_type, count in stats['by_type'].items():
            print(f"    - {log_type}: {count}")
        print(f"\n  Logs by Severity:")
        for severity, count in stats['by_severity'].items():
            print(f"    - {severity}: {count}")
        
        print(f"\n{Colors.BOLD}Alert Summary:{Colors.END}")
        print(f"  Total Alerts: {len(alerts)}")
        
        severity_counts = Counter(a['severity'] for a in alerts)
        for severity in ['critical', 'high', 'medium', 'info']:
            if severity in severity_counts:
                color = {
                    'critical': Colors.RED,
                    'high': Colors.YELLOW,
                    'medium': Colors.CYAN,
                    'info': Colors.BLUE
                }.get(severity, Colors.END)
                print(f"  {color}{severity.upper()}: {severity_counts[severity]}{Colors.END}")
        
        # Top MITRE techniques
        # En çok görülen MITRE teknikleri
        mitre_counts = Counter()
        for alert in alerts:
            mitre_counts.update(alert.get('mitre_tactics', []))
        
        if mitre_counts:
            print(f"\n{Colors.BOLD}Top MITRE ATT&CK Techniques:{Colors.END}")
            for technique, count in mitre_counts.most_common(5):
                print(f"  - {technique}: {count} occurrences")
        
        print(f"\n{Colors.HEADER}{'='*80}{Colors.END}\n")
    
    def monitor_realtime(self, log_file: str, log_type: str = 'auto', interval: float = 1.0):
        """Log dosyasını gerçek zamanlı izle"""
        print(f"[*] Starting real-time monitoring: {log_file}")
        print(f"[*] Press Ctrl+C to stop\n")
        
        try:
            with open(log_file, 'r') as f:
                # Dosyanın sonuna git
                f.seek(0, 2)
                
                while True:
                    line = f.readline()
                    if line:
                        self.ingest_log(line.strip(), log_type)
                    else:
                        time.sleep(interval)
        except KeyboardInterrupt:
            print("\n[*] Monitoring stopped")
        except Exception as e:
            print(f"[❌] Error monitoring file: {e}")
    
    def close(self):
        """Tüm bağlantıları kapat"""
        self.db.close()
        self.threat_hunter.close()


def main():
    """Ana CLI arayüzü"""
    parser = argparse.ArgumentParser(
        description='ThreatWeave SIEM - Log Analyzer & Threat Hunter',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
    # Dosyadan logları al
  %(prog)s ingest --file /var/log/auth.log --type auth

    # Logları gerçek zamanlı izle
  %(prog)s monitor --file /var/log/apache2/access.log --type apache

    # Tehdit avı çalıştır
  %(prog)s hunt

    # Anomali tespiti eğit
  %(prog)s train --file baseline_logs.txt

    # Güvenlik raporu oluştur
  %(prog)s report

    # Tüm alertleri göster
  %(prog)s alerts --severity high
        '''
    )
    
    parser.add_argument('command', choices=['ingest', 'monitor', 'hunt', 'train', 'report', 'alerts'], help='Çalıştırılacak komut')
    parser.add_argument('--file', help='Log dosyası yolu')
    parser.add_argument('--type', default='auto', choices=['auto', 'syslog', 'apache', 'nginx', 'auth', 'windows'], help='Log tipi (varsayılan: otomatik tespit)')
    parser.add_argument('--db', default='threatweave_logs.db', help='Veritabanı dosya yolu')
    parser.add_argument('--sigma-rules', help='Sigma kuralları dizin yolu')
    parser.add_argument('--severity', choices=['critical', 'high', 'medium', 'info'], help='Alertleri önem seviyesine göre filtrele')
    parser.add_argument('--interval', type=float, default=1.0, help='İzleme aralığı (saniye)')

    args = parser.parse_args()

    engine = ThreatWeaveEngine(db_path=args.db, sigma_rules_dir=args.sigma_rules)

    try:
        if args.command == 'ingest':
            if not args.file:
                print("[❌] --file parametresi gerekli")
                return 1
            engine.ingest_file(args.file, args.type)
            engine.generate_report()

        elif args.command == 'monitor':
            if not args.file:
                print("[❌] --file parametresi gerekli")
                return 1
            engine.monitor_realtime(args.file, args.type, args.interval)

        elif args.command == 'hunt':
            engine.hunt_threats()

        elif args.command == 'train':
            engine.train_anomaly_model(args.file)

        elif args.command == 'report':
            engine.generate_report()

        elif args.command == 'alerts':
            alerts = engine.alert_manager.get_alerts(severity=args.severity)
            print(f"\n[*] {len(alerts)} alert listeleniyor\n")
            for alert in alerts[:50]:
                engine.alert_manager.print_alert(alert)

    finally:
        engine.close()

    return 0


if __name__ == '__main__':
    print(f"""
{Colors.HEADER}{'='*80}
   ____  ________  __  ___       __    ____  ______   __  ____  _______________
  / ___| |_   _| |  \\/  |      / /   / __ \\/ ____/  /  |/  / |/ /_  __/ ____/ 
  \\___ \\   | |   | \\  / |     / /   / / / / / __   / /|_/ /|   / / / / __/    
   ___) |  | |   | |  | |    / /___/ /_/ / /_/ /  / /  / / /| / / / / /___    
  |____/  |_|___|_|  |_|   /_____/\\____/\\____/  /_/  /_/_/ |_/ /_/ /_____/    
                                                                               
  Güvenlik Bilgi ve Olay Yönetimi - Tehdit Avcısı
  Kurumsal Düzeyde Log Analizi & Tehdit Tespit Platformu
{'='*80}{Colors.END}
    """)
    
    sys.exit(main())
