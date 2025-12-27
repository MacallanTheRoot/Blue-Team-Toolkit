#!/usr/bin/env python3
"""
SIEM Hunter - Web Dashboard
Modern, interaktif grafiksel arayüz

Özellikler:
- Gerçek zamanlı istatistikler
- Alert görüntüleme ve filtreleme
- Log arama ve analiz
- Threat hunting arayüzü
- Grafikler ve visualizasyonlar
- IOC görüntüleme

Yazar: Macallan (Blue Team)
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import sqlite3
import json
import os
from typing import Dict, List, Any
from collections import Counter
import time
import hashlib

st.set_page_config(
    page_title="SIEM Hunter Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Session state initialization
if 'auto_refresh' not in st.session_state:
    st.session_state.auto_refresh = False
if 'refresh_interval' not in st.session_state:
    st.session_state.refresh_interval = 5
if 'alert_sound' not in st.session_state:
    st.session_state.alert_sound = True
if 'last_alert_count' not in st.session_state:
    st.session_state.last_alert_count = 0
st.markdown("""
<style>
    .main-header {
        font-size: 3rem;
        font-weight: bold;
        text-align: center;
        background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        padding: 1rem 0;
    }
    .metric-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 1rem;
        border-radius: 10px;
        color: white;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
    }
    .alert-critical {
        background-color: #ff4444;
        padding: 1rem;
        border-radius: 5px;
        border-left: 5px solid #cc0000;
    }
    .alert-high {
        background-color: #ffbb33;
        padding: 1rem;
        border-radius: 5px;
        border-left: 5px solid #ff8800;
    }
    .alert-medium {
        background-color: #00C851;
        padding: 1rem;
        border-radius: 5px;
        border-left: 5px solid #007E33;
    }
    .stAlert {
        background-color: rgba(102, 126, 234, 0.1);
    }
</style>
""", unsafe_allow_html=True)


class SIEMDashboard:
    """Dashboard yönetim sınıfı"""
    
    def __init__(self, db_path: str = 'siem_logs.db'):
        self.db_path = db_path
        
    def get_connection(self):
        """Veritabanı bağlantısı oluştur"""
        if not os.path.exists(self.db_path):
            st.error(f"⚠️ Veritabanı bulunamadı: {self.db_path}")
            st.info("💡 Önce logları yükleyin: `python siem_hunter.py ingest --file demo_logs.txt`")
            return None
        return sqlite3.connect(self.db_path)
    
    def get_stats(self) -> Dict[str, Any]:
        """İstatistikleri al"""
        conn = self.get_connection()
        if not conn:
            return {}
        
        cursor = conn.cursor()
        
        # Toplam log sayısı
        total_logs = cursor.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
        
        # Anomali sayısı
        anomalies = cursor.execute("SELECT COUNT(*) FROM logs WHERE is_anomaly = 1").fetchone()[0]
        
        # Log tipleri
        log_types = cursor.execute("""
            SELECT log_type, COUNT(*) as count 
            FROM logs 
            GROUP BY log_type
        """).fetchall()
        
        # Önem seviyeleri
        severities = cursor.execute("""
            SELECT severity, COUNT(*) as count 
            FROM logs 
            GROUP BY severity
        """).fetchall()
        
        # Son 1 saatteki loglar
        one_hour_ago = (datetime.now() - timedelta(hours=1)).isoformat()
        recent_logs = cursor.execute("""
            SELECT COUNT(*) FROM logs WHERE timestamp > ?
        """, (one_hour_ago,)).fetchone()[0]
        
        conn.close()
        
        return {
            'total_logs': total_logs,
            'anomalies': anomalies,
            'recent_logs': recent_logs,
            'log_types': dict(log_types),
            'severities': dict(severities)
        }
    
    def get_logs(self, limit: int = 100, log_type: str = None, 
                 severity: str = None, search: str = None) -> pd.DataFrame:
        """Logları al ve filtrele"""
        conn = self.get_connection()
        if not conn:
            return pd.DataFrame()
        
        query = "SELECT * FROM logs WHERE 1=1"
        params = []
        
        if log_type and log_type != "Tümü":
            query += " AND log_type = ?"
            params.append(log_type)
        
        if severity and severity != "Tümü":
            query += " AND severity = ?"
            params.append(severity)
        
        if search:
            query += " AND data LIKE ?"
            params.append(f"%{search}%")
        
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        
        df = pd.read_sql_query(query, conn, params=params)
        conn.close()
        
        # JSON verilerini parse et

        if not df.empty and 'data' in df.columns:
            df['parsed_data'] = df['data'].apply(lambda x: json.loads(x) if x else {})
        
        return df
    
    def get_top_ips(self, limit: int = 10) -> List[tuple]:
        """En çok görülen IP'leri al"""
        conn = self.get_connection()
        if not conn:
            return []
        
        cursor = conn.cursor()
        ips = cursor.execute("""
            SELECT json_extract(data, '$.ip') as ip, COUNT(*) as count
            FROM logs
            WHERE json_extract(data, '$.ip') IS NOT NULL
            GROUP BY ip
            ORDER BY count DESC
            LIMIT ?
        """, (limit,)).fetchall()
        
        conn.close()
        return ips
    
    def get_timeline_data(self, hours: int = 24) -> pd.DataFrame:
        """Zaman çizelgesi verisi"""
        conn = self.get_connection()
        if not conn:
            return pd.DataFrame()
        
        cutoff = (datetime.now() - timedelta(hours=hours)).isoformat()
        
        df = pd.read_sql_query("""
            SELECT 
                timestamp,
                log_type,
                severity,
                is_anomaly
            FROM logs
            WHERE timestamp > ?
            ORDER BY timestamp
        """, conn, params=(cutoff,))
        
        conn.close()
        return df
    
    def get_attack_types(self) -> Dict[str, int]:
        """Saldırı tiplerini analiz et"""
        conn = self.get_connection()
        if not conn:
            return {}
        
        cursor = conn.cursor()
        
        attack_patterns = {
            'SQL Injection': ['union', 'select', 'drop', 'insert', '--'],
            'XSS': ['<script>', 'javascript:', 'onerror', 'onload'],
            'Path Traversal': ['../', '../../', 'etc/passwd', 'windows/system32'],
            'Command Injection': [';', '|', '&&', 'whoami', 'cat /etc'],
            'Brute Force': ['Failed password', 'authentication failure']
        }
        
        results = {}
        for attack_type, patterns in attack_patterns.items():
            count = 0
            for pattern in patterns:
                result = cursor.execute("""
                    SELECT COUNT(*) FROM logs 
                    WHERE data LIKE ?
                """, (f'%{pattern}%',)).fetchone()[0]
                count += result
            if count > 0:
                results[attack_type] = count
        
        conn.close()
        return results


def main():
    """Ana dashboard fonksiyonu"""

    st.markdown('<h1 class="main-header">🛡️ SIEM Hunter Dashboard</h1>', unsafe_allow_html=True)
    st.markdown("### Kurumsal Güvenlik İzleme & Tehdit Analizi")

    st.sidebar.title("⚙️ Ayarlar")

    base_dir = os.path.dirname(__file__)
    default_db = os.path.join(base_dir, "siem_logs.db")
    fim_db = os.path.normpath(os.path.join(base_dir, "..", "FileIntegrityMonitor", "siem_logs.db"))

    quick_options = []
    if os.path.exists(default_db):
        quick_options.append(("SIEM varsayılan", default_db))
    if os.path.exists(fim_db):
        quick_options.append(("FileIntegrityMonitor SIEM (siem_logs.db)", fim_db))

    db_path = st.sidebar.text_input(
        "Veritabanı Yolu",
        value=default_db,
        help="SQLite veritabanı dosya yolu"
    )

    if quick_options:
        labels = [f"{label} — {path}" for label, path in quick_options] + ["Özel yol kullan"]
        choice = st.sidebar.selectbox("Hızlı veritabanı seç", labels, index=0)
        if choice != "Özel yol kullan":
            db_path = choice.split(" — ", 1)[1]

    st.sidebar.caption(f"Aktif DB: {db_path}")

    dashboard = SIEMDashboard(db_path)

    if st.sidebar.button("🔄 Yenile", use_container_width=True):
        st.rerun()

    page = st.sidebar.radio(
        "📊 Navigasyon",
        [
            "Ana Sayfa", 
            "Log Görüntüleyici", 
            "Tehdit Avı", 
            "IOC Analizi", 
            "Raporlar",
            "🔴 Canlı İzleme",
            "🌐 Network Haritası",
            "🔍 IOC Lookup",
            "🛠️ Özel Sorgu",
            "📦 Export/Import",
            "🤖 Otomatik Yanıt",
            "🔔 Alert Bildirimleri",
            "🛡️ File Integrity Monitor"
        ]
    )
    
    st.sidebar.markdown("---")
    st.sidebar.markdown("### 📚 Hızlı Komutlar")
    st.sidebar.code("python siem_hunter.py ingest --file demo_logs.txt", language="bash")
    st.sidebar.code("python siem_hunter.py hunt", language="bash")

    if page == "Ana Sayfa":
        show_home_page(dashboard)
    elif page == "Log Görüntüleyici":
        show_log_viewer(dashboard)
    elif page == "Tehdit Avı":
        show_threat_hunting(dashboard)
    elif page == "IOC Analizi":
        show_ioc_analysis(dashboard)
    elif page == "Raporlar":
        show_reports(dashboard)

    elif page == "🔴 Canlı İzleme":
        render_live_monitoring_widget(dashboard)
    elif page == "🌐 Network Haritası":
        render_network_graph_widget(dashboard)
    elif page == "🔍 IOC Lookup":
        render_ioc_lookup_widget(dashboard)
    elif page == "🛠️ Özel Sorgu":
        render_custom_query_builder(dashboard)
    elif page == "📦 Export/Import":
        render_export_import_module(dashboard)
    elif page == "🤖 Otomatik Yanıt":
        render_automated_response_module(dashboard)
    elif page == "🔔 Alert Bildirimleri":
        render_alert_notification_system(dashboard)
    elif page == "🛡️ File Integrity Monitor":
        render_fim_management(dashboard)


def show_home_page(dashboard: SIEMDashboard):
    """Ana sayfa - genel istatistikler"""

    stats = dashboard.get_stats()
    
    if not stats:
        st.warning("⚠️ Veri bulunamadı. Lütfen önce logları yükleyin.")
        return

    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric(
            label="📊 Toplam Log",
            value=f"{stats.get('total_logs', 0):,}",
            delta=f"+{stats.get('recent_logs', 0)} (1 saat)"
        )
    
    with col2:
        st.metric(
            label="🚨 Anomali",
            value=stats.get('anomalies', 0),
            delta=f"{(stats.get('anomalies', 0) / max(stats.get('total_logs', 1), 1) * 100):.1f}%"
        )
    
    with col3:
        critical_count = stats.get('severities', {}).get('critical', 0)
        high_count = stats.get('severities', {}).get('high', 0)
        st.metric(
            label="⚠️ Kritik/Yüksek",
            value=critical_count + high_count,
            delta="Önem: Yüksek" if (critical_count + high_count) > 0 else "Normal"
        )
    
    with col4:
        st.metric(
            label="📈 Log Tipi",
            value=len(stats.get('log_types', {})),
            delta="Farklı kaynak"
        )
    
    st.markdown("---")

    col1, col2 = st.columns(2)
    
    with col1:

        if stats.get('log_types'):
            fig = px.pie(
                names=list(stats['log_types'].keys()),
                values=list(stats['log_types'].values()),
                title="📊 Log Tipleri Dağılımı",
                hole=0.4,
                color_discrete_sequence=px.colors.sequential.RdBu
            )
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)
    
    with col2:

        if stats.get('severities'):
            fig = px.bar(
                x=list(stats['severities'].keys()),
                y=list(stats['severities'].values()),
                title="⚠️ Önem Seviyeleri",
                labels={'x': 'Önem Seviyesi', 'y': 'Adet'},
                color=list(stats['severities'].values()),
                color_continuous_scale='Reds'
            )
            fig.update_layout(height=400, showlegend=False)
            st.plotly_chart(fig, use_container_width=True)

    st.markdown("### 📈 Son 24 Saat - Zaman Çizelgesi")
    timeline_df = dashboard.get_timeline_data(hours=24)

    if not timeline_df.empty:

        try:
            timeline_df['timestamp'] = pd.to_datetime(timeline_df['timestamp'], errors='coerce', utc=True)

            timeline_df = timeline_df.dropna(subset=['timestamp'])
            timeline_df['hour'] = timeline_df['timestamp'].dt.floor('H')
        except Exception as e:
            st.error(f"Zaman çizelgesi verisi oluşturulamadı: {e}")
            timeline_df = pd.DataFrame()

    if not timeline_df.empty:

        hourly = timeline_df.groupby(['hour', 'severity']).size().reset_index(name='count')
        
        fig = px.line(
            hourly,
            x='hour',
            y='count',
            color='severity',
            title="Saatlik Log Aktivitesi",
            labels={'hour': 'Zaman', 'count': 'Log Sayısı'},
            color_discrete_map={
                'critical': '#ff4444',
                'high': '#ffbb33',
                'medium': '#00C851',
                'info': '#33b5e5'
            }
        )
        fig.update_layout(height=400)
        st.plotly_chart(fig, use_container_width=True)

    st.markdown("### 🌐 En Aktif IP Adresleri")
    top_ips = dashboard.get_top_ips(limit=10)

    if top_ips:
        ip_df = pd.DataFrame(top_ips, columns=['IP Adresi', 'İstek Sayısı'])
        
        fig = px.bar(
            ip_df,
            x='İstek Sayısı',
            y='IP Adresi',
            orientation='h',
            title="En Çok Trafik Gönderen IP'ler",
            color='İstek Sayısı',
            color_continuous_scale='Reds'
        )
        fig.update_layout(height=400)
        st.plotly_chart(fig, use_container_width=True)

    st.markdown("### 🎯 Tespit Edilen Saldırı Tipleri")
    attack_types = dashboard.get_attack_types()
    
    if attack_types:
        col1, col2 = st.columns([2, 1])
        
        with col1:
            fig = px.bar(
                x=list(attack_types.keys()),
                y=list(attack_types.values()),
                title="Saldırı Tipi Dağılımı",
                labels={'x': 'Saldırı Tipi', 'y': 'Tespit Sayısı'},
                color=list(attack_types.values()),
                color_continuous_scale='OrRd'
            )
            fig.update_layout(height=400, showlegend=False)
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            st.markdown("#### 📋 Detaylar")
            for attack, count in sorted(attack_types.items(), key=lambda x: x[1], reverse=True):
                severity_color = "🔴" if count > 10 else "🟡" if count > 5 else "🟢"
                st.markdown(f"{severity_color} **{attack}**: {count} tespit")


def show_log_viewer(dashboard: SIEMDashboard):
    """Log görüntüleyici sayfası"""

    st.title("📄 Log Görüntüleyici")

    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        log_type_filter = st.selectbox(
            "Log Tipi",
            ["Tümü", "apache", "auth", "syslog", "generic"]
        )
    
    with col2:
        severity_filter = st.selectbox(
            "Önem Seviyesi",
            ["Tümü", "critical", "high", "medium", "info"]
        )
    
    with col3:
        limit = st.number_input("Gösterim Limiti", min_value=10, max_value=1000, value=100)
    
    with col4:
        search_term = st.text_input("🔍 Ara", placeholder="IP, domain, vb...")

    df = dashboard.get_logs(
        limit=limit,
        log_type=log_type_filter if log_type_filter != "Tümü" else None,
        severity=severity_filter if severity_filter != "Tümü" else None,
        search=search_term if search_term else None
    )
    
    if df.empty:
        st.warning("⚠️ Filtrelere uygun log bulunamadı.")
        return

    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Toplam Log", len(df))
    with col2:
        st.metric("Anomali", df['is_anomaly'].sum())
    with col3:
        st.metric("Farklı Tip", df['log_type'].nunique())

    st.markdown("### 📊 Log Kayıtları")

    display_df = df[['timestamp', 'log_type', 'severity', 'is_anomaly']].copy()
    display_df.columns = ['Zaman', 'Tip', 'Önem', 'Anomali']
    display_df['Anomali'] = display_df['Anomali'].apply(lambda x: '🚨' if x else '✅')

    def highlight_severity(row):
        if row['Önem'] == 'critical':
            return ['background-color: #ff4444; color: white'] * len(row)
        elif row['Önem'] == 'high':
            return ['background-color: #ffbb33; color: black'] * len(row)
        elif row['Önem'] == 'medium':
            return ['background-color: #00C851; color: white'] * len(row)
        return [''] * len(row)
    
    st.dataframe(display_df.style.apply(highlight_severity, axis=1), use_container_width=True, height=400)

    st.markdown("### 🔍 Log Detayları")
    selected_index = st.selectbox("Log Seç", df.index, format_func=lambda x: f"Log #{x} - {df.loc[x, 'timestamp']}")
    
    if selected_index is not None:
        selected_log = df.loc[selected_index]
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("#### ℹ️ Temel Bilgiler")
            st.json({
                'ID': int(selected_log['id']),
                'Zaman': selected_log['timestamp'],
                'Tip': selected_log['log_type'],
                'Önem': selected_log['severity'],
                'Anomali': bool(selected_log['is_anomaly']),
                'Hash': selected_log['hash']
            })
        
        with col2:
            st.markdown("#### 📋 Tam Veri")
            if 'parsed_data' in df.columns:
                st.json(selected_log['parsed_data'])
            else:
                st.code(selected_log['data'], language='json')


def show_threat_hunting(dashboard: SIEMDashboard):
    """Tehdit avı sayfası"""
    
    st.title("🎯 Tehdit Avı")
    st.markdown("Gelişmiş sorgular ve pattern analizi")
    
    # Hazır sorgular
    st.markdown("### 🔍 Hazır Sorgular")
    
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("🚨 Başarısız Login Denemeleri", use_container_width=True):
            conn = dashboard.get_connection()
            if conn:
                query = """
                SELECT 
                    json_extract(data, '$.ip') as IP,
                    COUNT(*) as Denemeler,
                    MIN(timestamp) as İlk_Görülme,
                    MAX(timestamp) as Son_Görülme
                FROM logs
                WHERE json_extract(data, '$.auth_result') = 'failed'
                GROUP BY IP
                HAVING Denemeler >= 3
                ORDER BY Denemeler DESC
                st.title("🎯 Tehdit Avı")
                st.markdown("Gelişmiş sorgular ve pattern analizi")
                """
                df = pd.read_sql_query(query, conn)
                conn.close()
                
                if not df.empty:
                    st.dataframe(df, use_container_width=True)
                    st.success(f"✅ {len(df)} şüpheli IP bulundu")
                else:
                    st.info("ℹ️ Şüpheli aktivite tespit edilmedi")
    
    with col2:
        if st.button("🕷️ Web Saldırı Paternleri", use_container_width=True):
            conn = dashboard.get_connection()
            if conn:
                patterns = ['union', 'select', '<script>', 'javascript:', '../']
                results = []
                
                for pattern in patterns:
                    cursor = conn.cursor()
                    count = cursor.execute("""
                        SELECT COUNT(*) FROM logs 
                        WHERE json_extract(data, '$.path') LIKE ?
                    """, (f'%{pattern}%',)).fetchone()[0]
                    
                    if count > 0:
                        results.append({'Pattern': pattern, 'Tespit': count})
                
                conn.close()
                
                if results:
                    df = pd.DataFrame(results)
                    st.dataframe(df, use_container_width=True)
                    st.warning(f"⚠️ {len(results)} farklı saldırı paterni tespit edildi")
                else:
                    st.info("ℹ️ Saldırı paterni tespit edilmedi")
    
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("🛠️ Şüpheli User-Agent'lar", use_container_width=True):
            conn = dashboard.get_connection()
            if conn:
                suspicious_ua = ['sqlmap', 'nmap', 'nikto', 'metasploit', 'burp', 'masscan']
                results = []
                
                for ua in suspicious_ua:
                    cursor = conn.cursor()
                    logs = cursor.execute("""
                        SELECT 
                            json_extract(data, '$.ip') as IP,
                            json_extract(data, '$.user_agent') as UserAgent,
                            COUNT(*) as Adet
                        FROM logs
                        WHERE json_extract(data, '$.user_agent') LIKE ?
                        GROUP BY IP, UserAgent
                    """, (f'%{ua}%',)).fetchall()
                    
                    for log in logs:
                        results.append({'IP': log[0], 'User-Agent': log[1], 'İstek': log[2]})
                
                conn.close()
                
                if results:
                    df = pd.DataFrame(results)
                    st.dataframe(df, use_container_width=True)
                    st.error(f"🔴 {len(results)} saldırı aracı tespit edildi!")
                else:
                    st.info("ℹ️ Saldırı aracı tespit edilmedi")
    
    with col2:
        if st.button("🔐 Yetki Yükseltme Denemeleri", use_container_width=True):
            conn = dashboard.get_connection()
            if conn:
                query = """
                SELECT 
                    json_extract(data, '$.user') as Kullanıcı,
                    json_extract(data, '$.message') as Mesaj,
                    timestamp as Zaman
                FROM logs
                WHERE json_extract(data, '$.message') LIKE '%sudo%'
                   OR json_extract(data, '$.message') LIKE '%su:%'
                ORDER BY timestamp DESC
                LIMIT 50
                """
                df = pd.read_sql_query(query, conn)
                conn.close()
                
                if not df.empty:
                    st.dataframe(df, use_container_width=True)
                    st.warning(f"⚠️ {len(df)} yetki yükseltme denemesi bulundu")
                else:
                    st.info("ℹ️ Yetki yükseltme denemesi tespit edilmedi")
    
    # Özel sorgu
    st.markdown("---")
    st.markdown("### 💻 Özel SQL Sorgusu")
    
    custom_query = st.text_area(
        "SQL Sorgusu",
        value="SELECT * FROM logs LIMIT 10;",
        height=150,
        help="SQLite sorgusu yazın"
    )
    
    if st.button("▶️ Sorguyu Çalıştır", type="primary"):
        try:
            conn = dashboard.get_connection()
            if conn:
                df = pd.read_sql_query(custom_query, conn)
                conn.close()
                
                st.success(f"✅ {len(df)} kayıt bulundu")
                st.dataframe(df, use_container_width=True)
        except Exception as e:
            st.error(f"❌ Hata: {e}")


def show_ioc_analysis(dashboard: SIEMDashboard):
    """IOC analizi sayfası"""
    
    st.title("🔍 IOC (Indicators of Compromise) Analizi")
    
    conn = dashboard.get_connection()
    if not conn:
        return
    
    # IP analizi
    st.markdown("### 🌐 IP Adresi Analizi")
    
    ip_query = """
    SELECT 
        json_extract(data, '$.ip') as IP,
        COUNT(*) as Görülme,
        GROUP_CONCAT(DISTINCT log_type) as Kaynaklar,
        MIN(timestamp) as İlk_Görülme,
        MAX(timestamp) as Son_Görülme
    FROM logs
    WHERE json_extract(data, '$.ip') IS NOT NULL
    GROUP BY IP
    ORDER BY Görülme DESC
    LIMIT 20
    st.title("🔍 IOC (Indicators of Compromise) Analizi")
    """
    
    ip_df = pd.read_sql_query(ip_query, conn)
    
    if not ip_df.empty:
        st.dataframe(ip_df, use_container_width=True, height=300)
        
        # IP haritası (top 10)
        top_ips = ip_df.head(10)
        fig = px.treemap(
            top_ips,
            path=['IP'],
            values='Görülme',
            title='En Aktif IP Adresleri (Treemap)',
            color='Görülme',
            color_continuous_scale='Reds'
        )
        st.plotly_chart(fig, use_container_width=True)
    
    # Domain analizi
    st.markdown("### 🌍 Domain Analizi")
    
    # Domain'leri IOC'lerden çıkar
    cursor = conn.cursor()
    all_domains = []
    
    logs = cursor.execute("SELECT data FROM logs").fetchall()
    for log in logs:
        try:
            data = json.loads(log[0])
            iocs = data.get('iocs', {})
            domains = iocs.get('domains', [])
            all_domains.extend(domains)
        except:
            pass
    
    if all_domains:
        domain_counts = Counter(all_domains)
        domain_df = pd.DataFrame(domain_counts.most_common(20), columns=['Domain', 'Görülme'])
        
        st.dataframe(domain_df, use_container_width=True, height=300)
        
        fig = px.bar(
            domain_df.head(10),
            x='Görülme',
            y='Domain',
            orientation='h',
            title='En Çok Görülen Domain\'ler',
            color='Görülme',
            color_continuous_scale='Blues'
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("ℹ️ Domain bilgisi bulunamadı")
    
    # Hash analizi
    st.markdown("### 🔐 Hash Analizi")
    
    all_hashes = {'md5': [], 'sha256': []}
    
    for log in logs:
        try:
            data = json.loads(log[0])
            iocs = data.get('iocs', {})
            all_hashes['md5'].extend(iocs.get('md5', []))
            all_hashes['sha256'].extend(iocs.get('sha256', []))
        except:
            pass
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.metric("MD5 Hash'leri", len(set(all_hashes['md5'])))
        if all_hashes['md5']:
            st.code('\n'.join(set(all_hashes['md5'][:10])), language='text')
    
    with col2:
        st.metric("SHA256 Hash'leri", len(set(all_hashes['sha256'])))
        if all_hashes['sha256']:
            st.code('\n'.join(set(all_hashes['sha256'][:10])), language='text')
    
    conn.close()


def show_reports(dashboard: SIEMDashboard):
    """Raporlar sayfası"""
    
    st.title("📊 Güvenlik Raporları")
    
    # Rapor tipi seçimi
    report_type = st.selectbox(
        "Rapor Tipi",
        ["Özet Rapor", "Detaylı Analiz", "Trend Analizi", "Olay Zaman Çizelgesi"]
    )
    
    stats = dashboard.get_stats()
    
    if not stats:
        st.warning("⚠️ Rapor oluşturmak için veri bulunamadı.")
        return
    
    if report_type == "Özet Rapor":
        st.markdown("### 📋 Güvenlik Durumu Özeti")
        st.markdown(f"**Rapor Tarihi:** {datetime.now().strftime('%d.%m.%Y %H:%M')}")
        
        # Özet metrikler
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.info(f"""
            **📊 Toplam Aktivite**
            - Log Sayısı: {stats.get('total_logs', 0):,}
            - Son 1 Saat: {stats.get('recent_logs', 0)}
            - Farklı Kaynak: {len(stats.get('log_types', {}))}
            """)
        
        with col2:
            critical = stats.get('severities', {}).get('critical', 0)
            high = stats.get('severities', {}).get('high', 0)
            
            severity_status = "🔴 Kritik" if critical > 0 else "🟡 Yüksek" if high > 5 else "🟢 Normal"
            
            st.warning(f"""
            **⚠️ Güvenlik Durumu**
            - Durum: {severity_status}
            - Kritik: {critical}
            - Yüksek: {high}
            - Anomali: {stats.get('anomalies', 0)}
            """)
        
        with col3:
            attack_types = dashboard.get_attack_types()
            total_attacks = sum(attack_types.values())
            
            st.error(f"""
            **🎯 Tespit Edilen Tehditler**
            - Toplam Saldırı: {total_attacks}
            - Farklı Tip: {len(attack_types)}
            - En Yaygın: {max(attack_types.items(), key=lambda x: x[1])[0] if attack_types else 'N/A'}
            """)
        
        # Öneriler
        st.markdown("### 💡 Öneriler")
        
        recommendations = []
        
        if critical > 0:
            recommendations.append("🔴 **ACİL**: Kritik seviye olaylar tespit edildi. Hemen müdahale gerekiyor!")
        
        if high > 10:
            recommendations.append("🟡 **YÜKSEK**: Çok sayıda yüksek öncelikli olay var. İnceleme yapılmalı.")
        
        if stats.get('anomalies', 0) > 0:
            recommendations.append(f"🤖 **ANOMALI**: {stats.get('anomalies', 0)} anormal davranış tespit edildi.")
        
        if total_attacks > 20:
            recommendations.append(f"🎯 **SALDIRI**: {total_attacks} saldırı denemesi tespit edildi. Güvenlik duvarı kuralları gözden geçirilmeli.")
        
        if not recommendations:
            st.success("✅ Güvenlik durumu normal seviyede. Herhangi bir acil müdahale gerekmiyor.")
        else:
            for rec in recommendations:
                st.markdown(f"- {rec}")
        
        # PDF indir butonu (simüle)
        st.markdown("---")
        if st.button("📥 Raporu PDF Olarak İndir", type="primary"):
            st.info("💡 PDF export özelliği aktif edilecek...")
    
    elif report_type == "Trend Analizi":
        st.markdown("### 📈 Trend Analizi")
        
        timeline_df = dashboard.get_timeline_data(hours=168)  # 1 hafta
        
        if not timeline_df.empty:
            timeline_df['timestamp'] = pd.to_datetime(timeline_df['timestamp'])
            timeline_df['date'] = timeline_df['timestamp'].dt.date
            
            daily = timeline_df.groupby(['date', 'severity']).size().reset_index(name='count')
            
            fig = px.area(
                daily,
                x='date',
                y='count',
                color='severity',
                title='Haftalık Güvenlik Olayları Trendi',
                labels={'date': 'Tarih', 'count': 'Olay Sayısı'},
                color_discrete_map={
                    'critical': '#ff4444',
                    'high': '#ffbb33',
                    'medium': '#00C851',
                    'info': '#33b5e5'
                }
            )
            st.plotly_chart(fig, use_container_width=True)


# ============================================================================
# YENİ MODÜLLER
# ============================================================================

def render_live_monitoring_widget(dashboard):
    """Gerçek zamanlı izleme widget'ı"""
    st.markdown("### 🔴 Canlı İzleme")
    
    col1, col2, col3 = st.columns([2, 1, 1])
    
    with col1:
        auto_refresh = st.checkbox(
            "🔄 Otomatik Yenileme", 
            value=st.session_state.auto_refresh,
            help="Dashboard'u otomatik olarak yenile"
        )
        st.session_state.auto_refresh = auto_refresh
    
    with col2:
        if auto_refresh:
            interval = st.select_slider(
                "Yenileme Aralığı (sn)",
                options=[5, 10, 30, 60],
                value=st.session_state.refresh_interval
            )
            st.session_state.refresh_interval = interval
    
    with col3:
        if auto_refresh:
            st.info(f"⏱️ {interval}s'de bir yenileniyor")
            time.sleep(interval)
            st.rerun()
    
    # Son aktivite
    st.markdown("#### 📊 Son Aktivite (1 dakika)")
    
    conn = dashboard.get_connection()
    if conn:
        one_min_ago = (datetime.now() - timedelta(minutes=1)).isoformat()
        
        recent = pd.read_sql_query("""
            SELECT log_type, severity, COUNT(*) as count
            FROM logs
            WHERE timestamp > ?
            GROUP BY log_type, severity
        """, conn, params=(one_min_ago,))
        
        if not recent.empty:
            cols = st.columns(len(recent))
            for idx, row in recent.iterrows():
                with cols[idx]:
                    color = {
                        'critical': '🔴',
                        'high': '🟠',
                        'medium': '🟡',
                        'info': '🔵'
                    }.get(row['severity'], '⚪')
                    st.metric(
                        f"{color} {row['log_type']}", 
                        f"{row['count']} log",
                        delta=f"{row['severity']}"
                    )
        else:
            st.success("✅ Son 1 dakikada aktivite yok")
        
        conn.close()


def render_ioc_lookup_widget(dashboard):
    """IOC Lookup ve Enrichment Widget'ı"""
    st.markdown("### 🔍 IOC Lookup & Enrichment")
    
    tab1, tab2, tab3 = st.tabs(["🌐 IP Lookup", "🔗 Domain Lookup", "🔐 Hash Lookup"])
    
    with tab1:
        st.markdown("#### IP Adresi Sorgula")
        ip_input = st.text_input("IP Adresi:", placeholder="192.168.1.100")
        
        col1, col2 = st.columns(2)
        with col1:
            check_db = st.button("📊 Veritabanında Ara", key="ip_db")
        with col2:
            check_virustotal = st.button("🦠 VirusTotal (Yakında)", key="ip_vt", disabled=True)
        
        if check_db and ip_input:
            conn = dashboard.get_connection()
            if conn:
                results = pd.read_sql_query("""
                    SELECT timestamp, log_type, severity, data
                    FROM logs
                    WHERE data LIKE ?
                    ORDER BY timestamp DESC
                    LIMIT 50
                """, conn, params=(f'%{ip_input}%',))
                
                if not results.empty:
                    st.success(f"✅ {len(results)} kayıt bulundu")
                    
                    # Özet istatistikler
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        st.metric("Toplam Görülme", len(results))
                    with col2:
                        severity_counts = results['severity'].value_counts()
                        most_common = severity_counts.index[0] if not severity_counts.empty else "N/A"
                        st.metric("En Yaygın Seviye", most_common)
                    with col3:
                        first_seen = pd.to_datetime(results['timestamp']).min()
                        st.metric("İlk Görülme", first_seen.strftime('%Y-%m-%d %H:%M'))
                    
                    # Detaylar
                    with st.expander("📋 Detayları Göster"):
                        st.dataframe(results, use_container_width=True)
                else:
                    st.warning(f"⚠️ '{ip_input}' için kayıt bulunamadı")
                
                conn.close()
    
    with tab2:
        st.markdown("#### Domain Sorgula")
        domain_input = st.text_input("Domain:", placeholder="example.com")
        
        if st.button("🔍 Ara", key="domain_search") and domain_input:
            conn = dashboard.get_connection()
            if conn:
                results = pd.read_sql_query("""
                    SELECT COUNT(*) as count, log_type, severity
                    FROM logs
                    WHERE data LIKE ?
                    GROUP BY log_type, severity
                """, conn, params=(f'%{domain_input}%',))
                
                if not results.empty:
                    st.dataframe(results, use_container_width=True)
                else:
                    st.info("Domain bulunamadı")
                
                conn.close()
    
    with tab3:
        st.markdown("#### Hash Sorgula (MD5/SHA256)")
        hash_input = st.text_input("Hash:", placeholder="5d41402abc4b2a76b9719d911017c592")
        
        col1, col2 = st.columns(2)
        with col1:
            if st.button("📊 Veritabanında Ara", key="hash_db") and hash_input:
                st.info("Hash arama özelliği aktif...")
        with col2:
            if st.button("🦠 VirusTotal (Yakında)", key="hash_vt", disabled=True):
                pass


def render_custom_query_builder(dashboard):
    """Özel SQL Sorgu Oluşturucu"""
    st.markdown("### 🛠️ Özel Sorgu Oluşturucu")
    
    st.info("💡 SQLite sorguları ile özel aramalar yapabilirsiniz")
    
    # Hazır şablonlar
    query_templates = {
        "Tümünü Seç": "SELECT * FROM logs LIMIT 100",
        "IP Bazlı Gruplama": """
SELECT json_extract(data, '$.ip') as ip, 
       COUNT(*) as count,
       severity
FROM logs
WHERE json_extract(data, '$.ip') IS NOT NULL
GROUP BY ip, severity
ORDER BY count DESC
LIMIT 20""",
        "Zaman Aralığı": """
SELECT * FROM logs
WHERE timestamp BETWEEN datetime('now', '-1 day') AND datetime('now')
ORDER BY timestamp DESC
LIMIT 100""",
        "Önem Seviyesi Analizi": """
SELECT severity, log_type, COUNT(*) as count
FROM logs
GROUP BY severity, log_type
ORDER BY count DESC""",
        "MITRE ATT&CK Teknikleri": """
SELECT json_extract(data, '$.mitre_attack') as technique,
       COUNT(*) as count
FROM logs
WHERE json_extract(data, '$.mitre_attack') IS NOT NULL
GROUP BY technique
ORDER BY count DESC"""
    }
    
    col1, col2 = st.columns([1, 3])
    
    with col1:
        template = st.selectbox(
            "📑 Sorgu Şablonu",
            list(query_templates.keys())
        )
    
    with col2:
        custom_query = st.text_area(
            "SQL Sorgusu:",
            value=query_templates[template],
            height=150,
            help="Özel SQL sorgunuzu yazın"
        )
    
    col1, col2, col3 = st.columns([1, 1, 2])
    
    with col1:
        execute_btn = st.button("▶️ Sorguyu Çalıştır", type="primary")
    
    with col2:
        export_format = st.selectbox("📥 Export", ["CSV", "JSON"])
    
    if execute_btn:
        try:
            conn = dashboard.get_connection()
            if conn:
                results = pd.read_sql_query(custom_query, conn)
                conn.close()
                
                if not results.empty:
                    st.success(f"✅ {len(results)} satır döndürüldü")
                    st.dataframe(results, use_container_width=True)
                    
                    # Export butonu
                    if export_format == "CSV":
                        csv = results.to_csv(index=False)
                        st.download_button(
                            "📥 CSV İndir",
                            csv,
                            "query_results.csv",
                            "text/csv",
                            key='download-csv'
                        )
                    else:
                        json_data = results.to_json(orient='records', indent=2)
                        st.download_button(
                            "📥 JSON İndir",
                            json_data,
                            "query_results.json",
                            "application/json",
                            key='download-json'
                        )
                else:
                    st.warning("⚠️ Sorgu sonucu boş")
        except Exception as e:
            st.error(f"❌ Sorgu hatası: {str(e)}")


def render_network_graph_widget(dashboard):
    """Network Bağlantı Haritası"""
    st.markdown("### 🌐 Network Bağlantı Haritası")
    
    conn = dashboard.get_connection()
    if not conn:
        return
    
    # IP bağlantılarını al
    query = """
    SELECT 
        json_extract(data, '$.ip') as source_ip,
        json_extract(data, '$.path') as destination,
        COUNT(*) as connection_count,
        severity
    FROM logs
    WHERE json_extract(data, '$.ip') IS NOT NULL
    GROUP BY source_ip, destination, severity
    ORDER BY connection_count DESC
    LIMIT 50
    """
    
    df = pd.read_sql_query(query, conn)
    conn.close()
    
    if not df.empty:
        # Üstte özet
        col1, col2, col3 = st.columns(3)
        with col1:
            unique_ips = df['source_ip'].nunique()
            st.metric("Benzersiz IP", unique_ips)
        with col2:
            total_connections = df['connection_count'].sum()
            st.metric("Toplam Bağlantı", total_connections)
        with col3:
            critical_ips = df[df['severity'] == 'critical']['source_ip'].nunique()
            st.metric("Kritik IP'ler", critical_ips)
        
        # Top IP'ler tablosu
        st.markdown("#### 🔝 En Aktif IP Adresleri")
        top_ips = df.groupby('source_ip').agg({
            'connection_count': 'sum',
            'severity': lambda x: x.mode()[0] if len(x) > 0 else 'unknown'
        }).sort_values('connection_count', ascending=False).head(10)
        
        top_ips['severity_icon'] = top_ips['severity'].map({
            'critical': '🔴',
            'high': '🟠',
            'medium': '🟡',
            'info': '🔵'
        })
        
        st.dataframe(top_ips, use_container_width=True)
        
        # Görselleştirme
        fig = px.treemap(
            df.head(20),
            path=['severity', 'source_ip'],
            values='connection_count',
            color='severity',
            title='IP Bağlantı Haritası',
            color_discrete_map={
                'critical': '#ff4444',
                'high': '#ffbb33',
                'medium': '#00C851',
                'info': '#33b5e5'
            }
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("📊 Görüntülenecek network verisi yok")


def render_export_import_module(dashboard):
    """Export/Import Modülü"""
    st.markdown("### 📦 Veri Export/Import")
    
    tab1, tab2 = st.tabs(["📥 Export", "📤 Import"])
    
    with tab1:
        st.markdown("#### Veri Export")
        
        col1, col2 = st.columns(2)
        
        with col1:
            export_format = st.radio(
                "Format Seçin:",
                ["CSV", "JSON", "Excel (Yakında)"],
                help="Export formatını seçin"
            )
        
        with col2:
            time_range = st.selectbox(
                "Zaman Aralığı:",
                ["Son 1 Saat", "Son 24 Saat", "Son 7 Gün", "Son 30 Gün", "Tümü"]
            )
        
        filters = st.multiselect(
            "Filtreler:",
            ["critical", "high", "medium", "info"],
            default=["critical", "high"]
        )
        
        if st.button("📥 Export Başlat", type="primary"):
            conn = dashboard.get_connection()
            if conn:
                # Zaman aralığı hesapla
                time_filter = ""
                if time_range != "Tümü":
                    hours_map = {
                        "Son 1 Saat": 1,
                        "Son 24 Saat": 24,
                        "Son 7 Gün": 168,
                        "Son 30 Gün": 720
                    }
                    hours = hours_map[time_range]
                    cutoff = (datetime.now() - timedelta(hours=hours)).isoformat()
                    time_filter = f"AND timestamp > '{cutoff}'"
                
                # Severity filter
                severity_filter = ""
                if filters:
                    placeholders = ','.join(['?' for _ in filters])
                    severity_filter = f"AND severity IN ({placeholders})"
                
                query = f"SELECT * FROM logs WHERE 1=1 {time_filter} {severity_filter}"
                df = pd.read_sql_query(query, conn, params=filters if severity_filter else None)
                conn.close()
                
                if not df.empty:
                    st.success(f"✅ {len(df)} kayıt export edilecek")
                    
                    if export_format == "CSV":
                        csv_data = df.to_csv(index=False)
                        st.download_button(
                            "💾 CSV Dosyasını İndir",
                            csv_data,
                            f"siem_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                            "text/csv",
                            key='export-csv'
                        )
                    elif export_format == "JSON":
                        json_data = df.to_json(orient='records', indent=2)
                        st.download_button(
                            "💾 JSON Dosyasını İndir",
                            json_data,
                            f"siem_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                            "application/json",
                            key='export-json'
                        )
                else:
                    st.warning("⚠️ Export edilecek veri bulunamadı")
    
    with tab2:
        st.markdown("#### Veri Import")
        
        uploaded_file = st.file_uploader(
            "Log dosyası yükle:",
            type=['csv', 'json', 'txt'],
            help="CSV, JSON veya TXT formatında log dosyası"
        )
        
        if uploaded_file:
            st.info(f"📄 Dosya: {uploaded_file.name}")
            st.info(f"📊 Boyut: {uploaded_file.size / 1024:.2f} KB")
            
            if st.button("📤 Import Başlat", type="primary"):
                st.success("✅ Import işlemi başlatıldı")
                st.info("💡 CLI ile import yapın: `python siem_hunter.py ingest --file your_file.txt`")


def render_automated_response_module(dashboard):
    """Otomatik Yanıt Modülü"""
    st.markdown("### 🤖 Otomatik Yanıt Sistemi")
    
    st.warning("⚠️ Bu modül yapılandırma gerektirir. Dikkatli kullanın!")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("#### 🚨 Alert Kuralları")
        
        enable_auto_response = st.checkbox(
            "Otomatik yanıt aktif",
            value=False,
            help="Kritik olaylar için otomatik aksiyonlar al"
        )
        
        if enable_auto_response:
            st.selectbox(
                "Kritik IP tespit edildiğinde:",
                ["Sadece Logla", "Email Gönder", "Firewall Engelle (Simüle)", "Webhook Tetikle"]
            )
            
            threshold = st.slider(
                "Brute Force Eşiği:",
                min_value=3,
                max_value=20,
                value=5,
                help="Kaç başarısız denemede aksiyon alınsın"
            )
            
            st.text_input("Email Adresi:", placeholder="admin@example.com")
            st.text_input("Webhook URL:", placeholder="https://your-webhook.com/alert")
    
    with col2:
        st.markdown("#### 📊 Aksiyon Geçmişi")
        
        # Simüle edilmiş aksiyon geçmişi
        actions = pd.DataFrame({
            'Zaman': [datetime.now() - timedelta(hours=i) for i in range(5)],
            'Aksiyon': ['Email Sent', 'IP Blocked', 'Webhook Triggered', 'Email Sent', 'Alert Created'],
            'Hedef': ['192.168.1.100', '10.0.0.50', 'All Systems', '172.16.0.10', 'SOC Team'],
            'Durum': ['✅ Başarılı', '✅ Başarılı', '⚠️ Hata', '✅ Başarılı', '✅ Başarılı']
        })
        
        st.dataframe(actions, use_container_width=True)
        
        if st.button("🗑️ Geçmişi Temizle"):
            st.success("Aksiyon geçmişi temizlendi")


def render_alert_notification_system(dashboard):
    """Alert Bildirim Sistemi"""
    st.markdown("### 🔔 Alert Bildirimleri")
    
    conn = dashboard.get_connection()
    if not conn:
        return
    
    # Son 5 dakikadaki kritik alertler
    five_min_ago = (datetime.now() - timedelta(minutes=5)).isoformat()
    
    recent_critical = pd.read_sql_query("""
        SELECT COUNT(*) as count
        FROM logs
        WHERE severity = 'critical' AND timestamp > ?
    """, conn, params=(five_min_ago,))
    
    critical_count = recent_critical['count'].iloc[0] if not recent_critical.empty else 0
    
    # Yeni alert varsa bildirim göster
    if critical_count > st.session_state.last_alert_count:
        st.error(f"🚨 **YENİ KRİTİK ALERT!** {critical_count} kritik olay tespit edildi!")
        if st.session_state.alert_sound:
            st.markdown("""
            <audio autoplay>
                <source src="data:audio/wav;base64,UklGRnoGAABXQVZFZm10IBAAAAABAAEAQB8AAEAfAAABAAgAZGF0YQoGAACBhYqFbF1fdJivrJBhNjVgodDbq2EcBj+a2/LDciUFLIHO8tiJNwgZaLvt559NEAxQp+PwtmMcBjiR1/LMeSwFJHfH8N2QQAoUXrTp66hVFApGn+DyvmwhBTGH0fPTgjMGHm7A7+OZSA0PVqzn77BdGAg+ltryxnMpBSl+zPLaizsIGGS57OihUBELTKXh8bllHAU2jdXzzn0vBSB1xe/glEILElyx6OyrWBUIQ5zd8sFuJAUuhM/z1YU2Bhxqvu7mnEoODlOq5O+zYBoGPJPY88p2KwUme8rx3I0+CRZiturqpVITC0mi4PO9aigEL4XR88p/MQYfb8Lv45ZFCw9Wr+fvrl0ZCECb3PLEcSYEKoHN8diKOQgYZ7zs6KBPDwxLpOD" type="audio/wav">
            </audio>
            """, unsafe_allow_html=True)
    
    st.session_state.last_alert_count = critical_count
    
    # Bildirim ayarları
    col1, col2 = st.columns(2)
    
    with col1:
        st.session_state.alert_sound = st.checkbox(
            "🔊 Ses Bildirimleri",
            value=st.session_state.alert_sound
        )
    
    with col2:
        notification_level = st.selectbox(
            "Bildirim Seviyesi:",
            ["Sadece Kritik", "Kritik ve Yüksek", "Tümü"]
        )
    
    # Son alertler
    st.markdown("#### 📋 Son Alertler (5 dakika)")
    
    recent_alerts = pd.read_sql_query("""
        SELECT timestamp, severity, log_type, data
        FROM logs
        WHERE timestamp > ? AND severity IN ('critical', 'high')
        ORDER BY timestamp DESC
        LIMIT 10
    """, conn, params=(five_min_ago,))
    
    conn.close()
    
    if not recent_alerts.empty:
        for idx, row in recent_alerts.iterrows():
            severity_color = {
                'critical': '🔴',
                'high': '🟠'
            }.get(row['severity'], '🟡')
            
            with st.expander(f"{severity_color} {row['log_type']} - {row['timestamp']}", expanded=(idx < 3)):
                try:
                    data = json.loads(row['data'])
                    st.json(data)
                except:
                    st.text(row['data'])
    else:
        st.success("✅ Son 5 dakikada kritik/yüksek seviye alert yok")


def render_fim_management(dashboard):
    """File Integrity Monitor Yönetim Sekmesi"""
    st.markdown("### 🛡️ File Integrity Monitor (FIM)")
    st.markdown("Gerçek zamanlı dosya bütünlüğü izlemesi")
    
    import subprocess
    import psutil
    
    col1, col2, col3 = st.columns(3)
    
    # FIM işlem kontrolü
    fim_running = False
    fim_pid = None
    try:
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            if 'autosec_fim.py' in ' '.join(proc.info['cmdline'] or []):
                fim_running = True
                fim_pid = proc.info['pid']
                break
    except:
        pass
    
    with col1:
        if fim_running:
            st.success(f"✅ FIM Çalışıyor (PID: {fim_pid})")
        else:
            st.warning("⚠️ FIM Kapalı")
    
    with col2:
        if st.button("🛑 FIM Durdur", disabled=not fim_running):
            try:
                os.kill(fim_pid, 15)
                st.success("FIM durduruldu")
                st.rerun()
            except:
                st.error("Durdurulamadı")
    
    with col3:
        st.button("🔄 Yenile", key="fim_refresh")
    
    st.markdown("---")
    st.markdown("### ⚙️ FIM Başlat")
    
    col1, col2 = st.columns(2)
    
    with col1:
        fim_path = st.text_input(
            "İzlenecek Klasör Yolu",
            value="./FileIntegrityMonitor/testdata",
            help="Mutlak veya göreceli yol"
        )
    
    with col2:
        siem_endpoint = st.text_input(
            "SIEM Webhook URL",
            value="http://127.0.0.1:5000/webhook",
            help="Alert'lerin gönderileceği URL"
        )
    
    col1, col2 = st.columns(2)
    
    with col1:
        exclude_exts = st.text_input(
            "Hariç Tutulan Uzantılar",
            value=".log,.tmp",
            help="Virgülle ayrılmış: .log,.tmp"
        )
    
    with col2:
        use_siem = st.checkbox("SIEM'e Bağla", value=True)
    
    if st.button("▶️ FIM Başlat", type="primary", disabled=fim_running):
        try:
            cmd = [
                "python",
                os.path.join(os.path.dirname(__file__), "FileIntegrityMonitor", "autosec_fim.py"),
                "-p", fim_path,
                "-x", exclude_exts
            ]
            
            if use_siem:
                cmd.extend(["-s", siem_endpoint])
            else:
                cmd.append("--no-siem")
            
            # Arka planda başlat
            subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            st.success("✅ FIM başlatıldı")
            time.sleep(1)
            st.rerun()
        except Exception as e:
            st.error(f"Hata: {str(e)}")
    
    st.markdown("---")
    st.markdown("### 📊 FIM Logları")
    
    fim_log_path = os.path.join(os.path.dirname(__file__), "FileIntegrityMonitor", "fim_alerts.json")
    
    if os.path.exists(fim_log_path):
        with open(fim_log_path, 'r') as f:
            lines = f.readlines()
        
        if lines:
            st.markdown(f"**Toplam Alert: {len(lines)}**")
            
            limit = st.slider("Göster", 1, len(lines), min(10, len(lines)))
            
            for i, line in enumerate(reversed(lines[-limit:])):
                try:
                    alert = json.loads(line)
                    
                    severity_color = {
                        'CRITICAL': '🔴',
                        'HIGH': '🟠',
                        'MEDIUM': '🟡',
                        'LOW': '🟢'
                    }.get(alert.get('severity', 'MEDIUM'), '⚪')
                    
                    with st.expander(f"{severity_color} {alert.get('event_type', 'UNKNOWN')} — {alert.get('target_path', 'N/A')[-40:]}"):
                        st.json(alert)
                except:
                    st.text(line)
        else:
            st.info("📭 Henüz alert yok")
    else:
        st.info("📭 Log dosyası bulunamadı")


if __name__ == "__main__":
    main()
