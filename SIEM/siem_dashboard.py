"""Kurumsal seviye SIEM/SOC suite için Streamlit UI."""
from __future__ import annotations
import os
import json
import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime

from core.config import SIEMConfig
from core.db import SQLiteDB
from core.migrations import run_sqlite_migrations
from core.repository import SIEMRepository
from services.threat_intel import ThreatIntelService
from services.fim import FIMService
from services.assets import AssetService
from services.vuln import VulnerabilityService
from services.analytics import AnalyticsService
from services.correlation import CorrelationService
from services.rules_engine import RulesEngine
from services.ml import AnomalyDetectionService
from services.ingestion import IngestionService
from services.incident import IncidentService
from services.soc_tools import AlertTriageService, ThreatHuntingService, PlaybookService, MetricsService
from utils.logging import setup_logging
from utils.mitre import map_msg_to_technique
from ui.theme import setup_page

setup_logging()
config = SIEMConfig.load()
setup_page()

db = SQLiteDB(config.db_path)
with db.connect() as conn:
    run_sqlite_migrations(conn)
conn = db.connect()
repo = SIEMRepository(conn)

# Servisler
ti_service = ThreatIntelService(repo, abuse_key=config.abuseipdb_key, otx_key=config.otx_key, vt_key=config.virustotal_key)
fim_service = FIMService(conn, config.fim_path)
asset_service = AssetService(repo)
vuln_service = VulnerabilityService(conn)
analytics = AnalyticsService()
correlation = CorrelationService()
rules_engine = RulesEngine("rules/rules.yaml")
anomaly_service = AnomalyDetectionService()
ingestion_service = IngestionService(repo)
incident_service = IncidentService(repo)
alert_triage = AlertTriageService(repo)
threat_hunting = ThreatHuntingService(repo)
playbook_service = PlaybookService()
metrics_service = MetricsService(repo)

# Yardımcı fonksiyonlar
def load_logs() -> pd.DataFrame:
    return pd.DataFrame(repo.get_logs())

def ensure_demo(df: pd.DataFrame) -> pd.DataFrame:
    if not df.empty or not config.auto_seed_demo:
        return df
    from random import choice, randint
    severities = ['critical', 'high', 'medium', 'low']
    sources = ['fw01', 'ids-core', 'web01', 'mailgw', 'vpn']
    ips = ['10.0.0.5', '10.0.0.15', '192.168.1.50', '172.16.2.7', '45.33.22.11']
    severity_score = {'critical': 90, 'high': 70, 'medium': 40, 'low': 10}
    now = datetime.now()
    for i in range(50):
        sev = choice(severities)
        ip = choice(ips)
        src = choice(sources)
        ts = (now - pd.Timedelta(minutes=i * 5)).isoformat()
        base = severity_score[sev]
        jitter = randint(-5, 10)
        risk = max(0, min(100, base + jitter))
        repo.insert_log({"timestamp": ts, "severity": sev, "source": src, "ip": ip, "msg": f"{sev.upper()} event from {src} for {ip}", "risk_score": risk})
    return load_logs()

# Canlı yenileme
st_autorefresh = st.sidebar.checkbox("Canlı yenile (manuel) ☑", value=False)

# Sidebar
st.sidebar.title("SIEM X PRO")
menu = st.sidebar.selectbox("Navigasyon", ["Dashboard", "Alert Triage", "Threat Hunting", "Playbooks", "Metrikler", "Tehdit İstihbaratı", "Varlıklar", "Güvenlik Açıkları", "FIM", "Olaylar", "Ayarlar"])
quick_ip = st.sidebar.text_input("Hızlı IP Engelle", "192.168.1.50")
if st.sidebar.button("Engelle (Simule)"):
    st.sidebar.success(f"{quick_ip} engellendi (simule)")
global_search = st.sidebar.text_input("Global arama (IP / msg)")

df_logs = ensure_demo(load_logs())
if global_search:
    df_logs = df_logs[df_logs.apply(lambda r: global_search.lower() in str(r.values).lower(), axis=1)]

# Dashboard
if menu == "Dashboard":
    st.title("🛰️ Security Operations Center")
    anomalies_df = anomaly_service.score(df_logs)
    anomaly_count = int(anomalies_df["anomaly"].sum()) if not anomalies_df.empty else 0

    c1, c2, c3, c4 = st.columns(4)
    with c1: st.metric("Toplam Olay", len(df_logs))
    with c2: st.metric("Kritik Tehdit", len(df_logs[df_logs['severity'] == 'critical']))
    with c3: st.metric("Anomali", anomaly_count)
    with c4: st.metric("Aktif Varlık", df_logs['ip'].nunique() if not df_logs.empty else 0)

    col_a, col_b = st.columns([2, 1])
    with col_a:
        st.subheader("📊 Tehdit Trendi")
        fig = px.area(df_logs, x='timestamp', y='risk_score', color='severity', template="plotly_dark")
        st.plotly_chart(fig, width='stretch')
        st.subheader("🔥 Severity Heatmap")
        heat = analytics.severity_heatmap(df_logs)
        if not heat.empty:
            st.dataframe(heat)
    with col_b:
        st.subheader("🚩 En Riskli IP'ler")
        risk_ips = df_logs.groupby('ip')['risk_score'].sum().sort_values(ascending=False).head(5)
        st.bar_chart(risk_ips)
        st.subheader("📜 Kural & Korelasyon")
        findings = rules_engine.evaluate(df_logs)
        port_scans = correlation.detect_port_scans(df_logs)
        failed = correlation.detect_failed_logins(df_logs)
        st.write(f"Kural: {len(findings)} | Port scan: {len(port_scans)} | Failed login: {len(failed)}")

    st.subheader("⚡ Gerçek Zamanlı Olay Akışı")
    if not df_logs.empty:
        df_view = df_logs.copy()
        df_view["mitre"] = df_view["msg"].apply(map_msg_to_technique)
        st.dataframe(df_view.head(100))

    st.subheader("🤖 Anomali Listesi")
    if not anomalies_df.empty and anomaly_count:
        st.dataframe(anomalies_df[anomalies_df["anomaly"]].head(50))
    else:
        st.caption("Anomali tespit edilmedi")

# Alert Triage
elif menu == "Alert Triage":
    st.title("🎯 Alert Önceliklendirme ve Triage")
    st.info("Alertleri otomatik olarak önceliklendirir ve SOC analistlerine gösterir")
    
    prioritized = alert_triage.prioritize_alerts(df_logs)
    if not prioritized.empty:
        st.subheader("🔴 Yüksek Öncelikli Alertler")
        high_priority = prioritized[prioritized["triage_score"] > 70]
        st.dataframe(high_priority[["timestamp", "severity", "ip", "msg", "risk_score", "triage_score"]].head(20))
        
        st.subheader("📊 Triage Skoru Dağılımı")
        fig = px.histogram(prioritized, x="triage_score", color="severity", nbins=20)
        st.plotly_chart(fig, width='stretch')
    else:
        st.info("Henüz alert yok")

# Threat Hunting
elif menu == "Threat Hunting":
    st.title("🔍 Proaktif Tehdit Avı")
    
    hunt_tab1, hunt_tab2 = st.tabs(["IOC Arama", "Şüpheli Desen Tespiti"])
    
    with hunt_tab1:
        st.subheader("IOC Bazlı Hunting")
        ioc_input = st.text_input("IOC (IP/Hash/Domain)")
        ioc_type = st.selectbox("IOC Tipi", ["ip", "hash", "domain"])
        if st.button("Ara") and ioc_input:
            results = threat_hunting.hunt_by_ioc(ioc_input, ioc_type)
            st.write(f"✅ {len(results)} sonuç bulundu")
            if results:
                st.dataframe(pd.DataFrame(results))
    
    with hunt_tab2:
        st.subheader("Otomatik Şüpheli Desen Analizi")
        if st.button("Analiz Başlat"):
            findings = threat_hunting.hunt_suspicious_patterns(df_logs)
            if findings:
                st.json(findings)
                if "high_volume_ips" in findings:
                    st.warning(f"⚠️ Yüksek hacimli IP'ler tespit edildi: {len(findings['high_volume_ips'])}")
                if "failed_login_spike" in findings:
                    st.error(f"🚨 Failed login spike: {findings['failed_login_spike']} denemesi")
                if "night_activity_count" in findings:
                    st.info(f"🌙 Gece aktivitesi: {findings['night_activity_count']} olay")
            else:
                st.success("Şüpheli desen bulunamadı")

# Playbooks
elif menu == "Playbooks":
    st.title("📚 Olay Müdahale Playbook'ları")
    st.caption("Standart olay müdahale prosedürleri")
    
    available = playbook_service.list_playbooks()
    selected_scenario = st.selectbox("Senaryo Seç", available)
    
    playbook = playbook_service.get_playbook(selected_scenario)
    st.subheader(f"📖 {playbook['title']}")
    
    for step in playbook["steps"]:
        st.markdown(f"- {step}")
    
    if st.button("Bu Playbook için Olay Oluştur"):
        inc_id = incident_service.create(playbook["title"], "high", tags=selected_scenario)
        st.success(f"Olay oluşturuldu: #{inc_id}")

# Metrikler
elif menu == "Metrikler":
    st.title("📊 SOC Metrikleri ve KPI'lar")
    
    kpis = metrics_service.calculate_kpis(df_logs)
    if kpis:
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Toplam Olay", kpis.get("total_events", 0))
            st.metric("Kritik Olaylar", kpis.get("critical_events", 0))
        with col2:
            st.metric("Yüksek Olaylar", kpis.get("high_events", 0))
            st.metric("Ort. Risk Skoru", round(kpis.get("avg_risk_score", 0), 2))
        with col3:
            st.metric("Max Risk Skoru", kpis.get("max_risk_score", 0))
        
        st.subheader("📈 Severity Dağılımı")
        if "severity_distribution" in kpis:
            st.bar_chart(kpis["severity_distribution"])
        
        st.subheader("🔝 En Aktif Kaynaklar")
        if "top_sources" in kpis:
            st.json(kpis["top_sources"])
    else:
        st.info("Henüz yeterli veri yok")

# Threat Intel
elif menu == "Tehdit İstihbaratı":
    st.title("🔍 Tehdit İstihbaratı Merkezi")
    target_ip = st.text_input("Sorgulanacak IP Adresi:", placeholder="8.8.8.8")
    if st.button("İtibarı Sorgula") and target_ip:
        with st.spinner("IOC Havuzları taranıyor..."):
            res = ti_service.enrich_ip(target_ip)
            if res['status'] == "ZARARLI":
                st.error(f"⚠️ {target_ip} ZARARLI! (Risk: {res['score']})")
                st.button("Tüm Sistemlerde Engelle")
            else:
                st.success(f"✅ {target_ip} Temiz görünüyor.")
            st.json(res)
    st.subheader("📈 TI Geçmişi")
    if target_ip:
        st.dataframe(pd.DataFrame(repo.ti_history(target_ip)))

# Varlıklar
elif menu == "Varlıklar":
    st.title("🧭 Varlık Envanteri")
    if st.button("Otomatik Keşfet (Simule)"):
        asset_service.simulate_discovery()
    assets_df = pd.DataFrame(asset_service.list_assets())
    st.dataframe(assets_df)
    if not assets_df.empty:
        selection = st.selectbox("Varlık detay", assets_df["hostname"])
        asset_row = assets_df[assets_df["hostname"] == selection].iloc[0]
        st.json(asset_row.to_dict())

# Güvenlik Açıkları
elif menu == "Güvenlik Açıkları":
    st.title("🕵️ Dahili Güvenlik Açığı Tarayıcı")
    assets = asset_service.list_assets()
    ids = [a['id'] for a in assets]
    if st.button("Ağı Tara"):
        vulns = vuln_service.scan_assets(ids)
        st.success(f"{len(vulns)} bulgu eklendi")
    st.dataframe(pd.DataFrame(repo.list_vulnerabilities()))

# FIM
elif menu == "FIM":
    st.title("🛡️ Dosya Bütünlük İzleyici")
    
    # FIM Durumu
    col1, col2 = st.columns([1, 3])
    with col1:
        fim_status = st.toggle("FIM Aktif", value=config.fim_enabled)
        if fim_status != config.fim_enabled:
            config.fim_enabled = fim_status
            config.save()
            st.success(f"FIM {'etkinleştirildi' if fim_status else 'devre dışı bırakıldı'}")
    
    with col2:
        if not config.fim_enabled:
            st.warning("⚠️ FIM şu anda devre dışı")
    
    # Default Klasör Kısayolları
    st.subheader("📁 Hızlı Klasör Ekle")
    default_dirs = {
        "Mevcut dizin": os.getcwd(),
        "FIM test alanı": os.path.join(os.getcwd(), "fim_test_area"),
        "FileIntegrityMonitor testdata": os.path.join(os.getcwd(), "FileIntegrityMonitor", "testdata"),
        "/tmp": "/tmp",
        "Home dizini": os.path.expanduser("~"),
    }
    
    col_a, col_b, col_c = st.columns([2, 1, 1])
    with col_a:
        quick_dir = st.selectbox("Hazır klasörler", list(default_dirs.keys()))
    with col_b:
        if st.button("➕ Ekle"):
            selected_path = default_dirs[quick_dir]
            if selected_path not in config.fim_watched_dirs:
                config.fim_watched_dirs.append(selected_path)
                config.save()
                st.success(f"Eklendi: {selected_path}")
            else:
                st.info("Bu klasör zaten izleniyor")
    with col_c:
        st.write("")  # boşluk
    
    # Manuel Klasör Ekleme
    st.subheader("🔧 Manuel Klasör Ekle")
    custom_dir = st.text_input("Klasör yolu", placeholder="/path/to/directory")
    if st.button("Manuel Ekle") and custom_dir:
        if os.path.exists(custom_dir):
            if custom_dir not in config.fim_watched_dirs:
                config.fim_watched_dirs.append(custom_dir)
                config.save()
                st.success(f"Eklendi: {custom_dir}")
            else:
                st.info("Bu klasör zaten izleniyor")
        else:
            st.error("❌ Klasör bulunamadı")
    
    # İzlenen Klasörler Listesi
    st.subheader("👁️ İzlenen Klasörler")
    if config.fim_watched_dirs:
        for idx, watched_dir in enumerate(config.fim_watched_dirs):
            col_path, col_action = st.columns([4, 1])
            with col_path:
                exists = "✅" if os.path.exists(watched_dir) else "❌"
                st.text(f"{exists} {watched_dir}")
            with col_action:
                if st.button("🗑️ Kaldır", key=f"remove_{idx}"):
                    config.fim_watched_dirs.remove(watched_dir)
                    config.save()
                    st.rerun()
    else:
        st.info("ℹ️ Henüz izlenen klasör eklenmemiş. Yukarıdan ekleyebilirsiniz.")
    
    # Tarama Kontrolü
    st.subheader("🚀 Tarama")
    scan_col1, scan_col2 = st.columns(2)
    with scan_col1:
        if st.button("🔍 Tüm Klasörleri Tara", disabled=not config.fim_enabled or not config.fim_watched_dirs):
            if config.fim_watched_dirs:
                with st.spinner("Tarama yapılıyor..."):
                    results = fim_service.baseline_regen(target_dirs=config.fim_watched_dirs)
                    st.session_state['fim_results'] = results
                    st.success(f"✅ Tarama tamamlandı: {len(results)} değişiklik bulundu")
    
    with scan_col2:
        if st.button("🔄 Baseline Sıfırla", disabled=not config.fim_enabled):
            cur = conn.cursor()
            cur.execute("DELETE FROM fim_baseline")
            conn.commit()
            st.success("Baseline temizlendi")
    
    # Son Tarama Sonuçları
    if 'fim_results' in st.session_state and st.session_state['fim_results']:
        st.subheader("📋 Son Tarama Sonuçları")
        results_df = pd.DataFrame(st.session_state['fim_results'])
        
        # Status filtreleme
        status_filter = st.multiselect(
            "Duruma göre filtrele",
            options=["CREATED", "MODIFIED", "DELETED"],
            default=["CREATED", "MODIFIED", "DELETED"]
        )
        
        if status_filter:
            filtered_df = results_df[results_df['status'].isin(status_filter)]
            st.dataframe(filtered_df)
            
            # Export butonu
            if st.button("💾 Rapor İndir (JSON)"):
                export_path = fim_service.export_report(st.session_state['fim_results'], "fim_report.json")
                st.success(f"Rapor kaydedildi: {export_path}")
        else:
            st.info("Filtre seçin")
    
    # FIM Geçmişi
    st.subheader("📜 Son FIM Olayları")
    fim_history = pd.DataFrame(repo.recent_fim_events(limit=100))
    if not fim_history.empty:
        st.dataframe(fim_history)

# Incidents
elif menu == "Olaylar":
    st.title("📁 Olay Masası")
    title = st.text_input("Başlık")
    sev = st.selectbox("Öncelik", ["critical", "high", "medium", "low"])
    if st.button("Oluştur") and title:
        inc_id = incident_service.create(title, sev)
        st.success(f"Olay oluşturuldu: {inc_id}")
    incidents_df = pd.DataFrame(incident_service.list())
    st.dataframe(incidents_df)
    if not incidents_df.empty:
        inc_sel = st.selectbox("İncelenecek olay", incidents_df["id"])
        note = st.text_area("Not ekle")
        if st.button("Not Kaydet") and note:
            incident_service.add_note(int(inc_sel), "analyst", note)
        upload = st.file_uploader("Ek yükle")
        if upload:
            out_path = os.path.join("attachments", upload.name)
            os.makedirs("attachments", exist_ok=True)
            with open(out_path, "wb") as f:
                f.write(upload.getbuffer())
            incident_service.add_attachment(int(inc_sel), upload.name, out_path)
            st.success("Ek kaydedildi")
        st.subheader("Notlar")
        st.dataframe(pd.DataFrame(incident_service.notes(int(inc_sel))))
        st.subheader("Ekler")
        st.dataframe(pd.DataFrame(incident_service.attachments(int(inc_sel))))

# Ayarlar
elif menu == "Ayarlar":
    st.title("⚙️ Sistem Yapılandırması")
    st.json({"db_path": config.db_path, "fim_path": config.fim_path, "risk_threshold": config.risk_threshold, "auto_seed_demo": config.auto_seed_demo})
    st.caption("İleri seviye ayarlar için siem_config.json dosyasını düzenleyin.")
    if st.button("Ingestion kuyruğunu işle"):
        processed = ingestion_service.flush()
        st.success(f"{processed} olay işlendi")