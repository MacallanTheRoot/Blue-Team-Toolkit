<div align="center">

# �️ ThreatWeave
### Kurumsal Düzeyde Güvenlik Bilgi ve Olay Yönetimi Platformu

[![Python 3.13](https://img.shields.io/badge/python-3.13-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red.svg)](https://attack.mitre.org/)

**Gelişmiş log analizi, ML tabanlı anomali tespiti, proaktif tehdit avı ve SOC operasyon platformu**

[Hızlı Başlangıç](#-hızlı-başlangıç) • [Özellikler](#-özellikler) • [Kurulum](#-kurulum) • [Dashboard](#-web-dashboard) • [Dokümantasyon](#-kullanım-kılavuzu)

</div>

---

## 📖 İçindekiler

- [Genel Bakış](#-genel-bakış)
- [Özellikler](#-özellikler)
- [Kurulum](#-kurulum)
- [Hızlı Başlangıç](#-hızlı-başlangıç)
- [Web Dashboard](#-web-dashboard)
- [SOC Workflow](#-soc-workflow)
- [Kullanım Kılavuzu](#-kullanım-kılavuzu)
- [Mimari](#️-mimari)
- [Katkıda Bulunma](#-katkıda-bulunma)

---

## 🎯 Genel Bakış

**Silent Watcher SIEM**, SOC (Security Operations Center) ekipleri için tasarlanmış, modern ve kapsamlı bir güvenlik operasyonu platformudur. Gerçek dünya senaryolarında kullanılabilir tehdit tespiti, olay müdahalesi ve sürekli güvenlik izleme yetenekleri sunar.

### 🌟 Neden Silent Watcher?

- ✅ **SOC Odaklı**: Gerçek SOC analisti iş akışları için tasarlandı
- ✅ **Açık Kaynak & Ücretsiz**: Ticari SIEM maliyetleri olmadan kurumsal özellikler
- ✅ **Kolay Kurulum**: Dakikalar içinde çalışır duruma gelir
- ✅ **ML Destekli**: IsolationForest algoritması ile anomali tespiti
- ✅ **Modern Arayüz**: Streamlit tabanlı dark SOC teması
- ✅ **Türkçe Destek**: Tamamen Türkçe arayüz ve dokümantasyon
- ✅ **Genişletilebilir**: Modüler mimari, özel servisler ve kurallar eklemeye hazır

---

## 🚀 Özellikler
<tr>
<td width="50%">

<table>
<tr>
<td width="50%">

### 🔍 Tehdit Tespiti
- **ML Anomali Tespiti**
  - IsolationForest algoritması
  - Otomatik model eğitimi
  - Risk skorlaması
- **Kural Tabanlı Tespit**
  - Özelleştirilebilir kurallar
  - Port scan tespiti
  - Failed login tracking
- **MITRE ATT&CK Mapping**
  - Otomatik teknik eşleştirme
  - Taktik kategorileri
  
</td>
<td width="50%">

### 🎯 SOC Araçları
- **Alert Triage**
  - Otomatik önceliklendirme
  - Triage skoru hesaplama
  - Akıllı filtreleme
- **Threat Hunting**
  - IOC bazlı arama (IP/Hash/Domain)
  - Şüpheli desen tespiti
  - Gece aktivitesi analizi
- **Playbook Yönetimi**
  - 4 hazır olay müdahale playbook'u
  - Malware, Data Exfiltration, Brute Force, Ransomware

</td>
</tr>
<tr>
<td>

### 📊 Görselleştirme
- **Gerçek Zamanlı Dashboard**
  - Canlı metrikler
  - İnteraktif grafikler (Plotly)
  - Dark SOC teması
- **Analitik**
  - Severity heatmap
  - Risk trend analizi
  - IP itibar skorlaması
- **KPI Metrikleri**
  - Toplam/kritik olay sayısı
  - Ortalama risk skoru
  - En aktif kaynaklar

</td>
<td>

### 🛡️ Varlık & Güvenlik
- **Varlık Envanteri**
  - Otomatik keşif (simulated)
  - Hostname, IP, OS tracking
- **Güvenlik Açığı Tarama**
  - Dahili zafiyet tarayıcı
  - CVE tracking
- **Dosya Bütünlük İzleme (FIM)**
  - Çoklu klasör izleme
  - Baseline karşılaştırma
  - Değişiklik alertleri

</td>
</tr>
<tr>
<td>

### 🚨 Olay Yönetimi
- **Incident Response**
  - Olay oluşturma ve takip
  - Not sistemi (analyst notes)
  - Dosya ekleri (attachments)
- **Tehdit İstihbaratı**
  - IP itibar sorgulama
  - IOC havuzları
  - Tehdit beslemeleri
- **Korelasyon Motoru**
  - Port scan tespiti
  - Failed login korelasyonu
  - Zaman bazlı analiz

</td>
<td>

### ⚙️ Mimari & Entegrasyon
- **Modüler Yapı**
  - core/, services/, ui/, utils/
  - Kolay genişletme
- **Veritabanı**
  - SQLite (default)
  - PostgreSQL desteği
- **API & Forwarder**
  - REST API endpoint'leri
  - Log forwarding (Syslog, HTTP)
  - Ingestion queue

</td>
</tr>
</table>

---

## 💻 Kurulum

### Sistem Gereksinimleri

- **İşletim Sistemi**: Linux, macOS, Windows
- **Python**: 3.13+ (önerilen 3.11+)
- **RAM**: Minimum 2GB, önerilen 4GB+
- **Disk**: 1GB+ (log hacmine bağlı)

### Adım 1: Repository'yi Klonlayın

```bash
git clone https://github.com/yourusername/threatweave.git
cd threatweave/SIEM
```

### Adım 2: Virtual Environment Oluşturun

```bash
# Virtual environment oluştur
python3 -m venv macallan

# Aktive et (Linux/macOS)
source macallan/bin/activate

# Aktive et (Windows)
macallan\Scripts\activate
```

### Adım 3: Bağımlılıkları Yükleyin

```bash
pip install -r requirements.txt
```

### 📦 Temel Bağımlılıklar

| Paket | Versiyon | Kullanım |
|-------|----------|----------|
| **streamlit** | ≥1.28.0 | Web dashboard |
| **pandas** | ≥2.1.0 | Veri analizi |
| **scikit-learn** | ≥1.3.0 | ML anomali tespiti |
| **plotly** | ≥5.17.0 | İnteraktif görselleştirme |
| **numpy** | ≥1.24.0 | Numerical computing |

---

## ⚡ Hızlı Başlangıç

### 🎨 Web Dashboard ile Başlayın (Önerilen)

En hızlı yol - grafiksel arayüz ile:

```bash
# Dashboard'u başlat
streamlit run siem_dashboard.py

# Tarayıcıda otomatik açılacak: http://localhost:8501
```

### 📋 İlk Kullanım

1. **Dashboard** sayfasında otomatik demo log'lar yüklenecek
2. **FIM** sayfasından dosya izleme klasörleri ekleyin
3. **Alert Triage** ile öncelikli alertleri görüntüleyin
4. **Threat Hunting** ile IOC araması yapın
5. **Playbooks** ile olay müdahale senaryolarını inceleyin

---

## 📊 Web Dashboard

ThreatWeave'in web arayüzü 11 ana modülden oluşur:
python siem_hunter.py monitor --file /var/log/auth.log --type auth

# Özel izleme aralığı (saniye)
python siem_hunter.py monitor --file /var/log/syslog --interval 0.5
```

#### 3️⃣ Tehdit Avı Yap

```bash
# Otomatik tehdit avı sorgularını çalıştır
python siem_hunter.py hunt

# Aranacaklar:
# ✓ Brute force saldırıları
# ✓ Web saldırı paternleri (SQLi, XSS)
# ✓ Şüpheli user-agent'lar
# ✓ Yetki yükseltme denemeleri
```

#### 4️⃣ ML Model Eğitimi

```bash
# Anomali tespit modeli eğit
python siem_hunter.py train

# Baseline logları ile eğit
python siem_hunter.py train --file baseline_traffic.log
```

#### 5️⃣ Rapor Oluştur

```bash
# Kapsamlı güvenlik raporu
python siem_hunter.py report

# Alert'leri görüntüle
python siem_hunter.py alerts --severity critical
```

### 🎬 5 Dakikada Demo

```bash
# 1. Demo verisini yükle
python siem_hunter.py ingest --file demo_logs.txt

# 2. Tehdit avı yap
python siem_hunter.py hunt

# 3. Rapor oluştur
python siem_hunter.py report

# 4. Web dashboard'u aç
streamlit run siem_dashboard.py
```

---

## 🎨 Web Dashboard

Modern, interaktif Streamlit tabanlı güvenlik izleme arayüzü.

### 🌟 Dashboard Özellikleri

<table>
<tr>
<td width="33%">

#### 📊 Ana Sayfa
- Gerçek zamanlı KPI'lar
- Log istatistikleri
- Anomali grafikleri
- Zaman serisi analizi
- MITRE ATT&CK dağılımı

</td>
<td width="33%">

#### 🔍 Log Görüntüleyici
- Gelişmiş filtreleme
- Tam metin arama
- Tip/Önem filtreleri
- Export özellikleri
- JSON görüntüleyici

</td>
<td width="33%">

#### 🎯 Tehdit Avı
- Hazır sorgular
- Özel SQL sorguları
- Pattern matching
- IOC bulma
- Korelasyon analizi

</td>
</tr>
<tr>
<td>

#### 🔴 Canlı İzleme
- Otomatik yenileme (5-60s)
- Son 1 dakika aktivite
- Real-time metrikler
- Alert bildirimleri
- Ses uyarıları

</td>
<td>

#### 🌐 Network Haritası
- IP bağlantı analizi
- Trafik görselleştirme
- Treemap graph
- Top IP listesi
- Threat level mapping

</td>
<td>

#### 🔍 IOC Lookup
- IP/Domain/Hash arama
- Veritabanı sorguları
- VirusTotal entegre (yakında)
- AbuseIPDB desteği (yakında)
- Enrichment özellikleri

</td>
</tr>
<tr>
<td>

#### 🛠️ Özel Sorgu
- SQL query builder
- Hazır şablonlar
- Custom queries
- CSV/JSON export
- Result visualization

</td>
<td>

#### 📦 Export/Import
- CSV export
- JSON export
- Zaman aralığı seçimi
- Filtre desteği
- Batch processing

</td>
<td>

#### 🤖 Otomatik Yanıt
- Alert kuralları
- Email bildirimleri
- Webhook entegrasyonu
- Firewall simülasyonu
- Aksiyon geçmişi

</td>
</tr>
</table>

### ✨ Yeni Özellikler

#### 🔔 Alert Bildirim Sistemi
- Gerçek zamanlı kritik alert bildirimleri
- Ses uyarıları (opsiyonel)
- Son 5 dakika alert özeti
- Otomatik alert tracking
- Bildirim seviyesi ayarları

#### 🌐 Network Graph Widget
- IP bağlantı haritası
- Treemap görselleştirme
- Trafik analizi
- Top 10 aktif IP'ler
- Severity bazlı renklendirme

#### 🔍 IOC Lookup & Enrichment
- Multi-platform IOC arama
- IP/Domain/Hash lookup
- Veritabanı entegrasyonu
- Threat intelligence (yakında)
- Otomatik enrichment

#### 🛠️ Custom Query Builder
- Görsel sorgu oluşturucu
- 5+ hazır şablon
- SQL syntax highlighting
- İnteraktif sonuç tabloları
- Export özellikleri (CSV/JSON)

#### 📦 Veri Export/Import
- Toplu veri export
- Zaman aralığı filtreleme
- Severity filtreleri
- CSV/JSON/Excel desteği
- Automated scheduling (yakında)

#### 🤖 Otomatik Yanıt Sistemi
- Rule-based automation
- Email alerting
- Webhook notifications
- Simüle firewall blocks
- Aksiyon audit trail

### 🚀 Dashboard Başlatma

```bash
# Yöntem 1: Script ile
./start_dashboard.sh

# Yöntem 2: Doğrudan
streamlit run siem_dashboard.py

# Yöntem 3: Özel port
streamlit run siem_dashboard.py --server.port 8080
```

### 📸 Ekran Görüntüleri

```
┌─────────────────────────────────────────────────────────┐
│ 🔵 Silent Watcher SIEM Dashboard                        │
├─────────────────────────────────────────────────────────┤
│                                                           │
│  📊 METRIKLER                    📈 GRAFIKLER            │
│  ├─ Toplam Log: 1,247           ├─ Zaman Serisi          │
│  ├─ Alert: 18                   ├─ Log Dağılımı          │
│  ├─ Kritik: 3                   ├─ MITRE ATT&CK          │
│  └─ Anomali: 23                 └─ Önem Grafikleri       │
│                                                           │
│  🔍 LOG GÖRÜNTÜLEYİCİ                                    │
│  [Filtreler: Tip ▼ | Önem ▼ | Arama: ___________]       │
│  ┌─────────────────────────────────────────────┐        │
│  │ 2025-12-27 10:30:15 | CRITICAL | apache     │        │
│  │ 192.168.1.101 - SQLi attempt detected       │        │
│  └─────────────────────────────────────────────┘        │
│                                                           │
└─────────────────────────────────────────────────────────┘
```

**Detaylı kullanım**: [DASHBOARD.md](DASHBOARD.md)

---

## 📚 Kullanım Kılavuzu

### 🔧 Temel Komutlar

#### Log Yükleme (ingest)

```bash
# Otomatik format tespiti
python siem_hunter.py ingest --file /var/log/auth.log

# Desteklenen formatlar
python siem_hunter.py ingest --file access.log --type apache
python siem_hunter.py ingest --file access.log --type nginx
python siem_hunter.py ingest --file syslog --type syslog
python siem_hunter.py ingest --file events.json --type json
python siem_hunter.py ingest --file auth.log --type auth
```

#### Gerçek Zamanlı İzleme (monitor)

```bash
# Temel izleme
python siem_hunter.py monitor --file /var/log/auth.log

# Özel aralık (saniye)
python siem_hunter.py monitor --file /var/log/syslog --interval 0.1

# Yüksek frekanslı izleme
python siem_hunter.py monitor --file /var/log/apache2/access.log --interval 0.5
```

#### Tehdit Avı (hunt)

```bash
# Tüm hazır sorguları çalıştır
python siem_hunter.py hunt

# Tespit edilen:
# ✓ Başarısız login denemeleri (brute force)
# ✓ Şüpheli user-agent'lar (sqlmap, nmap, nikto)
# ✓ Web saldırıları (SQLi, XSS, Path Traversal)
# ✓ Port scan aktiviteleri
# ✓ Yetki yükseltme denemeleri
```

#### ML Model Eğitimi (train)

```bash
# Mevcut veritabanı ile eğit
python siem_hunter.py train

# Baseline logları ile eğit
python siem_hunter.py train --file baseline_normal.log

# Model bilgisi
# ✓ Algoritma: Isolation Forest
# ✓ Anomali skorları otomatik hesaplanır
# ✓ Eşik değer: Otomatik belirlenir
```

#### Alert Yönetimi (alerts)

```bash
# Tüm alert'leri göster
python siem_hunter.py alerts

# Önem derecesine göre filtrele
python siem_hunter.py alerts --severity critical
python siem_hunter.py alerts --severity high
python siem_hunter.py alerts --severity medium
python siem_hunter.py alerts --severity info
```

#### Raporlama (report)

```bash
# Kapsamlı güvenlik raporu
python siem_hunter.py report

# Rapor içeriği:
# ✓ Veritabanı istatistikleri
# ✓ Alert özeti
# ✓ MITRE ATT&CK dağılımı
# ✓ En çok görülen tehditler
# ✓ IOC listeleri
```

### 🎯 Gelişmiş Kullanım

#### Özel Veritabanı Yolu

```bash
python siem_hunter.py ingest --file logs.txt --db /custom/path/siem.db
```

#### Sigma Kuralları ile Çalışma

```bash
# Özel Sigma kural dizini
python siem_hunter.py ingest --file logs.txt --sigma-rules /path/to/rules/

# Örnek kural yapısı:
# sigma_rules/
# ├── web_attacks/
# │   ├── sql_injection.yml
# │   └── xss_attempt.yml
# └── network/
#     └── port_scan.yml
```

#### Log Yönlendiricilerle Entegrasyon

```bash
# rsyslog yapılandırması
# /etc/rsyslog.conf
*.* @@localhost:514

# syslog-ng yapılandırması
destination d_siem {
    file("/var/log/siem/aggregated.log");
};

# Toplanmış logu izle
python siem_hunter.py monitor --file /var/log/siem/aggregated.log
```

---

## 🔍 Tespit Kuralları

Silent Watcher, yerleşik ve özelleştirilebilir tespit kuralları ile geniş bir tehdit yelpazesini tanımlayabilir.

### 🛡️ Yerleşik Tespit Paternleri (7+ Kural)

<table>
<tr>
<th width="30%">Kural Adı</th>
<th width="15%">MITRE ID</th>
<th width="15%">Önem</th>
<th width="40%">Açıklama</th>
</tr>

<tr>
<td><strong>Brute Force Saldırısı</strong></td>
<td>T1110.001</td>
<td>🔴 Kritik</td>
<td>5 dakikada 5+ başarısız login</td>
</tr>

<tr>
<td><strong>SQL Injection</strong></td>
<td>T1190</td>
<td>🔴 Kritik</td>
<td>SQL komutları içeren payload'lar</td>
</tr>

<tr>
<td><strong>XSS Saldırısı</strong></td>
<td>T1189</td>
<td>🟠 Yüksek</td>
<td>&lt;script&gt;, javascript: paternleri</td>
</tr>

<tr>
<td><strong>Port Scanning</strong></td>
<td>T1595.002</td>
<td>🟠 Yüksek</td>
<td>1 dakikada 10+ farklı port</td>
</tr>

<tr>
<td><strong>Şüpheli User-Agent</strong></td>
<td>T1595</td>
<td>🟡 Orta</td>
<td>sqlmap, nmap, nikto, metasploit</td>
</tr>

<tr>
<td><strong>Yetki Yükseltme</strong></td>
<td>T1548</td>
<td>🟠 Yüksek</td>
<td>sudo, su komut kullanımları</td>
</tr>

<tr>
<td><strong>Lateral Movement</strong></td>
<td>T1021.004</td>
<td>🟡 Orta</td>
<td>10 dakikada 3+ SSH bağlantısı</td>
</tr>
</table>

### 📋 Kural Detayları

#### 1. Brute Force Saldırısı (T1110.001)
```yaml
title: Multiple Failed Login Attempts
description: Belirli bir IP'den çok sayıda başarısız giriş denemesi
level: high
detection:
  - 5 dakika içinde 5+ başarısız login
  - Aynı kaynak IP adresi
  - Farklı kullanıcı adları deneniyor olabilir
response:
  - IP adresini geçici olarak engelleyin
  - Fail2ban/denyhosts yapılandırması
  - Alert oluştur
```

#### 2. SQL Injection (T1190)
```yaml
title: SQL Injection Attempt  
description: Web isteklerinde SQL komutları tespit edildi
level: critical
patterns:
  - UNION SELECT, DROP TABLE, INSERT INTO
  - ' OR '1'='1, admin'--
  - Database error messages
response:
  - WAF kuralı ekleyin
  - Uygulama kodunu inceleyin
  - IP'yi izlemeye alın
```

#### 3. XSS Saldırısı (T1189)
```yaml
title: Cross-Site Scripting Attempt
description: JavaScript injection denemeleri
level: high
patterns:
  - <script>, </script>
  - javascript:, onerror=
  - <iframe>, <object>
response:
  - Input validation uygulayın
  - CSP headers ekleyin
  - Escape user input
```

### 🎯 Özel Sigma Kuralları

Kendi Sigma kurallarınızı ekleyin:

```bash
# Özel kural dizini belirtin
python siem_hunter.py ingest --file logs.txt --sigma-rules /path/to/sigma/rules/

# Örnek dizin yapısı:
sigma_rules/
├── web_attacks/
│   ├── sql_injection.yml
│   ├── xss_attempt.yml
│   └── command_injection.yml
├── network/
│   ├── port_scan.yml
│   └── dns_tunneling.yml
└── authentication/
    ├── brute_force.yml
    └── password_spray.yml
```

**Örnek Sigma Kuralı** (`custom_rule.yml`):
```yaml
title: Suspicious PowerShell Command
id: custom-001
status: experimental
description: Detects suspicious PowerShell execution patterns
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains:
      - 'Invoke-Expression'
      - 'DownloadString'
      - '-enc'
      - 'bypass'
  condition: selection
falsepositives:
  - Legitimate admin scripts
level: high
tags:
  - attack.execution
  - attack.t1059.001
```

---

## 🏗️ Mimari

### Sistem Mimarisi

```
┌─────────────────────────────────────────────────────────────┐
│                       SIEM Hunter Engine                     │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐  │
│  │ Log Parser   │───▶│ Sigma Rules  │───▶│ Alert Manager│  │
│  │  (Multi-fmt) │    │   Engine     │    │ (Correlation)│  │
│  └──────────────┘    └──────────────┘    └──────────────┘  │
│         │                     │                    │         │
│         ▼                     ▼                    ▼         │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐  │
│  │ IOC Extractor│    │ ML Anomaly   │    │Threat Hunter │  │
│  │ (STIX/TAXII) │    │  Detector    │    │  (Proactive) │  │
│  └──────────────┘    │(Isolation F.)│    └──────────────┘  │
│         │             └──────────────┘            │         │
│         └────────────────┬──────────────────────┘         │
│                          ▼                                  │
│                  ┌──────────────┐                          │
│                  │  SQLite DB   │                          │
│                  │  (Logs/IOCs) │                          │
│                  └──────────────┘                          │
│                          │                                  │
│         ┌────────────────┴────────────────┐                │
│         ▼                                  ▼                │
│  ┌──────────────┐                  ┌──────────────┐       │
│  │   CLI Tool   │                  │ Web Dashboard│       │
│  │(siem_hunter) │                  │  (Streamlit) │       │
│  └──────────────┘                  └──────────────┘       │
└─────────────────────────────────────────────────────────────┘
```

### Veri Akışı

```
1. Log Toplama
   ├─ Dosyadan okuma (ingest)
   ├─ Gerçek zamanlı izleme (monitor)
   └─ Syslog/rsyslog entegrasyonu
   
2. Parsing & Normalizasyon
   ├─ Format tespiti (auto-detect)
   ├─ Alanları çıkarma
   └─ Zaman damgası normalizasyonu
   
3. Enrichment
   ├─ IOC çıkarımı (IP, domain, hash)
   ├─ GeoIP lookup (gelecek)
   └─ Threat intelligence (gelecek)
   
4. Tespit
   ├─ Sigma kural eşleştirmesi
   ├─ ML anomali skoru
   └─ MITRE ATT&CK mapping
   
5. Alert & Response
   ├─ Alert oluşturma
   ├─ Önceliklendirme
   └─ Veritabanına kaydetme
   
6. Analiz & Raporlama
   ├─ Threat hunting sorguları
   ├─ İstatistiksel analiz
   └─ Görselleştirme
```

---

## 🎓 Kullanım Senaryoları

### 1. Güvenlik Operasyon Merkezi (SOC)
```bash
# Gerçek zamanlı izleme için
python siem_hunter.py monitor --file /var/log/syslog --interval 0.5

# Dashboard ile görselleştirme
streamlit run siem_dashboard.py
```

### 2. Olay Müdahalesi & Forensics
```bash
# Geçmiş logları analiz et
python siem_hunter.py ingest --file incident_logs.txt

# Tehdit avı yap
python siem_hunter.py hunt

# Detaylı rapor
python siem_hunter.py report
```

### 3. Proaktif Tehdit Avı
```bash
# Belirli IP için arama
sqlite3 siem_logs.db "SELECT * FROM logs WHERE json_extract(data, '$.ip') = '192.168.1.100'"

# Web saldırıları bul
sqlite3 siem_logs.db "SELECT * FROM logs WHERE data LIKE '%<script>%' OR data LIKE '%UNION SELECT%'"
```

### 4. Uyumluluk & Denetim
```bash
# Belirli tarih aralığında loglar
python siem_hunter.py ingest --file audit_logs.txt
python siem_hunter.py report
```

### 5. Red Team Tespit
```bash
# Saldırı simülasyonu sonrası
python siem_hunter.py hunt
python siem_hunter.py alerts --severity high
```

---

## 🛡️ MITRE ATT&CK Kapsamı

Silent Watcher'ın tespit edilebildiği taktik ve teknikler:

### 🔴 Initial Access (T1189, T1190)
- Drive-by Compromise
- Exploit Public-Facing Application

### 🟠 Execution (T1059)
- Command and Scripting Interpreter

### 🟡 Persistence (T1078)
- Valid Accounts

---

## 🔄 SOC Workflow

ThreatWeave, gerçek dünya SOC operasyonlarını destekler:

### 📝 Tipik Olay Müdahale Akışı

1. **Log Ingestion** → Loglar veritabanına alınır (ingestion service)
2. **Correlation** → Port scan, failed login gibi desenler tespit edilir
3. **Alert Triage** → Alertler otomatik önceliklendirilir (triage_score)
4. **Threat Hunting** → Analist IOC araması yapar, şüpheli desenleri inceler
5. **Playbook Execution** → İlgili olay müdahale playbook'u açılır
6. **Incident Creation** → Olay kaydı oluşturulur, notlar ve ekler eklenir
7. **Investigation** → Detaylı analiz, MITRE ATT&CK mapping
8. **Resolution** → Olay kapatılır, KPI metrikleri güncellenir

### 🎯 Örnek Senaryo: Şüpheli Port Scan

**1. Tespit**
```
Correlation Engine: 10.0.1.50 IP'sinden 5 dakikada 100+ farklı porta bağlantı denemesi
```

**2. Triage**
```
Alert Triage Service: Risk skoru 85/100, öncelik HIGH
```

**3. Hunting**
```
Analyst: Threat Hunting > IOC Arama > 10.0.1.50
Sonuç: IP temiz IOC listelerinde yok, ama internal subnet'te
```

**4. Playbook**
```
Playbook: "Network Scan Response"
- Kaynak IP'yi izole et
- Endpoint'i karantinaya al
- Network trafiğini logla
```

**5. Incident**
```
Olay #42 oluşturuldu
Severity: HIGH
Tags: port-scan, internal-threat
Not: "Internal workstation compromised, possible lateral movement"
```

---

## 🧩 Mimari

### Modüler Yapı
- Abuse Elevation Control Mechanism

### 🟣 Credential Access (T1110)
- Brute Force
- Password Spraying

### 🟤 Discovery (T1595)
- Active Scanning

### 🟢 Lateral Movement (T1021)
- Remote Services (SSH/RDP)

---

## 📈 Performans

### Benchmark Sonuçları

| Metrik | Değer | Notlar |
|--------|-------|--------|
| **Ayrıştırma Hızı** | ~10,000 log/sn | Python threading ile |
| **Veritabanı Yazma** | ~5,000 log/sn | SQLite batch insert |
| **Kural Eşleştirme** | <10ms/log | 7 yerleşik kural için |
| **ML Anomali Tespiti** | ~2,000 log/sn | Isolation Forest |
| **Bellek Kullanımı** | 100-500MB | Veri setine bağlı |
| **Disk Kullanımı** | ~1KB/log | Sıkıştırılmamış |

### Optimizasyon Önerileri

**Production Ortamı için:**
```bash
# PostgreSQL/MySQL'e geç (büyük veri setleri için)
# Elasticsearch entegrasyonu (tam metin arama)
# Redis cache (sık erişilen veriler)
# Multi-processing (CPU yoğun işlemler)
# Bulk insert (veritabanı yazma hızı)
```

---

## 🚧 Yol Haritası

### v1.1.0 (Planlanan)
- [ ] Elasticsearch backend desteği
- [ ] REST API endpoint'leri
- [ ] Otomatik IOC enrichment (VirusTotal, AbuseIPDB)
- [ ] Email alerting sistemi
- [ ] Custom Sigma kuralı editörü

### v1.2.0 (Planlanan)
- [ ] STIX/TAXII tehdit istihbaratı entegrasyonu
- [ ] GeoIP analizi ve harita görselleştirme
- [ ] Network flow analizi
- [ ] SOAR platformlarla entegrasyon
- [ ] Multi-tenant desteği
- [ ] RBAC (Role-Based Access Control)

### v2.0.0 (Gelecek)
- [ ] Log retention politikaları
- [ ] Automated response playbooks
- [ ] Özel ML model eğitim arayüzü
- [ ] Distributed deployment (microservices)
- [ ] Real-time streaming (Apache Kafka)

---

## 🤝 Katkıda Bulunma

Projeye katkıda bulunmak isterseniz:

1. Repository'yi fork edin
2. Feature branch oluşturun (`git checkout -b feature/amazing-feature`)
3. Değişikliklerinizi commit edin (`git commit -m 'Add amazing feature'`)
4. Branch'inizi push edin (`git push origin feature/amazing-feature`)
5. Pull Request açın

---

## 📄 Lisans

MIT Lisansı altında dağıtılmaktadır. Detaylar için `LICENSE` dosyasına bakın.

---

## 👤 Yazar

**Macallan** - Blue Team Güvenlik Mühendisi
- 🔬 Uzmanlık: Tehdit Tespiti & Olay Müdahalesi
- 🛡️ Proje: Kurumsal SIEM Geliştirme
- 📧 İletişim: [GitHub](https://github.com/yourusername)

---

## 🙏 Teşekkürler

Bu proje aşağıdaki açık kaynak projelerden ve teknolojilerden ilham almıştır:

- **Sigma HQ** - Evrensel tespit kuralı framework'ü
- **Splunk** - Gelişmiş arama ve korelasyon teknikleri
- **ELK Stack** - Log yönetimi ve analiz best practices
- **Wazuh** - Açık kaynak SIEM mimarisi
- **MITRE ATT&CK** - Tehdit modelleme framework'ü

---

## ⚠️ Sorumluluk Reddi

Bu araç **yalnızca yetkili güvenlik testi ve izleme** amacıyla geliştirilmiştir. Sistemleri izlemeden önce mutlaka:

- ✅ Uygun yasal yetkilendirmeyi alın
- ✅ Kurumsal politikalara uygun hareket edin
- ✅ Gizlilik ve veri koruma yasalarına riayet edin
- ⚠️ Yetkisiz sistemleri taramayın veya test etmeyin

---

<div align="center">

**[⬆ Başa Dön](#-threatweave)**

Sevgiyle geliştirildi — Blue Team

**ThreatWeave - Tehditleri Dokünü Gibi Bağlayan Platform**

</div>
