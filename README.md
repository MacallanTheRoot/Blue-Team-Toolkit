# Silent Watcher + AutoSec FIM (Entegre Çözüm)

Profesyonel dosya bütünlüğü izlemesi (FIM) + SIEM alarmları. AutoSec File Integrity Monitor, Silent Watcher SIEM'e gerçek zamanlı alarm gönderir ve Streamlit dashboard'dan yönetilir.

## Dizin Yapısı
```
SIEM/
  ├── siem_dashboard.py         # Ana dashboard (FIM yönetimi dahil)
  ├── siem_api.py              # SIEM ingest API (webhook)
  ├── siem_hunter.py           # Log analiz motoru
  ├── FileIntegrityMonitor/    # FIM ajanı
  │   ├── autosec_fim.py      # FIM çekirdek
  │   ├── testdata/           # Test dosyaları
  │   └── siem_listener.py    # Opsiyonel dummy SIEM
  ├── siem_logs.db            # SIEM veritabanı
  └── requirements.txt
```

## Kurulum

```bash
cd /home/macallan/Downloads/projects/macallan/blueteam
python3 -m venv .venv
source .venv/bin/activate
pip install -r SIEM/requirements.txt
```

## Çalıştırma (3 Terminal)

### Terminal 1: SIEM Ingest API
```bash
cd SIEM
python siem_api.py
# Dinler: http://127.0.0.1:5000/webhook
```

### Terminal 2: Dashboard (FIM dahil)
```bash
cd SIEM
streamlit run siem_dashboard.py
# http://localhost:8501 otomatik açılır
# Sekmeler → "🛡️ File Integrity Monitor" FIM başlatabilirsiniz
```

### Terminal 3: FIM Başlat (Dashboard'tan VEYA manuel)
**Dashboard üzerinden:**
- Sekmeler → "🛡️ File Integrity Monitor"
- "▶️ FIM Başlat" butonuna tıkla

**Veya Manuel:**
```bash
cd SIEM/FileIntegrityMonitor
python autosec_fim.py -p ./testdata -s http://127.0.0.1:5000/webhook
```

## Özellikler

✅ **FIM (File Integrity Monitor)**
- Gerçek zamanlı dosya izleme
- SHA256 hash tabanlı tespit
- Excludable extensions
- SIEM webhook entegrasyonu

✅ **Dashboard İntegrasyonu**
- FIM başlatma/durdurma
- Live log görüntüleme
- SIEM DB sorgusu
- Multi-database hızlı seçim

## Git'e Hazır
- `.gitignore` oluşturuldu
- Projeyi push etmeye hazırsınız!
