# 🛡️ GuardEDR v3.0 - Active Behavioral Response System

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![Type](https://img.shields.io/badge/Category-Blue--Team-blue)
![Status](https://img.shields.io/badge/Status-Expert--Edition-gold)

██████╗ ██╗ ██╗ █████╗ ██████╗ ██████╗ ███████╗██████╗ ██████╗ ██╔════╝ ██║ ██║██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔══██╗██╔══██╗ ██║ ███╗██║ ██║███████║██████╔╝██║ ██║█████╗ ██████╔╝██████╔╝ ██║ ██║██║ ██║██╔══██║██╔══██╗██║ ██║██╔══╝ ██╔══██╗██╔══██╗ ╚██████╔╝╚██████╔╝██║ ██║██║ ██║██████╔╝███████╗██║ ██║██║ ██║ ╚═════╝ ╚═════╝ ╚═╝ ╚═╝╚═╝ ╚═╝╚═════╝ ╚══════╝╚═╝ ╚═╝╚═╝ ╚═╝ >> Advanced Threat Detection & Active Response << >> Integrated with VOIDTRAP Modules <<


## 📋 Genel Bakış

**GuardEDR**, uç noktalardaki (endpoint) şüpheli aktiviteleri gerçek zamanlı olarak tespit eden, analiz eden ve otomatik müdahale (Active Response) gerçekleştiren gelişmiş bir EDR-Lite sistemidir. Geleneksel antivirüslerin aksine, imza tabanlı değil **davranış tabanlı (Behavioral)** analiz yöntemlerini kullanır.

## ✨ Öne Çıkan Özellikler

### 🧠 Davranışsal Analiz (Behavioral Detection)
- **Process Tree Tracking**: Ofis uygulamaları (Word, Excel) veya tarayıcılar üzerinden başlatılan şüpheli alt süreçleri (PowerShell, CMD) anlık olarak yakalar.
- **LotL (Living off the Land) Savunması**: Sistem araçlarının kötüye kullanımını engeller.

### ☣️ Anti-Ransomware & Malware Modülü
- **Entropy Analysis**: Dosya sistemindeki ani entropi değişimlerini izleyerek sıfırıncı gün (Zero-Day) fidye yazılımlarını tespit eder.
- **Physical Quarantine**: Şüpheli dosyaları `.vir` uzantısıyla fiziksel olarak izole edilmiş bir klasöre taşır.
- **Hash Integrity**: Yakalanan tehditlerin MD5 bütünlüğünü hesaplar.

### 🔍 Threat Intelligence (İstihbarat)
- **VirusTotal v3 Integration**: Karantinaya alınan dosyaların hash bilgilerini otomatik olarak VirusTotal üzerinden sorgular.
- **Asenkron Bildirim Sistemi**: `VOIDTRAP` projesinden port edilen asenkron kuyruk yapısı ile tarama hızını kesmeden bildirim gönderir.

### 📡 Bildirim & Yönetim
- **Telegram Command Center**: Kritik tehditler için anlık görsel raporlama.
- **CLI Management**: Komut satırı üzerinden dinamik yapılandırma ve "Nuke" (temizlik) protokolü.

## 🚀 Kurulum

### 1. Bağımlılıkları Yükleyin
```bash
pip install -r requirements.txt

### 2. İlk Çalıştırma ve Yapılandırma

Bash

# Telegram ve VirusTotal entegrasyonu ile başlat
python main.py --tg-token "YOUR_TOKEN" --tg-chat "YOUR_ID" --vt-key "YOUR_VT_KEY"

⚙️ CLI Kullanımı

--nuke	Tüm yapılandırma ve API anahtarlarını güvenli bir şekilde siler.
--tg-token	Telegram Bot API anahtarını tanımlar.
--vt-key	VirusTotal API anahtarını tanımlar.

📊 Örnek Senaryo: Bir Saldırının Engellenmesi

    Tespit: Bir Word belgesi üzerinden powershell.exe başlatıldı.

    Analiz: GuardEDR ebeveyn-çocuk ilişkisindeki anomaliyi yakaladı.

    Müdahale: Süreç 0.1 saniye içinde sonlandırıldı (Terminate).

    Karantina: PowerShell'i tetikleyen script fiziksel olarak edr_quarantine/ dizinine taşındı.

    İstihbarat: Dosya hash'i VirusTotal'de sorgulandı.

    Raporlama: Tüm bu süreç Telegram üzerinden "GuardEDR" başlığıyla iletildi.

⚖️ Yasal Uyarı

Bu araç eğitim ve savunma amaçlı geliştirilmiştir. Sadece yetkiniz olan sistemlerde kullanın.

Made with 🛡️ by MacallanTheRoot
