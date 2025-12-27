# AutoSec FIM - Dosya Bütünlüğü İzleyici

## 📋 Proje Hakkında

**AutoSec FIM** (File Integrity Monitor), dosya sisteminizdeki değişiklikleri gerçek zamanlı olarak izleyen ve raporlayan bir siber güvenlik aracıdır. Özellikle Blue Team operasyonları için tasarlanmış bu araç, dosya oluşturma, değiştirme ve silme işlemlerini algılayarak potansiyel güvenlik tehditlerini tespit etmenize yardımcı olur.

## 🎯 Özellikler

- ✅ **Gerçek Zamanlı İzleme**: Belirtilen dizindeki tüm dosya değişikliklerini anlık olarak izler
- ✅ **Hash Tabanlı Bütünlük Kontrolü**: SHA-256 algoritması ile dosya bütünlüğünü doğrular
- ✅ **Baseline Oluşturma**: İlk çalıştırmada dosyaların hash değerlerini veritabanına kaydeder
- ✅ **Bellek Dostu**: Büyük dosyaları 4KB'lık bloklar halinde işleyerek RAM kullanımını optimize eder
- ✅ **SIEM Entegrasyonu**: JSON formatında log üretir (SIEM sistemlerine entegre edilebilir)
- ✅ **Dosya Uzantısı Filtreleme**: İstenmeyen dosya türlerini izleme dışında bırakabilme
- ✅ **Renkli Konsol Çıktısı**: Farklı önem seviyelerinde renkli uyarılar
- ✅ **SQLite Veritabanı**: Hafif ve hızlı dosya hash kayıtları

## 🚀 Kurulum

### Gereksinimler

- Python 3.7+
- pip (Python paket yöneticisi)

### Adımlar

1. **Proje deposunu klonlayın veya indirin:**
```bash
cd /path/to/project
```

2. **Sanal ortamı aktif edin (önerilir):**
```bash
source macallan/bin/activate
```

3. **Gerekli paketleri yükleyin:**
```bash
pip install -r requirements.txt
```

## 📖 Kullanım

### Temel Kullanım

```bash
python autosec_fim.py -p /izlenecek/dizin
```

### Uzantı Hariç Tutma

Belirli dosya türlerini izleme dışında bırakmak için:

```bash
python autosec_fim.py -p /izlenecek/dizin -x .log,.tmp,.cache
```

### Parametreler

| Parametre | Kısa | Açıklama | Zorunlu |
|-----------|------|----------|---------|
| `--path` | `-p` | İzlenecek dizin yolu | Evet |
| `--exclude` | `-x` | Hariç tutulacak dosya uzantıları (virgülle ayrılmış) | Hayır |

## 📊 Çıktı Örnekleri

### Konsol Çıktısı
```
🛡️  AutoSec FIM - File Integrity Monitor Başlatılıyor...
[*] Hedef Dizin: /home/user/test
[*] Hariç Tutulanlar: ['.log', '.tmp']
[+] Baseline taraması yapılıyor (Lütfen bekleyin)...
[+] Baseline tamamlandı. 127 dosya indekslendi.
[*] Gerçek zamanlı koruma devrede. Loglar: fim_alerts.json

[!] ALERT: FILE_MODIFIED - /home/user/test/config.txt
    └── Hash Mismatch! Old: 8f3a4b2c... New: 7e9d5a1f...
```

### JSON Log Formatı (SIEM)
```json
{
  "timestamp": "2025-12-27T14:32:45.123456",
  "tool": "AutoSec_FIM",
  "event_type": "FILE_MODIFIED",
  "severity": "CRITICAL",
  "target_path": "/home/user/test/config.txt",
  "message": "Hash Mismatch! Old: 8f3a4b2c... New: 7e9d5a1f..."
}
```

## 🔍 Olay Tipleri ve Önem Seviyeleri

| Olay Tipi | Açıklama | Önem Seviyesi |
|-----------|----------|---------------|
| `FILE_MODIFIED` | Dosya içeriği değiştirildi | CRITICAL |
| `FILE_CREATED` | Yeni dosya oluşturuldu | MEDIUM |
| `FILE_DELETED` | Dosya silindi | HIGH |

## 📁 Dosya Yapısı

```
.
├── autosec_fim.py          # Ana uygulama dosyası
├── fim_baseline.db         # SQLite veritabanı (otomatik oluşturulur)
├── fim_alerts.json         # JSON formatında olay logları
├── requirements.txt        # Python bağımlılıkları
└── README.md              # Bu dosya
```

## 🛠️ Mimari ve Modüller

### 1. FIMCore (Veritabanı ve Hash Motoru)
- SQLite veritabanı yönetimi
- SHA-256 hash hesaplama
- Baseline güncelleme ve sorgulama

### 2. FIMHandler (Olay İzleyici)
- Dosya sistemi olaylarını yakalama (watchdog kütüphanesi)
- Değişiklik algılama ve loglama
- SIEM entegrasyonu için JSON çıktısı

### 3. Main (Ana Çalıştırıcı)
- CLI argüman yönetimi
- Baseline taraması
- Gerçek zamanlı izleme başlatma

## 🔒 Güvenlik Notları

- **Baseline Koruma**: `fim_baseline.db` dosyasını düzenli olarak yedekleyin
- **Log Yönetimi**: `fim_alerts.json` dosyası zaman içinde büyüyebilir, log rotasyonu önerilir
- **İzin Sorunları**: Bazı sistem dosyalarını okumak için yönetici yetkisi gerekebilir
- **Performans**: Çok büyük dizinlerde ilk baseline taraması zaman alabilir

## 🤝 Katkıda Bulunma

Bu proje Blue Team operasyonları için geliştirilmiştir. Öneriler ve geliştirmeler için katkılarınızı bekliyoruz.

## 📄 Lisans

Bu proje açık kaynak kodlu bir eğitim ve güvenlik aracıdır. Kullanımınızda yerel yasalara ve etik kurallara uygunluğu sağlayınız.

## 🔧 Sorun Giderme

### "PermissionError" Hatası
```bash
sudo python autosec_fim.py -p /protected/directory
```

### Sanal Ortam Aktif Etme
```bash
# Linux/Mac
source macallan/bin/activate

# Windows
macallan\Scripts\activate
```

## 📞 İletişim

Sorularınız veya geri bildirimleriniz için issue açabilirsiniz.

---

**⚠️ Uyarı**: Bu araç yalnızca yasal ve etik amaçlarla kullanılmalıdır. Yetkili olmadığınız sistemlerde kullanmayınız.
