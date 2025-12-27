# 🛡️ Blue Team Cyber Defense Toolkit

![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Security](https://img.shields.io/badge/Security-Blue%20Team-blue?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-lightgrey?style=for-the-badge)
![License](https://img.shields.io/badge/License-Educational-green?style=for-the-badge)

## 📌 Proje Hakkında
Bu depo, **Proaktif Savunma**, **Olay Müdahale (Incident Response)** ve **SOC Operasyonları** üzerine geliştirdiğim araçların ve sistemlerin kapsamlı bir koleksiyonudur.

Buradaki projeler, basit güvenlik scriptleri olmanın ötesinde; **Uç Nokta Koruması (EDR)**, **SIEM Mimarisi**, **Aldatma Teknikleri (Deception)** ve **Kimlik Güvenliği Denetimi** üzerine derinlemesine teknik yetkinlikleri sergilemek amacıyla tasarlanmıştır.

Bu repository; toplam 21 dizin ve 65 dosyadan oluşan, kurumsal savunma katmanlarını (Defense-in-Depth) simüle eden bir güvenlik ekosistemidir.

---

## 📂 Projeler ve Modüller

### 1. 🔍 ThreatWeaveSIEM
Merkezi güvenlik izleme ve olay yönetimi (SIEM) platformudur.
* **📂 Konum:** `/ThreatWeaveSIEM`
* **Özellikler:**
    * **Teknik Mimari:** `core` dizininde veritabanı ve migrasyon yönetimi, `services` altında ise ML tabanlı anomali tespiti ve korelasyon motoru yer alır.
    * **Kural Motoru:** `rules.yaml` üzerinden özelleştirilebilir tespit kuralları ve `threatweave_dashboard.py` ile interaktif SOC arayüzü.
    * **Gelişmiş FIM:** Dosya bütünlük izleme (File Integrity Monitor) modülü ile kritik dosyaları anlık takip eder.
    * **API Entegrasyonu:** `api/ingest.py` ile log toplama ve merkezi veri entegrasyon katmanı.
    * **Analytics & ML:** İzolasyon ormanı (Isolation Forest) algoritması ile anomali tespiti ve korelasyon analizi.

### 2. 🛡️ GuardEDR
Davranış tabanlı uç nokta tespit ve yanıt (EDR) sistemidir.
* **📂 Konum:** `/GuardEDR`
* **Özellikler:**
    * **Aktif Müdahale:** Şüpheli süreçleri tespit eder, sonlandırır ve ilgili dosyaları `edr_quarantine` dizinine taşır.
    * **Malware Analysis:** VirusTotal entegrasyonu ile dosya itibar analizi ve Shannon Entropy hesaplama modülleri.
    * **Behavioral Detection:** Süreç davranışlarını izleyerek zararlı aktiviteleri gerçek zamanlı tespit eder.
    * **Quarantine System:** Şüpheli dosyaları güvenli bir ortamda izole ederek analiz için saklar.

### 3. 🕷️ Voidtrap
Gelişmiş aldatma (deception) ve tehdit istihbaratı toplama sistemidir.
* **📂 Konum:** `/Voidtrap`
* **Özellikler:**
    * **Honeypot Framework:** Sahte servisler ve tuzaklar ile saldırganları kandırır ve davranışlarını kaydeder.
    * **Malware Collection:** Saldırganların indirmeye çalıştığı dosyaları yakalar ve `quarantine` klasöründe analiz için saklar (Örn: `eicar.com.txt`).
    * **Real-time Alerting:** Gerçek zamanlı saldırı verilerini asenkron bir kuyruk yapısıyla Telegram/Email üzerinden iletir.
    * **Threat Intelligence:** Saldırgan IP'leri, kullanılan teknikler ve zararlı yazılım örneklerini toplar.

### 4. 🔑 ADGuard
Active Directory ortamları için güvenlik denetim ve sıkılaştırma aracıdır.
* **📂 Konum:** `/ADGuard`
* **Özellikler:**
    * **Zafiyet Analizi:** Kerberoasting, AS-REP Roasting ve riskli delegasyon yapılandırmalarını (Unconstrained Delegation) LDAP üzerinden analiz eder.
    * **LDAP Queries:** Active Directory'ye karşı güvenlik odaklı sorgular çalıştırarak zayıf noktaları tespit eder.
    * **Actionable Reports:** Sistem yöneticilerine saldırı yüzeyini daraltmak için uygulanabilir öneriler sunar.
    * **Configuration Audit:** Domain controller yapılandırmalarını, güvenlik politikalarını ve kullanıcı hesaplarını denetler.

---

## 🏗️ Proje Yapısı

```
.
├── ADGuard          # AD Güvenlik Denetimi (adguard.py) 
├── GuardEDR         # Uç Nokta Savunması (GuardEDR.py) 
├── Voidtrap         # Honeypot & Deception (Voidtrap.py) 
└── ThreatWeaveSIEM  # Merkezi Log Analizi & SOC Platform
```

---

## 🛠️ Teknik Yetkinlikler (Tech Stack)

Bu projelerin geliştirilmesinde aşağıdaki teknolojiler ve kütüphaneler kullanılmıştır:

| **Kategori**        | **Teknolojiler**                                                        |
| ------------------- | ----------------------------------------------------------------------- |
| **Diller**          | Python 3.11+, Bash, HTML/CSS (UI)                                       |
| **Analiz & ML**     | `scikit-learn` (IsolationForest), `pandas`, `numpy`, `Shannon Entropy` |
| **Sistem & EDR**    | `psutil`, `watchdog` (FIM), `winreg`, Windows/Linux API                 |
| **Web & SOC UI**    | `Streamlit`, `Flask` (REST API), `Plotly`, `Chart.js`                   |
| **Network & Intel** | `ldap3` (AD), `socket`, `VirusTotal v3 API`, `Telegram Bot API`         |

---


## ⚠️ Yasal Uyarı (Disclaimer)

> **Bu depo sadece EĞİTİM, ARAŞTIRMA ve YETKİLENDİRİLMİŞ GÜVENLİK TESTLERİ (Red Teaming) amacıyla oluşturulmuştur.**

Burada bulunan araçların izinsiz sistemlerde kullanılması, veri şifrelenmesi veya ağ trafiğinin dinlenmesi suç teşkil eder. Geliştirici (**MacallanTheRoot**), bu yazılımların kötüye kullanımından doğacak yasal ve maddi sonuçlardan sorumlu değildir.

Bu projeler, savunma ekiplerinin (Blue Team) saldırı vektörlerini anlaması ve tespit mekanizmaları geliştirmesi için bir kaynak niteliğindedir.

---

### 📬 İletişim & Profil
**Developer:** MacallanTheRoot
*Siber Güvenlik Araştırmacısı & Yazılım Geliştirici*

