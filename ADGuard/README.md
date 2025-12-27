# AD-Guard: Professional Active Directory Security Auditor (CLI)

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Type](https://img.shields.io/badge/Category-Blue--Team-blue)

**AD-Guard**, kurumsal Active Directory ortamlarındaki kritik yapılandırma hatalarını ve potansiyel saldırı vektörlerini tespit etmek için geliştirilmiş, CLI tabanlı bir güvenlik denetim aracıdır. Red Team simülasyonlarından önce sistem sıkılaştırma (hardening) süreçleri için tasarlanmıştır.

## 🚀 Öne Çıkan Özellikler

- **Gelişmiş LDAP Analizi:** `ldap3` kütüphanesi ve bitwise filtreleme ile yüksek performanslı tarama.
- **Kritik Zafiyet Taraması:**
  - **Kerberoasting & AS-REP Roasting:** SPN ve Pre-Auth zafiyetlerinin tespiti.
  - **Delegasyon Analizi:** Tehlikeli "Unconstrained Delegation" yapılandırmalarının bulunması.
  - **MachineAccountQuota Check:** Saldırganların domain'e cihaz ekleme yetkisinin denetimi.
  - **Stale Accounts:** Pasif kalmış ama yetkili hesapların analizi.
- **Görsel Dashboard:** Tarama sonuçlarını `Chart.js` destekli interaktif bir HTML raporuna dönüştürme.
- **Güvenli Mimari:** `getpass` entegrasyonu ile terminal geçmişinde parola izi bırakmayan güvenli giriş.

## 📦 Kurulum

```bash
# Depoyu klonlayın
git clone [https://github.com/kullaniciadin/ad-guard.git](https://github.com/kullaniciadin/ad-guard.git)
cd ad-guard

# Sanal ortam oluşturun ve aktif edin
python -m venv .venv
source .venv/bin/activate  # Windows için: .venv\Scripts\activate

# Gerekli kütüphaneleri kurun
pip install ldap3 colorama