import sys
import time
import hashlib
import sqlite3
import os
import json
import logging
import argparse
import requests
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# --- KONFİGÜRASYON & RENKLER ---
DB_NAME = "fim_baseline.db"
LOG_FILE = "fim_alerts.json"

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'

# --- 1. MODÜL: VERİTABANI VE HASH MOTORU ---
class FIMCore:
    def __init__(self, db_path=DB_NAME, exclude_extensions=None):
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.cursor = self.conn.cursor()
        self.exclude_extensions = exclude_extensions if exclude_extensions else []
        self._init_db()

    def _init_db(self):
        """Veritabanı tablosunu oluşturur."""
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS file_integrity (
                path TEXT PRIMARY KEY,
                hash TEXT,
                last_check TEXT
            )
        ''')
        self.conn.commit()

    def is_excluded(self, file_path):
        """Hariç tutulan uzantıları kontrol eder (Örn: .log, .tmp)."""
        if any(file_path.endswith(ext) for ext in self.exclude_extensions):
            return True
        return False

    def calculate_hash(self, file_path):
        """
        Memory Efficient Hashing: Dosyayı 4KB'lık bloklar halinde okur.
        Büyük dosyalar RAM'i şişirmez.
        """
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except (PermissionError, FileNotFoundError, OSError):
            return None

    def update_baseline(self, path, file_hash):
        """Veritabanını günceller veya yeni kayıt ekler."""
        timestamp = datetime.now().isoformat()
        try:
            self.cursor.execute('''
                INSERT OR REPLACE INTO file_integrity (path, hash, last_check)
                VALUES (?, ?, ?)
            ''', (path, file_hash, timestamp))
            self.conn.commit()
        except sqlite3.Error as e:
            print(f"DB Error: {e}")

    def get_file_hash(self, path):
        """Veritabanından bilinen son hash'i çeker."""
        self.cursor.execute('SELECT hash FROM file_integrity WHERE path = ?', (path,))
        result = self.cursor.fetchone()
        return result[0] if result else None

# --- 2. MODÜL: OLAY İZLEYİCİ (WATCHER) ---
class FIMHandler(FileSystemEventHandler):
    def __init__(self, core_engine, report_file=LOG_FILE, siem_url="http://localhost:5000/webhook"):
        self.core = core_engine
        self.report_file = report_file
        self.siem_url = siem_url
        self.siem_enabled = siem_url is not None

    def _send_to_siem(self, alert_data):
        """Alarmları SIEM endpoint'ine POST isteği olarak gönderir."""
        if not self.siem_enabled:
            return
        
        try:
            # Timeout ile POST isteği gönder (2 saniye)
            response = requests.post(
                self.siem_url, 
                json=alert_data, 
                timeout=2,
                headers={'Content-Type': 'application/json'}
            )
            # HTTP hata kodlarını kontrol et
            response.raise_for_status()
            
        except requests.exceptions.Timeout:
            print(f"{Colors.FAIL}[!] SIEM timeout: Sunucu yanıt vermiyor.{Colors.ENDC}")
        except requests.exceptions.ConnectionError:
            print(f"{Colors.FAIL}[!] SIEM bağlantı hatası: Sunucu kapalı olabilir.{Colors.ENDC}")
        except requests.exceptions.HTTPError as e:
            print(f"{Colors.FAIL}[!] SIEM HTTP hatası: {e.response.status_code}{Colors.ENDC}")
        except requests.exceptions.RequestException as e:
            print(f"{Colors.FAIL}[!] SIEM genel hata: {str(e)[:50]}{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.FAIL}[!] Beklenmeyen SIEM hatası: {str(e)[:50]}{Colors.ENDC}")

    def _log_alert(self, event_type, path, message, severity="HIGH"):
        """SIEM için JSON formatında log üretir, ekrana basar ve SIEM'e gönderir."""
        alert = {
            "timestamp": datetime.now().isoformat(),
            "tool": "AutoSec_FIM",
            "event_type": event_type,
            "severity": severity,
            "target_path": path,
            "message": message
        }
        
        # 1. Ekrana Renkli Bas
        color = Colors.FAIL if severity == "CRITICAL" else Colors.WARNING
        print(f"{color}[!] ALERT: {event_type} - {path}{Colors.ENDC}")
        print(f"    └── {message}")

        # 2. Dosyaya JSON Yaz (Lokal loglama)
        try:
            with open(self.report_file, "a") as f:
                f.write(json.dumps(alert) + "\n")
        except Exception as e:
            print(f"Loglama hatası: {e}")

        # 3. SIEM'e Gönder
        self._send_to_siem(alert)

    def on_modified(self, event):
        if event.is_directory or self.core.is_excluded(event.src_path):
            return

        new_hash = self.core.calculate_hash(event.src_path)
        old_hash = self.core.get_file_hash(event.src_path)

        # Eğer eski hash yoksa (yeni oluşturulmuş olabilir) veya hash değişmişse
        if old_hash and new_hash:
            if new_hash != old_hash:
                msg = f"Hash Mismatch! Old: {old_hash[:8]}... New: {new_hash[:8]}..."
                self._log_alert("FILE_MODIFIED", event.src_path, msg, severity="CRITICAL")
                
                # Opsiyonel: Veritabanını güncelle (yeni normal bu olsun mu?)
                self.core.update_baseline(event.src_path, new_hash)

    def on_created(self, event):
        if event.is_directory or self.core.is_excluded(event.src_path):
            return
            
        self._log_alert("FILE_CREATED", event.src_path, "New file detected.", severity="MEDIUM")
        new_hash = self.core.calculate_hash(event.src_path)
        if new_hash:
            self.core.update_baseline(event.src_path, new_hash)

    def on_deleted(self, event):
        if event.is_directory or self.core.is_excluded(event.src_path):
            return
        self._log_alert("FILE_DELETED", event.src_path, "File removed from system.", severity="HIGH")

# --- 3. MODÜL: ANA ÇALIŞTIRICI (MAIN) ---
def start_monitoring(path, extensions, siem_url="http://localhost:5000/webhook"):
    print(f"{Colors.HEADER}🛡️  AutoSec FIM - File Integrity Monitor Başlatılıyor...{Colors.ENDC}")
    print(f"{Colors.BLUE}[*] Hedef Dizin: {path}{Colors.ENDC}")
    print(f"{Colors.BLUE}[*] Hariç Tutulanlar: {extensions}{Colors.ENDC}")
    print(f"{Colors.BLUE}[*] SIEM Endpoint: {siem_url if siem_url else 'Devre dışı'}{Colors.ENDC}")

    fim_core = FIMCore(exclude_extensions=extensions)

    # 1. Aşama: Baseline Oluşturma
    print(f"{Colors.GREEN}[+] Baseline taraması yapılıyor (Lütfen bekleyin)...{Colors.ENDC}")
    count = 0
    for root, dirs, files in os.walk(path):
        for file in files:
            file_path = os.path.join(root, file)
            if not fim_core.is_excluded(file_path):
                h = fim_core.calculate_hash(file_path)
                if h:
                    fim_core.update_baseline(file_path, h)
                    count += 1
    print(f"{Colors.GREEN}[+] Baseline tamamlandı. {count} dosya indekslendi.{Colors.ENDC}")

    # 2. Aşama: İzlemeyi Başlatma
    event_handler = FIMHandler(fim_core, siem_url=siem_url)
    observer = Observer()
    observer.schedule(event_handler, path, recursive=True)
    observer.start()

    print(f"{Colors.HEADER}[*] Gerçek zamanlı koruma devrede. Loglar: {LOG_FILE}{Colors.ENDC}")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        print(f"\n{Colors.WARNING}[!] Sistem durduruluyor...{Colors.ENDC}")
    
    observer.join()

if __name__ == "__main__":
    # CLI Argümanlarını Yönetme
    parser = argparse.ArgumentParser(description="AutoSec File Integrity Monitor")
    parser.add_argument("-p", "--path", help="İzlenecek Klasör Yolu", required=True)
    parser.add_argument("-x", "--exclude", help="Hariç tutulacak uzantılar (örn: .log,.tmp)", default="")
    parser.add_argument("-s", "--siem", help="SIEM Webhook URL (varsayılan: http://localhost:5000/webhook)", 
                        default="http://localhost:5000/webhook")
    parser.add_argument("--no-siem", help="SIEM entegrasyonunu devre dışı bırak", action="store_true")
    
    args = parser.parse_args()
    
    # Virgülle ayrılmış uzantıları listeye çevir
    exclude_list = [x.strip() for x in args.exclude.split(",")] if args.exclude else []
    
    # SIEM URL belirleme
    siem_url = None if args.no_siem else args.siem
    
    if os.path.exists(args.path):
        start_monitoring(args.path, exclude_list, siem_url=siem_url)
    else:
        print(f"{Colors.FAIL}Hata: Belirtilen yol bulunamadı.{Colors.ENDC}")
