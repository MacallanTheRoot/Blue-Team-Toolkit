import psutil
import time
import math
import requests
import os
import shutil
import hashlib
import json
import argparse
import sys
import threading
from queue import Queue
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from datetime import datetime
from colorama import Fore, init

init(autoreset=True)

# ==========================================
# 🛡️ GuardEDR CONFIGURATION
# ==========================================
CONFIG_FILE = "guard_config.json"
notification_queue = Queue()

SETTINGS = {
    "TELEGRAM": {"ENABLED": False, "TOKEN": "", "CHAT_ID": ""},
    "VIRUSTOTAL": {"ENABLED": False, "API_KEY": ""},
    "EDR": {
        "QUARANTINE_DIR": "edr_quarantine",
        "ENTROPY_THRESHOLD": 7.5,
        "MONITOR_PATH": os.path.expanduser("~")
    }
}

# --- VOIDTRAP'TEN PORT EDİLEN CONFIG VE NUKE MODÜLLERİ ---
def load_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r") as f:
                SETTINGS.update(json.load(f))
        except: pass

def save_config():
    with open(CONFIG_FILE, "w") as f:
        json.dump(SETTINGS, f, indent=4)

def nuke_data():
    """Hassas verileri temizle."""
    if os.path.exists(CONFIG_FILE):
        os.remove(CONFIG_FILE)
        print(f"{Fore.RED}[!] Yapılandırma ve API anahtarları silindi.")
    sys.exit()

# --- ANALİZ MODÜLLERİ ---
def get_file_hash(file_path):
    """Dosya bütünlüğü için MD5 hesaplar."""
    try:
        hasher = hashlib.md5()
        with open(file_path, 'rb') as f:
            buf = f.read()
            hasher.update(buf)
        return hasher.hexdigest()
    except: return None

def check_virustotal(file_hash):
    """VOIDTRAP VT Modülü - EDR Entegrasyonu."""
    if not SETTINGS["VIRUSTOTAL"]["ENABLED"] or not SETTINGS["VIRUSTOTAL"]["API_KEY"]:
        return "⚪ (Disabled)"
    try:
        headers = {"x-apikey": SETTINGS["VIRUSTOTAL"]["API_KEY"]}
        r = requests.get(f"https://www.virustotal.com/api/v3/files/{file_hash}", headers=headers, timeout=5)
        if r.status_code == 200:
            stats = r.json()['data']['attributes']['last_analysis_stats']
            mal = stats['malicious']
            return f"🔥 {mal} Malicious" if mal > 0 else "✅ Clean"
        return "❓ Unknown"
    except: return "❌ Connection Error"

# --- ASENKRON BİLDİRİM SİSTEMİ (VOIDTRAP WORKER) ---
def alert_worker():
    while True:
        item = notification_queue.get()
        if item is None: break
        
        header = "🛡️ *GuardEDR ALERT*"
        msg = f"{header}\n\n{item}"
        
        if SETTINGS["TELEGRAM"]["ENABLED"]:
            try:
                requests.post(f"https://api.telegram.org/bot{SETTINGS['TELEGRAM']['TOKEN']}/sendMessage",
                              json={"chat_id": SETTINGS['TELEGRAM']['CHAT_ID'], "text": msg, "parse_mode": "Markdown"})
            except: pass
        notification_queue.task_done()

threading.Thread(target=alert_worker, daemon=True).start()

# --- ANA EDR SINIFI ---
class GuardEDR:
    def __init__(self):
        self.suspicious_map = {
            "winword.exe": ["cmd.exe", "powershell.exe"],
            "powershell.exe": ["certutil.exe", "bitsadmin.exe"]
        }
        if not os.path.exists(SETTINGS["EDR"]["QUARANTINE_DIR"]):
            os.makedirs(SETTINGS["EDR"]["QUARANTINE_DIR"])

    def quarantine(self, pid, proc_name, file_path):
        """Süreci öldür ve dosyayı karantinaya taşı."""
        try:
            p = psutil.Process(pid)
            p.terminate()
            
            f_hash = get_file_hash(file_path)
            vt_res = check_virustotal(f_hash)
            
            # Fiziksel karantina
            if file_path and os.path.exists(file_path):
                dest = os.path.join(SETTINGS["EDR"]["QUARANTINE_DIR"], os.path.basename(file_path) + ".vir")
                shutil.move(file_path, dest)
            
            alert_msg = (f"🛑 *Process Terminated*\n"
                         f"Süreç: `{proc_name}`\n"
                         f"PID: `{pid}`\n"
                         f"Hash: `{f_hash}`\n"
                         f"VT: `{vt_res}`")
            notification_queue.put(alert_msg)
            print(f"{Fore.RED}[!] TEHDİT ENGELLENDİ: {proc_name}")
        except: pass

    def scan_processes(self):
        for proc in psutil.process_iter(['pid', 'name', 'ppid', 'exe']):
            try:
                p_name = proc.info['name'].lower()
                parent = psutil.Process(proc.info['ppid'])
                if parent.name().lower() in self.suspicious_map:
                    if p_name in self.suspicious_map[parent.name().lower()]:
                        self.quarantine(proc.info['pid'], p_name, proc.info['exe'])
            except: continue

# --- RANSOMWARE MODÜLÜ (Entropy) ---
class EntropyShield(FileSystemEventHandler):
    def on_modified(self, event):
        if not event.is_directory:
            # Buraya VOIDTRAP'teki entropi hesaplama fonksiyonunu ekleyebilirsin
            pass

# --- CLI BAŞLATICI ---
def main():
    load_config()
    parser = argparse.ArgumentParser(description="GuardEDR v3.0 - Active Response System")
    parser.add_argument("--nuke", action="store_true", help="Ayarları temizle")
    parser.add_argument("--tg-token", type=str)
    parser.add_argument("--tg-chat", type=str)
    parser.add_argument("--vt-key", type=str)
    
    args = parser.parse_args()
    if args.nuke: nuke_data()
    
    if args.tg_token: 
        SETTINGS["TELEGRAM"]["TOKEN"] = args.tg_token
        SETTINGS["TELEGRAM"]["ENABLED"] = True
    if args.vt_key:
        SETTINGS["VIRUSTOTAL"]["API_KEY"] = args.vt_key
        SETTINGS["VIRUSTOTAL"]["ENABLED"] = True
    
    save_config()
    
    edr = GuardEDR()
    print(f"{Fore.CYAN}[*] GuardEDR Başlatıldı. İzleme Modu: AKTİF")
    
    try:
        while True:
            edr.scan_processes()
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Durduruluyor...")

if __name__ == "__main__":
    main()
