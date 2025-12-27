import socket
import threading
import logging
import time
import json
import requests
import re
import os
import hashlib
import argparse
import sys
from queue import Queue
from datetime import datetime

# ==========================================
# 🕷️ VOIDTRAP CONFIGURATION
# ==========================================
CONFIG_FILE = "void_config.json"

# Varsayılan "Boş" Ayarlar (Secret içermez)
SETTINGS = {
    "HONEYPOT": {
        "BIND_IP": "0.0.0.0",
        "BIND_PORT": 2222,
        "LOG_FILE": "voidtrap.log",
        "QUARANTINE_DIR": "quarantine"
    },
    "TELEGRAM": {
        "ENABLED": False, 
        "TOKEN": "",
        "CHAT_ID": ""
    },
    "VIRUSTOTAL": {
        "ENABLED": False,
        "API_KEY": ""
    }
}

notification_queue = Queue()

# --- CONFIG YÖNETİMİ ---
def load_config():
    global SETTINGS
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r") as f:
                SETTINGS.update(json.load(f))
        except: pass

def save_config():
    try:
        with open(CONFIG_FILE, "w") as f:
            json.dump(SETTINGS, f, indent=4)
        print(f"[+] Ayarlar '{CONFIG_FILE}' dosyasına kaydedildi.")
    except Exception as e:
        print(f"[!] Kayıt hatası: {e}")

def nuke_data():
    """Tüm hassas verileri ve yapılandırma dosyalarını siler."""
    print("\n" + "!"*40)
    print("☢️  NUKE PROTOCOL INITIATED ☢️")
    print("!"*40)
    
    deleted = False
    # 1. Config dosyasını sil
    if os.path.exists(CONFIG_FILE):
        os.remove(CONFIG_FILE)
        print(f"[+] '{CONFIG_FILE}' silindi.")
        deleted = True
    else:
        print(f"[-] '{CONFIG_FILE}' zaten yok.")

    # 2. Log dosyasını silmek ister mi? (Opsiyonel, güvenlik için silebiliriz)
    # os.remove(SETTINGS["HONEYPOT"]["LOG_FILE"]) 
    
    if deleted:
        print("[+] Tüm API anahtarları ve Tokenler temizlendi.")
        print("[+] VOIDTRAP fabrika ayarlarına döndü.")
    else:
        print("[*] Temizlenecek veri bulunamadı.")
    
    print("!"*40 + "\n")
    sys.exit()

def parse_arguments():
    parser = argparse.ArgumentParser(description="VOIDTRAP v1.0 - Advanced Deception System")
    
    # Temel Komutlar
    parser.add_argument("--port", "-p", type=int, help="Dinlenecek Port")
    
    # Temizlik Komutu
    parser.add_argument("--nuke", "-n", action="store_true", help="⚠️ TÜM AYARLARI VE TOKENLERİ SİL")

    # Telegram
    parser.add_argument("--telegram", "-tg", action="store_true", help="Telegram modülünü aç")
    parser.add_argument("--tg-token", "-tt", type=str, help="Telegram Bot Token")
    parser.add_argument("--tg-chat", "-tci", type=str, help="Telegram Chat ID")
    
    # VirusTotal
    parser.add_argument("--virustotal", "-vtm", action="store_true", help="VirusTotal modülünü aç")
    parser.add_argument("--vt-key", "-vt", type=str, help="VirusTotal API Key")

    args = parser.parse_args()
    settings_changed = False

    # Nuke komutu geldiyse her şeyi sil ve çık
    if args.nuke:
        nuke_data()

    if args.port: 
        SETTINGS["HONEYPOT"]["BIND_PORT"] = args.port
        settings_changed = True
    
    if args.tg_token: 
        SETTINGS["TELEGRAM"]["TOKEN"] = args.tg_token
        SETTINGS["TELEGRAM"]["ENABLED"] = True 
        settings_changed = True
        
    if args.tg_chat: 
        SETTINGS["TELEGRAM"]["CHAT_ID"] = args.tg_chat
        settings_changed = True
    
    if args.telegram:
        SETTINGS["TELEGRAM"]["ENABLED"] = True
        settings_changed = True

    if args.vt_key: 
        SETTINGS["VIRUSTOTAL"]["API_KEY"] = args.vt_key
        SETTINGS["VIRUSTOTAL"]["ENABLED"] = True
        settings_changed = True
        
    if args.virustotal:
        SETTINGS["VIRUSTOTAL"]["ENABLED"] = True
        settings_changed = True

    if settings_changed: save_config()

# --- HAZIRLIK ---
if not os.path.exists(SETTINGS["HONEYPOT"]["QUARANTINE_DIR"]):
    os.makedirs(SETTINGS["HONEYPOT"]["QUARANTINE_DIR"])

def print_banner():
    print(r"""
██╗   ██╗ ██████╗ ██╗██████╗ ████████╗██████╗  █████╗ ██████╗ 
██║   ██║██╔═══██╗██║██╔══██╗╚══██╔══╝██╔══██╗██╔══██╗██╔══██╗
██║   ██║██║   ██║██║██║  ██║   ██║   ██████╔╝███████║██████╔╝
╚██╗ ██╔╝██║   ██║██║██║  ██║   ██║   ██╔══██╗██╔══██║██╔═══╝ 
 ╚████╔╝ ╚██████╔╝██║██████╔╝   ██║   ██║  ██║██║  ██║██║     
  ╚═══╝   ╚═════╝ ╚═╝╚═════╝    ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     
        >> Cyber Deception & Intelligence System <<
                  >>by MacallanTheRoot <<

              """)
    print(f"[*] Port:     {SETTINGS['HONEYPOT']['BIND_PORT']}")
    tg_s = "🟢 ONLINE" if SETTINGS["TELEGRAM"]["ENABLED"] and SETTINGS["TELEGRAM"]["TOKEN"] else "⚪ OFFLINE"
    vt_s = "🟢 ONLINE" if SETTINGS["VIRUSTOTAL"]["ENABLED"] and SETTINGS["VIRUSTOTAL"]["API_KEY"] else "⚪ OFFLINE"
    print(f"[*] Telegram: {tg_s}")
    print(f"[*] V.Total:  {vt_s}")
    print("="*60 + "\n")

# --- CORE FONKSİYONLAR ---
def get_ip_info(ip):
    if ip in ["127.0.0.1", "localhost"]: return "🏠 Localhost"
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=country,countryCode", timeout=3).json()
        return f"{r['country']} ({r['countryCode']})"
    except: return "Unknown"

def check_virustotal(file_hash):
    if not SETTINGS["VIRUSTOTAL"]["ENABLED"] or not SETTINGS["VIRUSTOTAL"]["API_KEY"]: return "⚪ (Disabled)"
    try:
        headers = {"x-apikey": SETTINGS["VIRUSTOTAL"]["API_KEY"]}
        r = requests.get(f"https://www.virustotal.com/api/v3/files/{file_hash}", headers=headers, timeout=10)
        if r.status_code == 200:
            stats = r.json()['data']['attributes']['last_analysis_stats']
            mal = stats['malicious']
            return f"🔥 {mal}/{stats['harmless']+stats['undetected']+mal} Malicious" if mal > 0 else "✅ Clean"
        return "❓ Not in DB" if r.status_code == 404 else f"⚠️ Error: {r.status_code}"
    except: return "❌ Net Error"

def send_telegram(msg):
    if not SETTINGS["TELEGRAM"]["ENABLED"] or not SETTINGS["TELEGRAM"]["TOKEN"]: return
    try:
        requests.post(f"https://api.telegram.org/bot{SETTINGS['TELEGRAM']['TOKEN']}/sendMessage",
                      json={"chat_id": SETTINGS['TELEGRAM']['CHAT_ID'], "text": msg, "parse_mode": "Markdown"}, timeout=5)
    except: pass

def download_malware(url):
    try:
        fname = url.split("/")[-1] or f"artifact_{int(time.time())}.bin"
        path = os.path.join(SETTINGS["HONEYPOT"]["QUARANTINE_DIR"], fname)
        requests.get(url, timeout=10)
        with open(path, 'wb') as f: f.write(requests.get(url).content)
        md5 = hashlib.md5(open(path,'rb').read()).hexdigest()
        return {"file": fname, "hash": md5, "vt": check_virustotal(md5)}
    except Exception as e: return {"error": str(e)}

def worker():
    while True:
        d = notification_queue.get()
        if d is None: break
        print(f"[LOG] {d}")
        if SETTINGS["TELEGRAM"]["ENABLED"]:
            msg = ""
            if "malware" in d:
                m = d['malware']
                msg = f"☣️ *VOIDTRAP ALERT* ☣️\n🌍 IP: `{d['ip']}`\n🔗 URL: `{d['url']}`\n📁 File: `{m.get('file','?')}`\n#️⃣ MD5: `{m.get('hash','?')}`\n📊 VT: `{m.get('vt','?')}`"
            elif "commands" in d:
                msg = f"🕵️‍♂️ *SESSION LOG*\n🌍 IP: `{d['ip']}`\n📜 CMD:\n" + "\n".join([f"`> {c}`" for c in d['commands']])
            else:
                msg = f"🔓 *INTRUSION*\n🌍 IP: `{d['ip']} - {d['location']}`\n👤 U: `{d['user']}` 🔑 P: `{d['pass']}`"
            send_telegram(msg)
        notification_queue.task_done()

threading.Thread(target=worker, daemon=True).start()

FAKE_FS = {"ls": "bin boot dev etc home lib opt root sbin tmp usr var\r\n", "pwd": "/root\r\n", "whoami": "root\r\n"}

def handle_client(sock, ip):
    try:
        sock.send(b"Ubuntu 22.04 LTS\r\nLogin: "); u = sock.recv(1024).decode().strip()
        sock.send(b"Password: "); p = sock.recv(1024).decode().strip()
        time.sleep(1); loc = get_ip_info(ip)
        logging.info(json.dumps({"ip": ip, "u": u, "p": p, "loc": loc}))
        notification_queue.put({"ip": ip, "location": loc, "user": u, "pass": p, "time": datetime.now()})
        
        sock.send(b"\r\nroot@server:~# "); hist = []
        while True:
            data = sock.recv(1024)
            if not data: break
            cmd = data.decode('utf-8', errors='ignore').strip()
            if not cmd: sock.send(b"root@server:~# "); continue
            hist.append(cmd)
            
            if cmd.startswith(("wget", "curl")):
                urls = re.findall(r'http[s]?://[^\s]+', cmd)
                if urls:
                    sock.send(f"Connecting to {urls[0]}... 200 OK\r\nDownloading payload...\r\n".encode())
                    res = download_malware(urls[0])
                    if "error" not in res:
                        sock.send(b"Saved.\r\n"); notification_queue.put({"ip": ip, "url": urls[0], "malware": res})
                    else: sock.send(b"Error.\r\n")
                else: sock.send(b"missing URL\r\n")
            elif cmd == "exit": break
            elif cmd in FAKE_FS: sock.send(FAKE_FS[cmd].encode())
            else: sock.send(f"bash: {cmd}: command not found\r\n".encode())
            sock.send(b"root@server:~# ")
        if hist: notification_queue.put({"ip": ip, "commands": hist})
    except: pass
    finally: sock.close()

def start():
    load_config(); parse_arguments()
    logging.basicConfig(filename=SETTINGS["HONEYPOT"]["LOG_FILE"], level=logging.INFO, format='%(asctime)s %(message)s')
    print_banner()
    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try: 
        s.bind((SETTINGS["HONEYPOT"]["BIND_IP"], SETTINGS["HONEYPOT"]["BIND_PORT"]))
    except PermissionError:
        print(f"[!] Critical: Sudo required for port {SETTINGS['HONEYPOT']['BIND_PORT']}."); return
    
    s.listen(5)
    print("[*] VoidTrap is active. Listening for prey... (CTRL+C to stop)")

    try:
        while True:
            c, a = s.accept()
            threading.Thread(target=handle_client, args=(c, a[0])).start()
    except KeyboardInterrupt:
        print("\n\n[*] Deactivating VoidTrap. Good hunting. 👋")
        s.close()
        sys.exit()

if __name__ == "__main__": 
    start()