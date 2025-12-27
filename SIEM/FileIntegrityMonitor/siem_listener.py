# Basit SIEM Listener (Dummy Server)
# Gelen FIM alarmlarını dinler ve ekrana basar.
# 
# Çalıştırmak için:
# 1. Gerekli kütüphaneyi kurun: pip install Flask
# 2. Sunucuyu başlatın: python siem_listener.py

from flask import Flask, request, jsonify
from datetime import datetime
import json

app = Flask(__name__)

# Renkler (Konsolde daha okunaklı çıktı için)
class Colors:
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'

@app.route('/')
def index():
    """
    Ana sayfa - SIEM Listener durumunu gösterir.
    """
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>SIEM Listener</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; background: #1e1e1e; color: #ffffff; }
            .container { max-width: 800px; margin: 0 auto; }
            h1 { color: #4CAF50; }
            .status { background: #2d2d2d; padding: 20px; border-radius: 5px; margin: 20px 0; }
            .endpoint { background: #1a1a1a; padding: 15px; margin: 10px 0; border-left: 4px solid #4CAF50; }
            code { background: #000; padding: 2px 6px; border-radius: 3px; color: #4CAF50; }
            .info { color: #888; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🛡️ SIEM Listener - Aktif</h1>
            <div class="status">
                <h2>Durum: <span style="color: #4CAF50;">Çalışıyor ✓</span></h2>
                <p class="info">SIEM Listener başarıyla çalışıyor ve alarm almaya hazır.</p>
            </div>
            
            <div class="endpoint">
                <h3>Webhook Endpoint</h3>
                <p><code>POST /webhook</code></p>
                <p class="info">FIM alarmlarını bu endpoint'e gönderin.</p>
            </div>
            
            <div class="endpoint">
                <h3>Test Komutu</h3>
                <pre><code>curl -X POST http://127.0.0.1:5000/webhook \\
  -H "Content-Type: application/json" \\
  -d '{"timestamp": "2025-12-27", "tool": "FIM", "event_type": "file_modified", "severity": "HIGH", "target_path": "/test/file.txt", "message": "Test alarm"}'</code></pre>
            </div>
        </div>
    </body>
    </html>
    """

@app.route('/webhook', methods=['POST'])
def siem_webhook():
    """
    FIM aracından gelen POST isteklerini kabul eden endpoint.
    """
    if not request.is_json:
        return jsonify({"error": "Invalid request: Content-Type must be application/json"}), 400

    alert_data = request.get_json()
    
    # Gelen veriyi terminale daha okunaklı bir formatta yazdır
    print(f"\n{Colors.GREEN}--- [SIEM] Yeni Alarm Alındı ---{Colors.ENDC}")
    print(f"{Colors.BLUE}Zaman Damgası:{Colors.ENDC} {alert_data.get('timestamp', 'N/A')}")
    print(f"{Colors.BLUE}Araç:          {Colors.ENDC} {alert_data.get('tool', 'N/A')}")
    print(f"{Colors.BLUE}Olay Tipi:     {Colors.ENDC} {Colors.WARNING}{alert_data.get('event_type', 'N/A')}{Colors.ENDC}")
    print(f"{Colors.BLUE}Önem Derecesi: {Colors.ENDC} {Colors.FAIL}{alert_data.get('severity', 'N/A')}{Colors.ENDC}")
    print(f"{Colors.BLUE}Hedef Yol:     {Colors.ENDC} {alert_data.get('target_path', 'N/A')}")
    print(f"{Colors.BLUE}Mesaj:         {Colors.ENDC} {alert_data.get('message', 'N/A')}")
    print(f"{Colors.GREEN}----------------------------------{Colors.ENDC}")
    
    # Pretty print raw JSON
    # print(json.dumps(alert_data, indent=2))

    return jsonify({"status": "success", "message": "Alert received"}), 200

if __name__ == '__main__':
    print(f"{Colors.GREEN}🛡️  Dummy SIEM Listener Başlatıldı.{Colors.ENDC}")
    print(f"{Colors.BLUE}[*] Alarmlar http://127.0.0.1:5000/webhook adresinde dinleniyor...{Colors.ENDC}")
    print(f"{Colors.WARNING}Durdurmak için CTRL+C tuşlarına basın.{Colors.ENDC}")
    # production'da app.run() debug=False olmalı, bu sadece test için.
    app.run(host='0.0.0.0', port=5000, debug=False)
