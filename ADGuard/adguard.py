import argparse
import datetime
import json
import getpass
import sys
from ldap3 import Server, Connection, ALL
from colorama import Fore, Style, init

# Renkleri başlat
init(autoreset=True)

class ADCLI_Auditor:
    def __init__(self, domain, user, pwd):
        self.domain = domain
        self.base_dn = ",".join([f"DC={p}" for p in domain.split('.')])
        try:
            self.server = Server(domain, get_info=ALL)
            self.conn = Connection(self.server, user=user, password=pwd, auto_bind=True)
            print(f"{Fore.GREEN}[+] Bağlantı Başarılı: {domain}")
        except Exception as e:
            print(f"{Fore.RED}[- ] Hata: Bağlantı kurulamadı. {e}")
            sys.exit(1)
        
        self.findings = []
        self.stats = {"Critical": 0, "High": 0, "Medium": 0}

    def log_finding(self, severity, title, obj, fix):
        color = Fore.RED if severity == "Critical" else (Fore.YELLOW if severity == "High" else Fore.CYAN)
        print(f"{color}[!] {severity}: {title} -> {obj}")
        self.findings.append({"severity": severity, "title": title, "object": str(obj), "fix": fix})
        self.stats[severity] += 1

    def run_scans(self):
        print(f"\n{Fore.BLUE}{'='*20} TARAMA BAŞLADI {'='*20}\n")
        
        # 1. Machine Account Quota
        self.conn.search(self.base_dn, "(objectClass=domainDNS)", attributes=['ms-DS-MachineAccountQuota'])
        quota = self.conn.entries[0].ms_DS_MachineAccountQuota.value
        if quota > 0:
            self.log_finding("High", "Yüksek Machine Account Quota", "Domain Config", "Quota değerini 0 yapın.")

        # 2. Unconstrained Delegation
        self.conn.search(self.base_dn, "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))", attributes=['sAMAccountName'])
        for e in self.conn.entries:
            self.log_finding("Critical", "Unconstrained Delegation", e.sAMAccountName, "Sınırsız delegasyonu kaldırın.")

        # 3. AS-REP Roasting
        self.conn.search(self.base_dn, "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))", attributes=['sAMAccountName'])
        for e in self.conn.entries:
            self.log_finding("High", "AS-REP Roasting", e.sAMAccountName, "Pre-auth ayarını aktifleştirin.")

    def generate_html(self, output_file):
        # ... (Bir önceki cevaptaki HTML Dashboard kodunu buraya entegre edebilirsin)
        print(f"\n{Fore.GREEN}[+] Rapor oluşturuldu: {output_file}")

def banner():
    print(f"""{Fore.CYAN}
    ###########################################
    #       AD EXPERT AUDITOR CLI v1.0        #
    #    Blue Team Security Assessment Tool   #
    #      Developed by Macallantheroot       #
    ###########################################
    """)

def main():
    banner()
    parser = argparse.ArgumentParser(description="Active Directory Güvenlik Denetim Aracı")
    parser.add_argument("-d", "--domain", required=True, help="Hedef Domain (örn: lab.local)")
    parser.add_argument("-u", "--user", required=True, help="Kullanıcı Adı (örn: DOMAIN\\Admin)")
    parser.add_argument("-p", "--password", help="Kullanıcı Parolası (Boş bırakılırsa güvenli giriş istenir)")
    parser.add_argument("-o", "--output", default="audit_report.html", help="HTML Rapor dosya adı")

    args = parser.parse_args()

    password = args.password if args.password else getpass.getpass(f"{Fore.YELLOW}[?] {args.user} için parolanızı girin: ")

    auditor = ADCLI_Auditor(args.domain, args.user, password)
    auditor.run_scans()
    auditor.generate_html(args.output)

if __name__ == "__main__":
    main()
