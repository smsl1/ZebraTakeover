# language: Python 3.10+, file: ZebraTakeover.py
# pip install requests dnspython

import requests
import urllib3
import dns.resolver
from concurrent.futures import ThreadPoolExecutor, as_completed

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
CYAN = '\033[96m'
RESET = '\033[0m'

# Уязвимые сервисы и их маркеры (если сайт не настроен)
VULN_SERVICES = {
    "github.io": "There isn't a GitHub Pages site here.",
    "herokuapp.com": "No such app",
    "s3.amazonaws.com": "NoSuchBucket",
    "cloudfront.net": "Bad request",
    "azurewebsites.net": "404 Web Site not found",
    "surge.sh": "project not found",
    "bitbucket.io": "Repository not found"
}

def get_subdomains(domain):
    print(f"{YELLOW}[*] Fetching subdomains for {domain} from crt.sh...{RESET}")
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    subs = set()
    try:
        r = requests.get(url, timeout=30)
        if r.status_code == 200:
            for entry in r.json():
                for d in entry.get("name_value", "").split("\n"):
                    d = d.strip().lower()
                    if d and not any(x in d for x in ["*", " "]):
                        subs.add(d)
    except Exception as e:
        print(f"{RED}[-] crt.sh error: {e}{RESET}")
    return list(subs)

def check_takeover(sub):
    try:
        # 1. Получаем CNAME
        answers = dns.resolver.resolve(sub, 'CNAME')
        cname = str(answers[0].target).strip('.')
        
        # 2. Проверяем, есть ли сервис в списке уязвимых
        for service, marker in VULN_SERVICES.items():
            if service in cname:
                # 3. Делаем HTTP-запрос и ищем маркер
                try:
                    r = requests.get(f"https://{sub}", timeout=10, verify=False, headers={"User-Agent": "Mozilla/5.0"})
                    if marker in r.text:
                        return (sub, cname, service, marker)
                except Exception:
                    pass
    except Exception:
        pass
    return None

def main():
    print(f"{CYAN}=== ZebraTakeover v1.0 ==={RESET}")
    target = input("Target Domain (e.g., example.com)> ").strip()
    if not target:
        return
        
    subs = get_subdomains(target)
    print(f"{GREEN}[+] Found {len(subs)} subdomains.{RESET}")
    
    if not subs:
        return

    print(f"{YELLOW}[*] Scanning {len(subs)} subdomains for takeover...{RESET}")
    
    found = []
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(check_takeover, s): s for s in subs}
        for future in as_completed(futures):
            res = future.result()
            if res:
                sub, cname, service, marker = res
                print(f"\n{RED}[!!!] TAKEOVER FOUND: {sub}{RESET}")
                print(f"    CNAME: {cname}")
                print(f"    Service: {service}")
                print(f"    Response: {marker}")
                found.append(sub)
                
    print(f"\n{CYAN}[*] Scan complete. Found {len(found)} vulnerable subdomains.{RESET}")

if __name__ == "__main__":
    main()