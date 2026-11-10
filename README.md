# 🦓 ZebraTakeover

**ZebraTakeover** is a fast, asynchronous Subdomain Takeover scanner for bug bounty hunters and penetration testers.

## 🚀 Features
- **Subdomain Enumeration:** Fetches subdomains via crt.sh.
- **CNAME Analysis:** Resolves CNAME records for each subdomain.
- **Vulnerability Detection:** Checks if a subdomain points to an unclaimed service (GitHub Pages, Heroku, AWS S3, etc.).
- **Fingerprinting:** Verifies the takeover by checking the HTTP response for specific "unclaimed" error messages.

## 🛠️ Installation
```bash
git clone https://github.com/smsl1/ZebraTakeover.git
cd ZebraTakeover
pip install -r requirements.txt