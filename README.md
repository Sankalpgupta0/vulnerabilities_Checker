# 🛡️ Wagtail Security Scanner

A Python-based security scanner designed to audit Wagtail-powered websites for common misconfigurations and vulnerabilities such as:

- 🧪 XSS (Cross-Site Scripting)  
- 🔐 Exposed Admin Login Pages  
- 📢 DEBUG Mode Leakage  
- 📁 Public Media File Access  

---

## 📦 Features

- ✅ Crawls the site and tests forms for XSS
- ✅ Detects DOM-based and reflected XSS
- ✅ Tests public access to the `/admin/` panel
- ✅ Checks if Wagtail DEBUG mode is exposed via headers or error pages
- ✅ Scans for exposed media files (e.g., images, documents)

---

## 🚀 Getting Started

### Requirements

- Python 3.7+
- `requests`
- `beautifulsoup4`
- `colorama`
- `tldextract`

### Installation

```bash
git clone https://github.com/Sankalpgupta0/vulnerabilities_Checker.git
cd vulnerabilities_Checker
pip install -r requirements.txt
```

---

## ⚙️ Usage

```bash
python scanner.py https://example-site.com
```

You can also set depth for crawling (default is 1):

```bash
python scanner.py https://example-site.com --depth 2
```

---

## 📝 Report

A final report is printed at the end of the scan showing:

- Number of XSS vulnerabilities
- Admin panel exposure
- DEBUG mode visibility
- Public media files (if any)
- Summary in ✅ / ⚠️ format

---

## 🛡️ Example Output

```text
[+] Crawling site (depth=1) and testing for XSS...
↳ Crawled: https://example.com/page1 (depth 0)
🧪 Testing form at https://example.com/search via GET
  ↪ Filling field 'query' with: <script>alert('xss')</script>
[!] Possible XSS via form at: https://example.com/search ⚠️

🔐 Admin Page Exposure:
  ⚠️ Admin login page is accessible at https://example.com/admin/

⚠️ DEBUG mode appears to be ON (suspicious header/value detected)

📁 Public Media Files:
  - https://example.com/media/private_invoice.pdf
```

---

## 🧠 How It Works

- Uses BeautifulSoup to extract forms and links.
- Sends common XSS payloads to detect vulnerable inputs.
- Parses HTML and responses to detect reflected/DOM XSS.
- Follows internal links and respects domain scope.
- Uses heuristic checks for DEBUG mode and media URLs.

---

## 📂 Folder Structure

```bash
scanner.py            # Main script
xss.py                # XSS crawling + form testing logic
report.py             # Generates and formats final summary
utils.py              # Helper functions and utilities
```

---

## 🧑‍💻 Author

**Sankalp Gupta**  
Built for gsoc submission.


---


### basic info
common_ports = [
    21,    # FTP
    22,    # SSH
    23,    # Telnet
    25,    # SMTP
    53,    # DNS
    80,    # HTTP
    110,   # POP3
    143,   # IMAP
    443,   # HTTPS
    465,   # SMTPS
    587,   # SMTP (submission)
    993,   # IMAPS
    995,   # POP3S
    1433,  # MS SQL Server
    1521,  # Oracle DB
    2049,  # NFS
    2082,  # cPanel
    2083,  # cPanel (SSL)
    2222,  # DirectAdmin
    2375,  # Docker API (unsecured)
    3306,  # MySQL
    3389,  # RDP (Remote Desktop)
    5432,  # PostgreSQL
    5900,  # VNC
    6379,  # Redis
    8000,  # Dev servers
    8080,  # HTTP Alt / Proxy
    8443,  # HTTPS Alt
    8888,  # Jupyter / Admin panels
    9200,  # Elasticsearch
    27017  # MongoDB
]