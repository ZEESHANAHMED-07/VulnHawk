import requests

SENSITIVE_PATHS = [
    ".env",
    ".git/",
    ".git/config",
    "backup.zip",
    "backup.tar.gz",
    "db.sql",
    "database.sql",
    "admin/",
    "admin/login",
    "config.php",
    ".htaccess"
]

def scan_sensitive_files(base_url):
    findings = {}

    print("[*] Scanning for sensitive files and directories...")

    for path in SENSITIVE_PATHS:
        url = f"{base_url}/{path}"

        try:
            response = requests.get(url, timeout=5, allow_redirects=False)

            if response.status_code in [200, 301, 302, 403]:
                print(f"[!] Found {path} (Status: {response.status_code})")
                findings[path] = response.status_code

        except requests.RequestException:
            continue

    return findings
