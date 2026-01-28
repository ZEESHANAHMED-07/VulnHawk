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


def scan_sensitive_files(base_url, auth_headers=None):
    """
    Scans for common sensitive files and directories.

    :param base_url: Base URL (e.g., http://example.com)
    :param auth_headers: Optional authentication headers dict
    :return: dict of discovered paths with HTTP status codes
    """
    findings = {}

    print("[*] Scanning for sensitive files and directories...")

    for path in SENSITIVE_PATHS:
        url = f"{base_url}/{path}"

        try:
            response = requests.get(
                url,
                timeout=5,
                allow_redirects=False,
                headers=auth_headers or {}
            )

            if response.status_code in [200, 301, 302, 403]:
                print(f"[!] Found /{path} (HTTP {response.status_code})")
                findings[path] = response.status_code

        except requests.RequestException:
            # Ignore unreachable paths / blocked requests
            continue

    return findings
