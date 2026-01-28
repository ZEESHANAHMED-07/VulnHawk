import argparse

from utils.helpers import resolve_target
from core.ports import scan_ports
from core.services import detect_services
from web.headers import check_security_headers


def main():
    # -------------------------------
    # Argument Parsing
    # -------------------------------
    parser = argparse.ArgumentParser(
        description="VulnHawk - Modular Vulnerability Scanner"
    )

    parser.add_argument(
        "-t", "--target",
        required=True,
        help="Target domain or IP address"
    )

    args = parser.parse_args()

    # -------------------------------
    # Target Resolution
    # -------------------------------
    ip = resolve_target(args.target)

    if not ip:
        print("[!] Could not resolve target")
        return

    print(f"[+] Target resolved: {args.target} -> {ip}")

    # -------------------------------
    # Port Scanning
    # -------------------------------
    open_ports = scan_ports(ip)

    if not open_ports:
        print("[-] No open ports found")
        return

    print(f"[+] Open ports discovered: {open_ports}")

    # -------------------------------
    # Service & Banner Detection
    # -------------------------------
    services = detect_services(ip, open_ports)

    print("\n[+] Service Detection Results:")
    for port, banner in services.items():
        first_line = banner.splitlines()[0] if banner else "Unknown"
        print(f"Port {port} -> {first_line}")

    # -------------------------------
    # HTTP Security Header Scan
    # -------------------------------
    print("\n[*] Checking HTTP security headers...")

    url = f"http://{args.target}"
    header_issues = check_security_headers(url)

    if not header_issues:
        print("[+] All recommended security headers are present")
    else:
        print("[!] Missing / Weak Security Headers:")
        for header, issue in header_issues.items():
            print(f" - {header}: {issue}")


if __name__ == "__main__":
    main()
