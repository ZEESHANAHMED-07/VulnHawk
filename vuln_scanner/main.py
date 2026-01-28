import argparse

from utils.helpers import resolve_target

# Core scanning
from core.ports import scan_ports
from core.services import detect_services
from core.auth import get_auth_headers
from core.severity import (
    score_headers,
    score_sensitive_files,
    score_ports,
    severity_label
)

# Web scanners
from web.headers import check_security_headers
from web.files import scan_sensitive_files

# Plugins
from plugins.plugin_loader import load_plugins

# Reports
from reports.reporter import generate_report
from reports.html_reporter import generate_html_report


def main():
    # -------------------------------
    # Argument Parsing
    # -------------------------------
    parser = argparse.ArgumentParser(
        description="VulnHawk - Purple Team Vulnerability Scanner"
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
    # Authentication (Optional)
    # -------------------------------
    auth_headers = get_auth_headers()
    if auth_headers:
        print("[*] Authenticated scanning enabled")

    # -------------------------------
    # Multithreaded Port Scanning
    # -------------------------------
    open_ports = scan_ports(ip)
    if not open_ports:
        print("[-] No open ports found")
        return

    # -------------------------------
    # Service Detection
    # -------------------------------
    services = detect_services(ip, open_ports)

    # -------------------------------
    # Web-Based Scanning
    # -------------------------------
    base_url = f"http://{args.target}"

    header_issues = check_security_headers(
        base_url,
        auth_headers
    )

    sensitive_findings = scan_sensitive_files(
        base_url,
        auth_headers
    )

    # -------------------------------
    # CVSS-Style Severity Scoring
    # -------------------------------
    header_scores = score_headers(header_issues)
    file_scores = score_sensitive_files(sensitive_findings)
    port_scores = score_ports(open_ports)

    # -------------------------------
    # Plugin Execution
    # -------------------------------
    plugin_results = []
    plugins = load_plugins()

    context = {
        "open_ports": open_ports,
        "services": services,
        "headers": header_issues,
        "sensitive_files": sensitive_findings,
        "scores": {
            "headers": header_scores,
            "files": file_scores,
            "ports": port_scores
        },
        "auth_enabled": bool(auth_headers)
    }

    if plugins:
        print(f"[*] Executing {len(plugins)} plugins...")
        for plugin in plugins:
            try:
                result = plugin.run(args.target, ip, context)
                plugin_results.append(result)
            except Exception as e:
                print(f"[!] Plugin error: {e}")

    # -------------------------------
    # Report Generation (JSON)
    # -------------------------------
    generate_report(
        target=args.target,
        ip=ip,
        open_ports=open_ports,
        services=services,
        headers=header_scores,
        sensitive_files=file_scores
    )

    # -------------------------------
    # Report Generation (HTML)
    # -------------------------------
    generate_html_report(
        target=args.target,
        ip=ip,
        open_ports=open_ports,
        services=services,
        headers=header_scores,
        sensitive_files=file_scores
    )

    # -------------------------------
    # Plugin Results Output
    # -------------------------------
    if plugin_results:
        print("\n[+] Plugin Results:")
        for result in plugin_results:
            print(f" - {result}")

    print("\n[✓] Scan completed successfully")


if __name__ == "__main__":
    main()
