import argparse

from utils.helpers import resolve_target

# Core
from core.ports import scan_ports
from core.services import detect_services
from core.auth import get_auth_headers
from core.severity import (
    score_headers,
    score_sensitive_files,
    score_ports
)

# Web scanners
from web.headers import check_security_headers
from web.files import scan_sensitive_files
from web.injection import scan_injections

# Plugins
from plugins.plugin_loader import load_plugins

# Reports
from reports.reporter import generate_report
from reports.html_reporter import generate_html_report


def main():
    parser = argparse.ArgumentParser(
        description="VulnHawk - Purple Team Vulnerability Scanner"
    )
    parser.add_argument("-t", "--target", required=True)
    parser.add_argument(
        "--url",
        help="Full URL with parameters (required for injection scanning)"
    )
    args = parser.parse_args()

    ip = resolve_target(args.target)
    if not ip:
        print("[!] Could not resolve target")
        return

    print(f"[+] Target resolved: {args.target} -> {ip}")

    auth_headers = get_auth_headers()
    if auth_headers:
        print("[*] Authenticated scanning enabled")

    # -------------------------------
    # Recon
    # -------------------------------
    open_ports = scan_ports(ip)
    services = detect_services(ip, open_ports)

    base_url = f"http://{args.target}"

    # -------------------------------
    # Web Security Scans
    # -------------------------------
    header_issues = check_security_headers(base_url, auth_headers)
    sensitive_findings = scan_sensitive_files(base_url, auth_headers)

    # -------------------------------
    # Injection Scanning (URL-based)
    # -------------------------------
    injection_findings = []
    if args.url:
        print("[*] Running injection detection...")
        injection_findings = scan_injections(
            args.url,
            auth_headers
        )

        for f in injection_findings:
            print(f"[!] {f['type']} detected on parameter '{f['parameter']}'")

    # -------------------------------
    # Severity Scoring
    # -------------------------------
    header_scores = score_headers(header_issues)
    file_scores = score_sensitive_files(sensitive_findings)
    port_scores = score_ports(open_ports)

    # -------------------------------
    # Plugins
    # -------------------------------
    context = {
        "open_ports": open_ports,
        "services": services,
        "headers": header_issues,
        "sensitive_files": sensitive_findings,
        "injections": injection_findings
    }

    plugin_results = []
    for plugin in load_plugins():
        try:
            plugin_results.append(
                plugin.run(args.target, ip, context)
            )
        except Exception as e:
            print(f"[!] Plugin error: {e}")

    # -------------------------------
    # Reports
    # -------------------------------
    generate_report(
        target=args.target,
        ip=ip,
        open_ports=open_ports,
        services=services,
        headers=header_scores,
        sensitive_files=file_scores
    )

    generate_html_report(
        target=args.target,
        ip=ip,
        open_ports=open_ports,
        services=services,
        headers=header_scores,
        sensitive_files=file_scores
    )

    print("\n[✓] Scan completed successfully")


if __name__ == "__main__":
    main()
