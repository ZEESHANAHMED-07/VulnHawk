import argparse

from utils.helpers import resolve_target
from core.ports import scan_ports
from core.services import detect_services
from web.headers import check_security_headers
from web.files import scan_sensitive_files
from core.severity import (
    score_headers,
    score_sensitive_files,
    score_ports,
    severity_label
)
from reports.reporter import generate_report
from reports.html_reporter import generate_html_report


def main():
    parser = argparse.ArgumentParser(
        description="VulnHawk - Modular Vulnerability Scanner"
    )
    parser.add_argument("-t", "--target", required=True)
    args = parser.parse_args()

    ip = resolve_target(args.target)
    if not ip:
        print("[!] Could not resolve target")
        return

    print(f"[+] Target resolved: {args.target} -> {ip}")

    # Multithreaded port scan
    open_ports = scan_ports(ip)
    services = detect_services(ip, open_ports)

    base_url = f"http://{args.target}"
    header_issues = check_security_headers(base_url)
    sensitive_findings = scan_sensitive_files(base_url)

    # Severity scoring
    header_scores = score_headers(header_issues)
    file_scores = score_sensitive_files(sensitive_findings)
    port_scores = score_ports(open_ports)

    # Reports
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


if __name__ == "__main__":
    main()
