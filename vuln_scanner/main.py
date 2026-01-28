import argparse

from utils.helpers import resolve_target
from core.ports import scan_ports
from core.services import detect_services
from web.headers import check_security_headers
from web.files import scan_sensitive_files
from reports.reporter import generate_report
from reports.html_reporter import generate_html_report


def main():
    parser = argparse.ArgumentParser(
        description="VulnHawk - Modular Vulnerability Scanner"
    )

    parser.add_argument(
        "-t", "--target",
        required=True,
        help="Target domain or IP address"
    )

    args = parser.parse_args()

    ip = resolve_target(args.target)
    if not ip:
        print("[!] Could not resolve target")
        return

    print(f"[+] Target resolved: {args.target} -> {ip}")

    open_ports = scan_ports(ip)
    if not open_ports:
        print("[-] No open ports found")
        return

    services = detect_services(ip, open_ports)

    base_url = f"http://{args.target}"
    header_issues = check_security_headers(base_url)
    sensitive_findings = scan_sensitive_files(base_url)

    # JSON Report
    generate_report(
        target=args.target,
        ip=ip,
        open_ports=open_ports,
        services=services,
        headers=header_issues,
        sensitive_files=sensitive_findings
    )

    # HTML Report
    generate_html_report(
        target=args.target,
        ip=ip,
        open_ports=open_ports,
        services=services,
        headers=header_issues,
        sensitive_files=sensitive_findings
    )


if __name__ == "__main__":
    main()
