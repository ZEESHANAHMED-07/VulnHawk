import argparse
from utils.helpers import resolve_target
from core.ports import scan_ports

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
    else:
        print(f"[+] Open ports discovered: {open_ports}")

if __name__ == "__main__":
    main()
