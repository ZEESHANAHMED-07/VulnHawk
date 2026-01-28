import socket
from concurrent.futures import ThreadPoolExecutor

COMMON_PORTS = [21, 22, 80, 443, 3306, 8080]


def scan_port(target_ip, port, timeout=1):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target_ip, port))
        sock.close()
        return port
    except:
        return None


def scan_ports(target_ip, workers=10):
    print("[*] Starting multithreaded TCP port scan...")
    open_ports = []

    with ThreadPoolExecutor(max_workers=workers) as executor:
        results = executor.map(
            lambda p: scan_port(target_ip, p),
            COMMON_PORTS
        )

    for result in results:
        if result:
            print(f"[+] Port {result} is OPEN")
            open_ports.append(result)

    return open_ports
