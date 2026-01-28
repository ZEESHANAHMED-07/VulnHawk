import socket

COMMON_PORTS = [21, 22, 80, 443, 3306, 8080]

def scan_port(target_ip, port, timeout=1):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        sock.connect((target_ip, port))
        sock.close()
        return True
    except:
        return False

def scan_ports(target_ip):
    open_ports = []
    print("[*] Starting TCP port scan...")

    for port in COMMON_PORTS:
        if scan_port(target_ip, port):
            print(f"[+] Port {port} is OPEN")
            open_ports.append(port)

    return open_ports
