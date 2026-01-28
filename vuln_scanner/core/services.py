import socket
import ssl

def detect_service(target_ip, port, timeout=2):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        sock.connect((target_ip, port))

        if port == 443:
            context = ssl.create_default_context()
            sock = context.wrap_socket(sock, server_hostname=target_ip)

        try:
            sock.sendall(b"HEAD / HTTP/1.1\r\nHost: target\r\n\r\n")
        except:
            pass

        banner = sock.recv(1024).decode(errors="ignore")
        sock.close()

        return banner.strip()

    except:
        return None


def detect_services(target_ip, open_ports):
    services = {}
    print("[*] Detecting services and grabbing banners...")

    for port in open_ports:
        banner = detect_service(target_ip, port)

        if banner:
            print(f"[+] Port {port} banner detected")
            services[port] = banner
        else:
            services[port] = "Unknown / No banner"

    return services
