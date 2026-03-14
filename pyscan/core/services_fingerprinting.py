import socket
import ssl
import re
from concurrent.futures import ThreadPoolExecutor, as_completed


# =========================
# Service Detection
# =========================
class ServiceDetector:
    def __init__(self, timeout=2):
        self.timeout = timeout

        self.default_ports = {
            21: "FTP",
            22: "SSH",
            23: "TELNET",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            3306: "MYSQL",
            3389: "RDP",
        }

    def detect_service(self, host, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)

                try:
                    sock.connect((host, port))
                except (socket.timeout, ConnectionRefusedError, OSError):
                    return {"port": port, "status": "CLOSED"}

                banner = ""

                if port == 443:
                    try:
                        context = ssl.create_default_context()

                        with context.wrap_socket(sock, server_hostname=host) as ssock:
                            ssock.sendall(
                                b"HEAD / HTTP/1.1\r\nHost: "
                                + host.encode()
                                + b"\r\nConnection: close\r\n\r\n"
                            )
                            banner = ssock.recv(1024).decode(errors="ignore").strip()

                    except ssl.SSLError:
                        return {"port": port, "status": "OPEN", "service": "HTTPS"}

                else:
                    try:
                        if port in (80, 8080):
                            sock.sendall(
                                b"HEAD / HTTP/1.0\r\nConnection: close\r\n\r\n"
                            )

                        banner = sock.recv(1024).decode(errors="ignore").strip()

                    except socket.timeout:
                        banner = ""

                service = self.identify_by_banner(banner)

                if not service:
                    service = self.default_ports.get(port, "UNKNOWN")

                return {
                    "port": port,
                    "status": "OPEN",
                    "service": service,
                    "banner": banner,
                }

        except Exception:
            return {"port": port, "status": "ERROR"}
        except (socket.timeout, ConnectionRefusedError, OSError):
            return {"port": port, "status": "CLOSED"}

    def identify_by_banner(self, banner):
        if not banner:
            return None

        banner = banner.upper()

        services_patterns = {
            "SSH": r"\bSSH\b",
            "HTTP": r"\bHTTP\b",
            "FTP": r"\bFTP\b",
            "SMTP": r"\bSMTP\b",
            "MYSQL": r"\bMYSQL\b",
            "POP3": r"\bPOP3\b",
            "IMAP": r"\bIMAP\b",
            "RDP": r"\bRDP\b",
        }

        for service, pattern in services_patterns.items():
            if re.search(pattern, banner):
                return service

        return None


# =========================
# Scanner de Fingerprinting
# =========================
class ServiceFingerprintScanner:
    def __init__(self, timeout=1, threads=200):
        self.timeout = timeout
        self.threads = threads
        self.detector = ServiceDetector(timeout=self.timeout)

    def scan_ports(self, host, ports=None):
        """
        Se ports for None -> escaneia portas padrão (1-1024)
        """

        if ports is None:
            ports = range(1, 1025)

        if isinstance(ports, int):
            ports = [ports]

        open_ports = []

        with ThreadPoolExecutor(max_workers=self.threads) as executor:

            futures = {
                executor.submit(self.detector.detect_service, host, port): port
                for port in ports
            }

            for future in as_completed(futures):
                try:
                    result = future.result()

                    if result["status"] == "OPEN":
                        open_ports.append(result)

                except Exception as e:
                    print(f"[ERROR] Falha ao escanear porta {futures[future]}: {e}")
                    continue

        open_ports.sort(key=lambda x: x["port"])

        if open_ports:
            for port_info in open_ports:
                print("[INFO] Serviços identificados com sucesso.")
                print(f"{port_info['port']}/tcp  OPEN  {port_info['service']}")
        else:
            print("\n[INFO] Nenhuma porta aberta encontrada.")
