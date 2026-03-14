import socket
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
                sock.connect((host, port))
                if port in [80, 8080]:
                    sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")

                banner = ""
                try:
                    banner = sock.recv(1024).decode(errors="ignore").strip()
                except Exception as e:
                    print(f"[ERROR] {host}: {e}")
                    return {"host": host, "status": "ERROR", "latency": None}


                service = self.identify_by_banner(banner)

                if not service:
                    service = self.default_ports.get(port, "UNKNOWN")

                return {"port": port, "status": "OPEN", "service": service}

        except (socket.timeout, ConnectionRefusedError):
            return {"port": port, "status": "CLOSED"}
        except Exception:
            return {"port": port, "status": "CLOSED"}

    def identify_by_banner(self, banner):
        banner = banner.upper()

        if "SSH" in banner:
            return "SSH"
        elif "HTTP" in banner:
            return "HTTP"
        elif "FTP" in banner:
            return "FTP"
        elif "SMTP" in banner:
            return "SMTP"
        elif "MYSQL" in banner:
            return "MYSQL"
        elif "POP3" in banner:
            return "POP3"
        elif "IMAP" in banner:
            return "IMAP"
        elif "RDP" in banner:
            return "RDP"
        else:
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

        open_ports = []

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [
                executor.submit(self.detector.detect_service, host, port)
                for port in ports
            ]

            for future in as_completed(futures):
                result = future.result()
                if result["status"] == "OPEN":
                    open_ports.append(result)

        open_ports.sort(key=lambda x: x["port"])

        for port_info in open_ports:
            print(f"{port_info['port']}/tcp  OPEN  {port_info['service']}")

        print("\n[INFO] Serviços identificados com sucesso.")

        return open_ports
