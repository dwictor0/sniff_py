# pyscan/core/port_scanner.py

import socket
import time
import re
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional, Tuple

try:
    from scapy.all import IP, TCP, sr1, send

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

TOP_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 8080]


# =========================
# Version Detector
# =========================
class VersionDetector:
    SERVICE_REGEX = {
        "SSH": re.compile(r"(OpenSSH)[_/ ]?([\d\.p]+)?", re.IGNORECASE),
        "APACHE": re.compile(r"(Apache)[/ ]?([\d\.]+)?", re.IGNORECASE),
        "NGINX": re.compile(r"(nginx)[/ ]?([\d\.]+)?", re.IGNORECASE),
        "IIS": re.compile(r"(Microsoft-IIS)[/ ]?([\d\.]+)?", re.IGNORECASE),
        "FTP": re.compile(r"(vsFTPd)[/ ]?([\d\.]+)?", re.IGNORECASE),
        "GENERIC_HTTP": re.compile(r"HTTP/[\d\.]+", re.IGNORECASE),
    }

    @classmethod
    def detect(cls, banner: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
        if not banner:
            return None, None
        if isinstance(banner, bytes):
            banner = banner.decode(errors="ignore")
        for name, pattern in cls.SERVICE_REGEX.items():
            match = pattern.search(banner)
            if match:
                if name == "GENERIC_HTTP":
                    return "HTTP", None
                service = match.group(1)
                version = match.group(2) if len(match.groups()) > 1 else None
                return service, version
        return None, None


# =========================
# Models
# =========================
@dataclass
class PortResult:
    port: int
    protocol: str
    state: str
    service: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None


@dataclass
class ScanResult:
    host: str
    results: List[PortResult]
    duration: float

    @property
    def open_ports(self) -> int:
        return sum(1 for r in self.results if r.state == "OPEN")


# =========================
# Scanner
# =========================
class PortScanner:

    def __init__(
        self, scan_type: str = "connect", threads: int = 100, timeout: float = 1.0
    ):
        self.scan_type = scan_type
        self.threads = threads
        self.timeout = timeout

    # Parse ports: 80, 1-100, top 10
    def parse_ports(self, port_input: str) -> List[int]:
        port_input = port_input.strip().lower()
        if port_input.startswith("top"):
            qty = int(port_input.replace("top", "").strip())
            return TOP_PORTS[:qty]
        if "-" in port_input:
            start, end = map(int, port_input.split("-"))
            return list(range(start, end + 1))
        return [int(port_input)]

    # Banner grab
    def get_banner(self, host: str, port: int) -> Optional[str]:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                sock.connect((host, port))
                # Envios simples de dados para banner
                if port == 80 or port == 8080:
                    sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                else:
                    sock.sendall(b"\r\n")
                banner = sock.recv(1024)
                return banner.decode(errors="ignore")
        except Exception:
            return None

    # Connect Scan
    def _connect_scan(self, host: str, port: int) -> PortResult:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            result = sock.connect_ex((host, port))
            if result == 0:
                state = "OPEN"
                banner = self.get_banner(host, port)
                service, version = VersionDetector.detect(banner)
            else:
                state, banner, service, version = "CLOSED", None, None, None
        except socket.timeout:
            state, banner, service, version = "FILTERED", None, None, None
        finally:
            sock.close()
        return PortResult(port, "tcp", state, service, version, banner)

    # SYN Scan
    def _syn_scan(self, host: str, port: int) -> PortResult:
        if not SCAPY_AVAILABLE:
            return PortResult(port, "tcp", "SCAPY_NOT_INSTALLED")
        pkt = IP(dst=host) / TCP(dport=port, flags="S")
        resp = sr1(pkt, timeout=self.timeout, verbose=0)
        if resp is None:
            return PortResult(port, "tcp", "FILTERED")
        if resp.haslayer(TCP):
            if resp[TCP].flags == 0x12:  # SYN-ACK
                send(IP(dst=host) / TCP(dport=port, flags="R"), verbose=0)
                return PortResult(port, "tcp", "OPEN")
            elif resp[TCP].flags == 0x14:  # RST-ACK
                return PortResult(port, "tcp", "CLOSED")
        return PortResult(port, "tcp", "FILTERED")

    # Scan múltiplas portas
    def scan(self, host: str, ports: List[int]) -> ScanResult:
        start_time = time.time()
        results = []
        scan_function = (
            self._connect_scan if self.scan_type == "connect" else self._syn_scan
        )
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(scan_function, host, port) for port in ports]
            for future in as_completed(futures):
                results.append(future.result())
        duration = time.time() - start_time
        return ScanResult(
            host=host, results=sorted(results, key=lambda r: r.port), duration=duration
        )
