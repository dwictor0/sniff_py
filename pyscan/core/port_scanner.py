import socket
import time
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List

try:
    from scapy.all import IP, TCP, sr1, send

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


TOP_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 8080]


# =========================
# Models
# =========================


@dataclass
class PortResult:
    port: int
    protocol: str
    state: str


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

    def parse_ports(self, port_input: str) -> List[int]:
        port_input = port_input.strip().lower()

        if port_input.startswith("top"):
            qty = int(port_input.replace("top", "").strip())
            return TOP_PORTS[:qty]

        if "-" in port_input:
            start, end = map(int, port_input.split("-"))
            return list(range(start, end + 1))

        return [int(port_input)]

    def _connect_scan(self, host: str, port: int):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)

        try:
            result = sock.connect_ex((host, port))
            if result == 0:
                state = "OPEN"
            else:
                state = "CLOSED"
        except socket.timeout:
            state = "FILTERED"
        finally:
            sock.close()

        return PortResult(port, "tcp", state)

    def _syn_scan(self, host: str, port: int):
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
