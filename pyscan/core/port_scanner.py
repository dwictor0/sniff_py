"""
Módulo de varredura de portas.
Fornece recursos de varredura de conexão TCP e varredura SYN,
incluindo captura opcional de banners e detecção de serviços.
"""

import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional

from pyscan.model.port_result import PortResult
from pyscan.model.scan_result import ScanResult
from pyscan.core.version_detector import VersionDetector
from pyscan.core.config import ScanConfig

try:
    from scapy.all import IP, TCP, sr1, send

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


TOP_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 8080]


class PortScanner:
    """
    Executa operações de varredura de portas em um host alvo.

    Suporta:
        - Varredura TCP Connect
        - Varredura TCP SYN (requer Scapy)
        - Captura de banners
        - Detecção de serviço e versão
    """

    def __init__(
        self,
        scan_type: str = "connect",
        threads: int = 100,
        timeout: float = 1.0,
        delay: float = 0.0,
        config: Optional[ScanConfig] = None,
    ):
        """
        Inicializa o scanner.

        Args:
            scan_type (str): Tipo de scan ("connect" ou "syn")
            threads (int): Número de threads
            timeout (float): Timeout de conexão
            delay (float): Delay entre probes
            config (ScanConfig): Configuração global opcional
        """

        if config:
            self.timeout = config.timeout
            self.threads = config.threads
            self.delay = config.delay
        else:
            self.timeout = timeout
            self.threads = threads
            self.delay = delay

        self.scan_type = scan_type

    def parse_ports(self, port_input: str) -> List[int]:
        """
        Converte entrada de portas em lista de inteiros.

        Formatos suportados:
            80
            20-25
            top 10
        """

        port_input = port_input.strip().lower()

        if port_input.startswith("top"):
            qty = int(port_input.replace("top", "").strip())
            return TOP_PORTS[:qty]

        if "-" in port_input:
            start, end = map(int, port_input.split("-"))
            return list(range(start, end + 1))

        return [int(port_input)]

    def get_banner(self, host: str, port: int) -> Optional[str]:
        """
        Tenta capturar banner do serviço.
        """

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:

                sock.settimeout(self.timeout)
                sock.connect((host, port))

                if port in (80, 8080):
                    sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                else:
                    sock.sendall(b"\r\n")

                banner = sock.recv(1024)

                return banner.decode(errors="ignore")

        except Exception:
            return None

    def _connect_scan(self, host: str, port: int) -> PortResult:
        """
        Executa TCP Connect Scan.
        """

        if self.delay > 0:
            time.sleep(self.delay)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)

        try:

            result = sock.connect_ex((host, port))

            if result == 0:

                state = "OPEN"

                banner = self.get_banner(host, port)

                service, version = (
                    VersionDetector.detect(banner) if banner else (None, None)
                )

            else:

                state = "CLOSED"
                banner = service = version = None

        except socket.timeout:

            state = "FILTERED"
            banner = service = version = None

        finally:
            sock.close()

        return PortResult(
            port=port,
            protocol="tcp",
            state=state,
            service=service,
            version=version,
            banner=banner,
        )

    def _syn_scan(self, host: str, port: int) -> PortResult:
        """
        Executa TCP SYN Scan (semi-open scan).
        """

        if self.delay > 0:
            time.sleep(self.delay)

        if not SCAPY_AVAILABLE:

            return PortResult(
                port=port,
                protocol="tcp",
                state="SCAPY_NOT_INSTALLED",
            )

        pkt = IP(dst=host) / TCP(dport=port, flags="S")

        resp = sr1(pkt, timeout=self.timeout, verbose=0)

        if resp is None:

            return PortResult(port=port, protocol="tcp", state="FILTERED")

        if resp.haslayer(TCP):

            if resp[TCP].flags == 0x12:

                send(IP(dst=host) / TCP(dport=port, flags="R"), verbose=0)

                return PortResult(port=port, protocol="tcp", state="OPEN")

            elif resp[TCP].flags == 0x14:

                return PortResult(port=port, protocol="tcp", state="CLOSED")

        return PortResult(port=port, protocol="tcp", state="FILTERED")

    def scan(self, host: str, ports: List[int]) -> ScanResult:
        """
        Executa varredura de portas em um host.

        Args:
            host: Host alvo
            ports: Lista de portas

        Returns:
            ScanResult
        """

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
            host=host,
            results=sorted(results, key=lambda r: r.port),
            duration=duration,
        )
