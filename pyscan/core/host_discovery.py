import ipaddress
import logging
import time
import psutil
from concurrent.futures import ThreadPoolExecutor, as_completed

import scapy.all as scapy

from pyscan.model.scan_result import HostDiscoveryResult, HostResult

logging.getLogger("scapy").setLevel(logging.CRITICAL)
logging.getLogger("scapy.runtime").setLevel(logging.CRITICAL)


# =========================
# TCP Scanner
# =========================
class TcpScanner:
    """
    Realiza verificação de disponibilidade de host via conexão TCP.
    """

    def __init__(self, timeout=2):
        self.timeout = timeout

    def tcp_syn(self, host, port=80):
        """
        Executa TCP SYN para verificar disponibilidade do host.
        """
        try:
            ip_layer = scapy.IP(dst=host)
            tcp_layer = scapy.TCP(dport=port, flags="S")
            packet = ip_layer / tcp_layer

            start = time.time()
            response = scapy.sr1(packet, timeout=self.timeout, verbose=False)
            latency = 1000 * (time.time() - start)

            if response is None:
                return {
                    "host": host,
                    "status": "FILTERED",
                    "latency": None,
                }

            if response.haslayer(scapy.TCP):
                tcp_flags = response.getlayer(scapy.TCP).flags

                if tcp_flags == 0x12:
                    rst_packet = scapy.IP(dst=host) / scapy.TCP(
                        dport=port,
                        flags="R",
                        seq=response.ack,
                    )
                    scapy.send(rst_packet, verbose=False)

                    return {
                        "host": host,
                        "status": "UP",
                        "latency": round(latency, 2),
                    }

                if tcp_flags == 0x14:
                    return {
                        "host": host,
                        "status": "DOWN",
                        "latency": None,
                    }

            return {
                "host": host,
                "status": "FILTERED",
                "latency": None,
            }

        except (PermissionError, OSError) as exc:
            print(f"[ERRO TCP SYN] {host}: {exc}")
            return {
                "host": host,
                "status": "ERROR",
                "latency": None,
            }


# =========================
# ICMP Scanner
# =========================
class IcmpScanner:
    """
    Realiza descoberta de host via ICMP Echo Request.
    """

    def __init__(self, timeout=2):
        self.timeout = timeout

    def icmp_ping(self, host):
        """
        Envia um ICMP Echo Request para verificar disponibilidade do host.
        """
        try:
            pkt = scapy.IP(dst=host) / scapy.ICMP()

            start = time.time()
            ans, _ = scapy.sr(pkt, timeout=self.timeout, verbose=False)
            latency = 1000 * (time.time() - start)

            if ans:
                return {
                    "host": host,
                    "status": "UP",
                    "latency": round(latency, 2),
                }

            return {
                "host": host,
                "status": "DOWN",
                "latency": None,
            }

        except (PermissionError, OSError) as exc:
            print(f"[ERRO ICMP] {host}: {exc}")
            return {
                "host": host,
                "status": "ERROR",
                "latency": None,
            }


# =========================
# ARP Scanner
# =========================
class ArpScanner:
    """
    Realiza varredura ARP restrita à mesma subnet da interface ativa.
    """

    def __init__(self, timeout=1, iface=None):
        """
        Inicializa o scanner ARP usando psutil.
        """
        self.timeout = timeout
        
        self.iface = iface or scapy.conf.iface
        iface_name = self.iface.name if hasattr(self.iface, "name") else str(self.iface)
        
        addrs = psutil.net_if_addrs()
        
        if iface_name not in addrs:
            raise ValueError(f"Interface {iface_name} não encontrada.")
            
        self.local_ip = None
        self.local_netmask = None
        
        for addr in addrs[iface_name]:
            if addr.family == 2:  # AF_INET (IPv4)
                self.local_ip = addr.address
                self.local_netmask = addr.netmask
                break
        
        if not self.local_ip or not self.local_netmask:
            raise ValueError(f"Não foi possível obter IP/Máscara da interface {iface_name}")
            
        self.local_network = ipaddress.IPv4Network(
            f"{self.local_ip}/{self.local_netmask}",
            strict=False,
        )

    def arp_broadcast(self, host):
        """
        Executa varredura ARP para um IP ou rede CIDR.
        """
        try:
            if "/" in host:
                target_net = ipaddress.IPv4Network(host, strict=False)
                targets = list(target_net.hosts())
            else:
                targets = [ipaddress.IPv4Address(host)]

            for ip in targets:
                if ip not in self.local_network:
                    raise ValueError(f"Host {ip} não pertence à rede local {self.local_network}")

            arp_request = scapy.ARP(pdst=host)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = broadcast / arp_request

            answered, _ = scapy.srp(
                packet,
                timeout=self.timeout,
                iface=self.iface,
                verbose=False,
            )

            client_list = []
            for sent, received in answered:
                latency = None
                if hasattr(sent, "sent_time") and hasattr(received, "time"):
                    latency = round(1000 * (received.time - sent.sent_time), 2)

                client_list.append({
                    "host": received.psrc,
                    "status": "UP",
                    "latency": latency,
                    "mac": received.hwsrc,
                })

            return client_list if client_list else [{"host": host, "status": "DOWN", "latency": None}]

        except (PermissionError, OSError, ValueError) as exc:
            print(f"[ERRO ARP] {host}: {exc}")
            return [{"host": host, "status": "ERROR", "latency": None}]


# =========================
# Host Discovery
# =========================
class HostDiscovery:
    """
    Classe principal responsável por coordenar a descoberta de hosts
    utilizando diferentes métodos (ICMP, TCP ou ARP).
    """

    def __init__(
        self,
        timeout: float = 2.0,
        threads: int = 50,
        delay: float = 0.0,
        tcp_port: int = 80,
        config=None,
    ):
        """
        Inicializa o mecanismo de descoberta.

        Args:
            timeout (int | float): Timeout padrão para scanners.
            threads (int): Número máximo de threads simultâneas.
            delay (float): Delay entre probes.
            tcp_port (int): Porta padrão usada no método TCP.
            config (ScanConfig): Configuração global opcional.
        """
        if config:
            self.timeout = config.timeout
            self.threads = config.threads
            self.delay = config.delay
        else:
            self.timeout = timeout
            self.threads = threads
            self.delay = delay

        self.tcp_port = tcp_port
        self.tcp_scanner = TcpScanner(timeout=self.timeout)
        self.icmp_scanner = IcmpScanner(timeout=self.timeout)
        self.arp_scanner = ArpScanner(timeout=self.timeout)

    @staticmethod
    def parse_hosts(host_input):
        """
        Interpreta entrada de host único, range ou rede CIDR.

        Args:
            host_input (str): Entrada fornecida pelo usuário.

        Returns:
            list[str]: Lista de IPs válidos.

        Raises:
            ValueError: Se a entrada for inválida.
        """
        host_input = host_input.strip()

        if "-" in host_input:
            start_ip, end_ip = host_input.split("-")
            start_int = int(ipaddress.IPv4Address(start_ip))
            end_int = int(ipaddress.IPv4Address(end_ip))
            return [
                str(ipaddress.IPv4Address(i)) for i in range(start_int, end_int + 1)
            ]

        if "/" in host_input:
            net = ipaddress.IPv4Network(host_input, strict=False)
            return [str(ip) for ip in net.hosts()]

        ipaddress.IPv4Address(host_input)
        return [host_input]

    def _scan_with_delay(self, scanner_func, host):
        result = scanner_func(host)

        if self.delay > 0:
            time.sleep(self.delay)

        return result

    def discover(self, host_input, method="icmp"):
        """
        Executa a descoberta de hosts utilizando o método especificado.

        Args:
            host_input (str): Host único, range ou rede CIDR.
            method (str): Método de varredura ('icmp', 'tcp', 'arp').

        Returns:
            list[dict]: Lista de resultados contendo status e latência.

        Raises:
            ValueError: Se método inválido for informado.
        """
        hosts = self.parse_hosts(host_input)
        results = []

        scanner = {
            "icmp": self.icmp_scanner.icmp_ping,
            "tcp": lambda h: self.tcp_scanner.tcp_syn(h, port=self.tcp_port),
            "arp": self.arp_scanner.arp_broadcast,
        }.get(method.lower())

        if not scanner:
            raise ValueError(f"Método desconhecido: {method}")

        start_time = time.time()

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [
                executor.submit(self._scan_with_delay, scanner, h) for h in hosts
            ]

            for future in as_completed(futures):
                res = future.result()

                if isinstance(res, list):
                    results.extend(res)
                else:
                    results.append(res)

        duration = round(time.time() - start_time, 2)

        host_results = [
            HostResult(
                host=r["host"],
                status=r["status"],
                latency=r.get("latency"),
                mac=r.get("mac"),
            )
            for r in results
        ]

        return HostDiscoveryResult(
            host=host_input,
            results=host_results,
            duration=duration,
        )
