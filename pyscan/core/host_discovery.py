import time
import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
import scapy.all as scapy


# =========================
# TCP Scanner
# =========================
class TcpScanner:
    def __init__(self, timeout=2):
        self.timeout = timeout

    def tcpSyn(self, host, port=80):
        try:
            start = time.time()
            with socket.create_connection((host, port), timeout=self.timeout):
                pass
            latency = 1000 * (time.time() - start)
            return {"host": host, "status": "UP", "latency": round(latency, 2)}

        except (socket.timeout, ConnectionRefusedError):
            return {"host": host, "status": "DOWN", "latency": None}

        except socket.gaierror:
            return {"host": host, "status": "ERROR", "latency": None}

        except OSError as e:
            print(f"[ERRO TCP] {host}: {e}")
            return {"host": host, "status": "ERROR", "latency": None}


# =========================
# ICMP Scanner
# =========================
class IcmpScanner:
    def __init__(self, timeout=2):
        self.timeout = timeout

    def icmpPing(self, host):
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

            return {"host": host, "status": "DOWN", "latency": None}

        except (PermissionError, OSError) as e:
            print(f"[ERRO ICMP] {host}: {e}")
            return {"host": host, "status": "ERROR", "latency": None}


# =========================
# ARP Scanner
# =========================
class ArpScanner:
    """ARP scan restrito à mesma subnet da interface ativa"""

    def __init__(self, timeout=1, iface=None):
        self.timeout = timeout
        self.iface = iface or scapy.conf.iface

        self.local_ip = scapy.get_if_addr(self.iface)
        self.local_netmask = scapy.get_if_netmask(self.iface)

        self.local_network = ipaddress.IPv4Network(
            f"{self.local_ip}/{self.local_netmask}", strict=False
        )

    def arpBroadcast(self, host):
        try:
            if "/" in host:
                target_net = ipaddress.IPv4Network(host, strict=False)
                targets = list(target_net.hosts())
            else:
                targets = [ipaddress.IPv4Address(host)]

            for ip in targets:
                if ip not in self.local_network:
                    raise ValueError(
                        f"Host {ip} não pertence à rede local {self.local_network}"
                    )

            arp_request = scapy.ARP(pdst=host)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = broadcast / arp_request

            answered, _ = scapy.srp(
                packet,
                timeout=self.timeout,
                iface=self.iface,
                verbose=False,
            )

            if not answered:
                return [
                    {"host": str(ip), "status": "DOWN", "latency": None}
                    for ip in targets
                ]

            client_list = []

            for sent, received in answered:
                latency = None
                if hasattr(sent, "sent_time") and hasattr(received, "time"):
                    latency = round(
                        1000 * (received.time - sent.sent_time), 2
                    )

                client_list.append(
                    {
                        "host": received.psrc,
                        "status": "UP",
                        "latency": latency,
                        "mac": received.hwsrc,
                    }
                )

            return client_list

        except (PermissionError, OSError) as e:
            print(f"[ERRO ARP] {host}: {e}")
            return [{"host": host, "status": "ERROR", "latency": None}]


# =========================
# Host Discovery
# =========================
class HostDiscovery:
    def __init__(self, timeout=2, threads=50, tcp_port=80):
        self.timeout = timeout
        self.threads = threads
        self.tcp_port = tcp_port

        self.tcp_scanner = TcpScanner(timeout=self.timeout)
        self.icmp_scanner = IcmpScanner(timeout=self.timeout)
        self.arp_scanner = ArpScanner(timeout=self.timeout)

    @staticmethod
    def parse_hosts(host_input):
        """Aceita host único, range ou CIDR"""
        host_input = host_input.strip()

        if "-" in host_input:
            start_ip, end_ip = host_input.split("-")
            start_int = int(ipaddress.IPv4Address(start_ip))
            end_int = int(ipaddress.IPv4Address(end_ip))
            return [
                str(ipaddress.IPv4Address(i))
                for i in range(start_int, end_int + 1)
            ]

        elif "/" in host_input:
            net = ipaddress.IPv4Network(host_input, strict=False)
            return [str(ip) for ip in net.hosts()]

        else:
            ipaddress.IPv4Address(host_input)
            return [host_input]

    def discover(self, host_input, method="icmp"):
        hosts = self.parse_hosts(host_input)
        results = []

        scanner = {
            "icmp": self.icmp_scanner.icmpPing,
            "tcp": lambda h: self.tcp_scanner.tcpSyn(h, port=self.tcp_port),
            "arp": self.arp_scanner.arpBroadcast,
        }.get(method.lower())

        if not scanner:
            raise ValueError(f"Método desconhecido: {method}")

        start_time = time.time()

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(scanner, h) for h in hosts]

            for future in as_completed(futures):
                res = future.result()

                if isinstance(res, list):
                    results.extend(res)
                else:
                    results.append(res)

        end_time = time.time()

        total_hosts = sum(1 for r in results if r.get("status") == "UP")

        for r in results:
            lat_str = (
                f"Latência: {r['latency']} ms"
                if r["latency"] is not None
                else "Timeout"
            )
            print(f"[{r['status']}] {r['host']} {lat_str}")

        print("\n[INFO] Descoberta finalizada.")
        print(f"Hosts ativos: {total_hosts}")
        print(f"Tempo total: {end_time - start_time:.2f}s")

        return results