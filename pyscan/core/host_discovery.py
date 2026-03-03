import time
import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
import scapy.all as scapy


# =========================
# Classes de Scan
# =========================
class TcpScanner:
    def __init__(self, timeout=2):
        self.timeout = timeout

    def tcpSyn(self, host, port=80):
        try:
            s = socket.socket()
            s.settimeout(self.timeout)
            start = time.time()
            s.connect((host, port))
            s.close()
            end = time.time()
            latency = 1000 * (end - start)
            return {"host": host, "status": "UP", "latency": round(latency, 2)}
        except socket.timeout:
            return {"host": host, "status": "DOWN", "latency": None}
        except socket.gaierror:
            return {"host": host, "status": "ERROR", "latency": None}
        except ConnectionRefusedError:
            return {"host": host, "status": "DOWN", "latency": None}
        except Exception as e:
            print(f"[ERRO TCP] {host}: {e}")
            return {"host": host, "status": "ERROR", "latency": None}


class IcmpScanner:
    def __init__(self, timeout=2):
        self.timeout = timeout

    def icmpPing(self, host):
        try:
            pkt = scapy.IP(dst=host) / scapy.ICMP()
            start = time.time()
            ans, _ = scapy.sr(pkt, timeout=self.timeout, verbose=False)
            end = time.time()

            if ans:
                latency = 1000 * (end - start)
                return {
                    "host": host,
                    "status": "UP",
                    "latency": round(latency, 2),
                }
            else:
                return {"host": host, "status": "DOWN", "latency": None}

        except Exception as e:
            print(f"[ERRO ICMP] {host}: {e}")
            return {"host": host, "status": "ERROR", "latency": None}


class ArpScanner:
    """ARP scan restrito a redes locais"""

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
            return [{"host": str(ip), "status": "DOWN", "latency": None} for ip in targets]

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

    except Exception as e:
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
        hosts = []
        host_input = host_input.strip()
        try:
            if "-" in host_input:
                start_ip, end_ip = host_input.split("-")
                start_int = int(ipaddress.IPv4Address(start_ip))
                end_int = int(ipaddress.IPv4Address(end_ip))
                hosts = [
                    str(ipaddress.IPv4Address(i)) for i in range(start_int, end_int + 1)
                ]
            elif "/" in host_input:
                net = ipaddress.IPv4Network(host_input, strict=False)
                hosts = [str(ip) for ip in net.hosts()]
            else:
                hosts = [host_input]
        except Exception as e:
            print(f"[ERRO] Entrada inválida: {host_input}, {e}")
        return hosts

    def discover(self, host_input, method="icmp"):
        hosts = self.parse_hosts(host_input)
        results = []

        scanner = {
            "icmp": self.icmp_scanner.icmpPing,
            "tcp": lambda h: self.tcp_scanner.tcpSyn(h, port=self.tcp_port),
            "arp": self.arp_scanner.arpBroadcast,
        }.get(method.lower())

        if not scanner:
            print(f"[ERRO] Método desconhecido: {method}")
            return []

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
