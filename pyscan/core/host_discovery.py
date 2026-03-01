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
            pkt = (
                scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
                / scapy.IP(dst=host)
                / scapy.ICMP()
            )
            ans, _ = scapy.srp(pkt, timeout=self.timeout, verbose=False)
            if ans:
                latency = 1000 * (
                    ans[0][1].time - ans[0][0].sent_time
                )
                return {
                    "host": host,
                    "status": "UP",
                    "latency": round(latency, 2)
                }
            else:
                return {"host": host, "status": "DOWN", "latency": None}
        except Exception as e:
            print(f"[ERRO ICMP] {host}: {e}")
            return {"host": host, "status": "ERROR", "latency": None}


class ArpScanner:
    """ARP scan restrito a redes locais"""

    def __init__(self, timeout=1):
        self.timeout = timeout

    def arpBroadcast(self, host):
        try:
            ip_obj = (
                ipaddress.IPv4Address(host.split("/")[0])
                if "/" in host
                else ipaddress.IPv4Address(host)
            )
            if not (ip_obj.is_private):
                raise ValueError(
                    (
                        f"ARP só é permitido em redes locais. "
                        f"Host {host} não permitido."
                    )
                )

            arpRequest = scapy.ARP(pdst=host)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arpRequest
            answered_list = scapy.srp(
                arp_request_broadcast, timeout=self.timeout, verbose=False
            )[0]

            if not answered_list:
                return [{"host": host, "status": "DOWN", "latency": None}]

            client_list = []
            for element in answered_list:
                latency = 1000 * (element[1].time - element[0].sent_time)
                client_list.append(
                    {
                        "host": element[1].psrc,
                        "status": "UP",
                        "latency": round(latency, 2),
                        "mac": element[1].hwsrc,
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
                    str(ipaddress.IPv4Address(i))
                    for i in range(start_int, end_int + 1)
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
