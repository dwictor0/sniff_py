import time
import ipaddress
import netifaces
from concurrent.futures import ThreadPoolExecutor, as_completed
import scapy.all as scapy


# =========================
# TCP Scanner
# =========================
class TcpScanner:
    """
    Realiza verificação de disponibilidade de host via conexão TCP.
    """

    def __init__(self, timeout=2):
        """
        Inicializa o scanner TCP SYN.

        Args:
            timeout (int | float): Tempo máximo de espera em segundos.
        """
        self.timeout = timeout

    def tcpSyn(self, host, port=80):
        """
        Executa TCP SYN scan para verificar se a porta está aberta.

        Args:
            host (str): IP alvo.
            port (int): Porta TCP a ser testada.

        Returns:
            dict: Resultado contendo:
                - host (str)
                - status (str): UP, DOWN ou FILTERED
                - latency (float | None)
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
                        dport=port, flags="R", seq=response.ack
                    )
                    scapy.send(rst_packet, verbose=False)

                    return {
                        "host": host,
                        "status": "UP",
                        "latency": round(latency, 2),
                    }

                elif tcp_flags == 0x14:
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

        except (PermissionError, OSError) as e:
            print(f"[ERRO TCP SYN] {host}: {e}")
            return {"host": host, "status": "ERROR", "latency": None}


# =========================
# ICMP Scanner
# =========================
class IcmpScanner:
    """
    Realiza descoberta de host via ICMP Echo Request (ping).
    """

    def __init__(self, timeout=2):
        """
        Inicializa o scanner ICMP.

        Args:
            timeout (int | float): Tempo máximo de espera em segundos.
        """
        self.timeout = timeout

    def icmpPing(self, host):
        """
        Envia um ICMP Echo Request para verificar disponibilidade do host.

        Args:
            host (str): Endereço IP alvo.

        Returns:
            dict: Resultado contendo:
                - host (str)
                - status (str): UP, DOWN ou ERROR
                - latency (float | None): Latência em ms
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

            return {"host": host, "status": "DOWN", "latency": None}

        except (PermissionError, OSError) as e:
            print(f"[ERRO ICMP] {host}: {e}")
            return {"host": host, "status": "ERROR", "latency": None}


# =========================
# ARP Scanner
# =========================
class ArpScanner:
    """
    Realiza varredura ARP restrita à mesma subnet da interface ativa.
    """

    def __init__(self, timeout=1, iface=None):
        """
        Inicializa o scanner ARP.

        Args:
            timeout (int | float): Tempo máximo de espera em segundos.
            iface (str | None): Interface de rede a ser utilizada.
            Se None, utiliza a interface padrão do Scapy.
        """
        self.timeout = timeout
        self.iface = iface or scapy.conf.iface
        iface_name = self.iface.name if hasattr(self.iface, "name") else self.iface
        self.local_ip = scapy.get_if_addr(iface_name)
        netif = netifaces.ifaddresses(iface_name)
        self.local_netmask = netif[netifaces.AF_INET][0]["netmask"]
        self.local_network = ipaddress.IPv4Network(
            f"{self.local_ip}/{self.local_netmask}", strict=False
        )

    def arpBroadcast(self, host):
        """
        Executa varredura ARP para um IP ou rede CIDR.

        Args:
            host (str): IP único ou rede no formato CIDR (ex: 192.168.1.0/24).

        Returns:
            list[dict]: Lista contendo:
                - host (str)
                - status (str): UP, DOWN ou ERROR
                - latency (float | None)
                - mac (str, opcional)

        Raises:
            ValueError: Se o host não pertencer à mesma rede local.
        """
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
                    latency = round(1000 * (received.time - sent.sent_time), 2)

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
    """
    Classe principal responsável por coordenar a descoberta de hosts
    utilizando diferentes métodos (ICMP, TCP ou ARP).
    """

    def __init__(self, timeout=2, threads=50, tcp_port=80):
        """
        Inicializa o mecanismo de descoberta.

        Args:
            timeout (int | float): Timeout padrão para scanners.
            threads (int): Número máximo de threads simultâneas.
            tcp_port (int): Porta padrão usada no método TCP.
        """
        self.timeout = timeout
        self.threads = threads
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

        elif "/" in host_input:
            net = ipaddress.IPv4Network(host_input, strict=False)
            return [str(ip) for ip in net.hosts()]

        else:
            ipaddress.IPv4Address(host_input)
            return [host_input]

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
            print(f"[{r['status']:^7}] {r['host']:<15} {lat_str}")

        print("\n[INFO] Descoberta finalizada.")
        print(f"Hosts ativos: {total_hosts}")
        print(f"Tempo total: {end_time - start_time:.2f}s")

        return results
