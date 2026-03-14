# pyscan/cli.py

import argparse
from pyscan.core.port_scanner import PortScanner
from pyscan.core.host_discovery import HostDiscovery
from pyscan.utils.report import print_console


def main():
    parser = argparse.ArgumentParser(
        prog="pyscan",
        description="Network Scanner",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # =========================
    # Host Discovery
    # =========================
    host_parser = subparsers.add_parser("host", help="Host discovery")

    host_parser.add_argument(
        "target",
        help="Host ou rede alvo (IP, range ou CIDR)",
    )

    host_parser.add_argument(
        "method",
        choices=["icmp", "tcp", "arp"],
        help="Método de host discovery",
    )

    # =========================
    # Port Scanner
    # =========================
    port_parser = subparsers.add_parser("port", help="Port scanning")

    port_parser.add_argument(
        "target",
        help="Host alvo para escaneamento",
    )

    port_parser.add_argument(
        "-p",
        "--ports",
        required=True,
        help='Porta (80), range (1-100) ou top N ("top 10")',
    )

    port_parser.add_argument(
        "--scan-type",
        choices=["connect", "syn"],
        default="connect",
        help="Tipo de varredura TCP",
    )

    port_parser.add_argument(
        "-t",
        "--threads",
        type=int,
        default=100,
        help="Número de threads",
    )

    port_parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="Timeout por porta",
    )

    args = parser.parse_args()

    # =========================
    # EXECUÇÃO
    # =========================
    if args.command == "host":
        hd = HostDiscovery()
        results = hd.discover(args.target, method=args.method)

    elif args.command == "port":
        scanner = PortScanner(
            scan_type=args.scan_type,
            threads=args.threads,
            timeout=args.timeout,
        )

        ports = scanner.parse_ports(args.ports)
        results = scanner.scan(args.target, ports)

        print_console(results)


# permite rodar com: python -m pyscan.cli
if __name__ == "__main__":
    main()