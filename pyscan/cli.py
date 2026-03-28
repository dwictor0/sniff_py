import argparse
import time

from pyscan.core.port_scanner import PortScanner
from pyscan.core.host_discovery import HostDiscovery
from pyscan.core.config import ScanConfig
from pyscan.model.mode import get_mode, ModeConfig
from pyscan.utils.report import print_console


def validate_positive(value, name):
    if value <= 0:
        raise argparse.ArgumentTypeError(f"{name} deve ser maior que 0")
    return value


def validate_non_negative(value, name):
    if value < 0:
        raise argparse.ArgumentTypeError(f"{name} não pode ser negativo")
    return value


def apply_mode_defaults(args, mode: ModeConfig):
    """
    Aplica valores padrão do modo apenas se o usuário
    não tiver sobrescrito via CLI.
    """
    if not args.ports:
        args.ports = mode.ports

    if args.timeout == 1.0:
        args.timeout = mode.timeout

    if args.threads == 100:
        args.threads = mode.threads

    if args.delay == 0:
        args.delay = mode.delay


def main():
    parser = argparse.ArgumentParser(
        prog="pyscan",
        description="PyScan - Network Scanner",
        epilog="""
Exemplos de uso:

Host Enumeration
pyscan host 192.168.0.0/24 icmp
pyscan host 192.168.0.1 arp
pyscan host 192.168.0.10 tcp

Port Scan
pyscan port 192.168.0.1 -p 80
pyscan port 192.168.0.1 -p 1-100
pyscan port 192.168.0.1 -p "top 10"
pyscan port 192.168.0.1 -p 1-1024 --scan-type syn --threads 50 --timeout 1.5

Port Scan com modo
pyscan port 192.168.0.1 --mode fast
pyscan port 192.168.0.1 --mode full
pyscan port 192.168.0.1 --mode stealth

Port Scan com config global
pyscan port 192.168.0.1 -p 1-100 --config 0.5 200 0
        """,
        formatter_class=argparse.RawTextHelpFormatter,
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
        "--mode",
        choices=["fast", "full", "stealth"],
        help="Modo de execução predefinido",
    )

    port_parser.add_argument(
        "-p",
        "--ports",
        help='Porta específica (80), range (1-100) ou top N ("top 10")',
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
        type=lambda x: validate_positive(int(x), "Threads"),
        default=100,
        help="Número de threads",
    )

    port_parser.add_argument(
        "--timeout",
        type=lambda x: validate_positive(float(x), "Timeout"),
        default=1.0,
        help="Timeout por porta",
    )

    port_parser.add_argument(
        "--delay",
        type=lambda x: validate_non_negative(float(x), "Delay"),
        default=0,
        help="Delay entre as tentativas",
    )

    port_parser.add_argument(
        "--config",
        nargs=3,
        metavar=("TIMEOUT", "THREADS", "DELAY"),
        help="Configuração global: timeout threads delay",
    )

    parser.add_argument("--version", action="version", version="pyscan 0.1.0")

    args = parser.parse_args()

    start_time = time.time()

    if args.command == "host":
        hd = HostDiscovery()
        results = hd.discover(args.target, method=args.method)
        print_console(results)

    elif args.command == "port":
        if args.mode:
            mode: ModeConfig = get_mode(args.mode)
            apply_mode_defaults(args, mode)

            print(f"[MODE] {mode.name}")
            print(mode.describe() + "\n")

        if not args.ports:
            parser.error("Informe --ports ou utilize um --mode")

        if args.config:
            timeout = validate_positive(float(args.config[0]), "Timeout")
            threads = validate_positive(int(args.config[1]), "Threads")
            delay = validate_non_negative(float(args.config[2]), "Delay")

            config = ScanConfig(timeout, threads, delay)

            print("[CONFIG]")
            print(f"{'Threads:':<12}{config.threads:<8}")
            print(f"{'Timeout:':<12}{config.timeout:<8.2f}s")
            print(f"{'Delay:':<12}{config.delay:<8.2f}s\n")

            scanner = PortScanner(
                scan_type=args.scan_type,
                threads=config.threads,
                timeout=config.timeout,
                delay=config.delay,
            )
        else:
            print("[CONFIG]")
            print(f"{'Threads:':<12}{args.threads:<8}")
            print(f"{'Timeout:':<12}{args.timeout:<8.2f}s")
            print(f"{'Delay:':<12}{args.delay:<8.2f}s\n")

            scanner = PortScanner(
                scan_type=args.scan_type,
                threads=args.threads,
                timeout=args.timeout,
                delay=args.delay,
            )

        print("Scan iniciado...\n")

        ports = scanner.parse_ports(args.ports)
        results = scanner.scan(args.target, ports)
        print_console(results)

    end_time = time.time()
    print(f"\nScan finalizado em {end_time - start_time:.2f}s")


if __name__ == "__main__":
    main()
