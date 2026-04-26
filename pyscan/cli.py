import argparse
import time
from datetime import datetime

from pyscan.core.port_scanner import PortScanner
from pyscan.core.host_discovery import HostDiscovery
from pyscan.core.config import ScanConfig
from pyscan.model.mode import get_mode, ModeConfig
from pyscan.utils.report import print_console, export_html_report


def validate_positive(value, name):
    if value <= 0:
        raise argparse.ArgumentTypeError(f"{name} deve ser maior que 0")
    return value


def validate_non_negative(value, name):
    if value < 0:
        raise argparse.ArgumentTypeError(f"{name} não pode ser negativo")
    return value


def apply_mode_defaults(args, mode: ModeConfig):
    if not args.ports:
        args.ports = mode.ports

    if args.timeout == 1.0:
        args.timeout = mode.timeout

    if args.threads == 100:
        args.threads = mode.threads

    if args.delay == 0:
        args.delay = mode.delay


def resolve_config(args):
    if args.mode:
        mode = get_mode(args.mode)
        apply_mode_defaults(args, mode)

        print(f"[MODE] {mode.name}")
        print(mode.describe() + "\n")

    if args.config:
        timeout = validate_positive(float(args.config[0]), "Timeout")
        threads = validate_positive(int(args.config[1]), "Threads")
        delay = validate_non_negative(float(args.config[2]), "Delay")

        return ScanConfig(timeout, threads, delay)

    return ScanConfig(args.timeout, args.threads, args.delay)


def main():
    parser = argparse.ArgumentParser(
        prog="pyscan",
        description="PyScan - Network Scanner",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
==============================
EXEMPLOS COMPLETOS
==============================

HOST DISCOVERY
sudo .venv/bin/pyscan 192.168.0.0/24 --host icmp
pyscan 192.168.0.1 --host tcp
sudo .venv/bin/pyscan 192.168.0.0/24 --host arp

PORT SCAN
pyscan 192.168.0.1 -p 80
pyscan 192.168.0.1 -p 1-100
pyscan 192.168.0.1 -p "top 10"

MODOS
pyscan 192.168.0.1 --mode fast
pyscan 192.168.0.1 --mode full
pyscan 192.168.0.1 --mode stealth

CONFIG GLOBAL
pyscan 192.168.0.1 --config 0.5 200 0

COMBINAÇÕES E RELATÓRIOS HTML
pyscan 192.168.0.1 -p 1-100 --mode fast
sudo .venv/bin/pyscan 192.168.0.0/24 --host icmp --mode stealth --html
pyscan 192.168.0.1 -p "top 100" --html
        """,
    )

    # =========================
    # ARGUMENTOS GLOBAIS
    # =========================
    parser.add_argument(
        "target",
        help="Host alvo ou rede (IP, range ou CIDR)",
    )

    parser.add_argument(
        "--host",
        choices=["icmp", "tcp", "arp"],
        help="Executa host discovery",
    )

    parser.add_argument(
        "-p",
        "--ports",
        help='Portas: "80", "1-100", "top 10"',
    )

    parser.add_argument(
        "--scan-type",
        choices=["connect", "syn"],
        default="connect",
        help="Tipo de scan TCP",
    )

    parser.add_argument(
        "--mode",
        choices=["fast", "full", "stealth"],
        help="Modo predefinido",
    )

    parser.add_argument(
        "-t",
        "--threads",
        type=lambda x: validate_positive(int(x), "Threads"),
        default=100,
        help="Número de threads",
    )

    parser.add_argument(
        "--timeout",
        type=lambda x: validate_positive(float(x), "Timeout"),
        default=1.0,
        help="Timeout",
    )

    parser.add_argument(
        "--delay",
        type=lambda x: validate_non_negative(float(x), "Delay"),
        default=0,
        help="Delay entre requests",
    )

    parser.add_argument(
        "--config",
        nargs=3,
        metavar=("TIMEOUT", "THREADS", "DELAY"),
        help="Config global",
    )

    parser.add_argument(
        "--html",
        action="store_true",
        help="Gera um relatório HTML ao final (report.html)",
    )

    parser.add_argument("--version", action="version", version="pyscan 1.0")

    args = parser.parse_args()
    start_time_dt = datetime.now()
    start_time = time.time()

    config = resolve_config(args)

    print("[CONFIG]")
    print(f"{'Threads:':<12}{config.threads}")
    print(f"{'Timeout:':<12}{config.timeout}")
    print(f"{'Delay:':<12}{config.delay}\n")

    # =========================
    # HOST DISCOVERY
    # =========================
    if args.host:
        print("Host discovery iniciado...\n")

        hd = HostDiscovery(config=config)

        results = hd.discover(args.target, method=args.host)
        print_console(results)

    # =========================
    # PORT SCAN
    # =========================
    else:
        if not args.ports:
            parser.error("Informe --ports ou use --host")

        print("Port scan iniciado...\n")

        scanner = PortScanner(
            scan_type=args.scan_type,
            config=config,
        )

        ports = scanner.parse_ports(args.ports)
        results = scanner.scan(args.target, ports)

        print_console(results)

    end_time = time.time()
    print(f"\nTempo total: {end_time - start_time:.2f}s")

    if args.html:
        export_html_report(
            results=results,
            start_time=start_time_dt,
            target=args.target,
            mode=args.mode,
            threads=config.threads,
            timeout=config.timeout,
        )


if __name__ == "__main__":
    main()
