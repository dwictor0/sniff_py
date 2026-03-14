# pyscan/cli.py

import argparse
import time
from pyscan.core.port_scanner import PortScanner
from pyscan.core.config import ScanConfig
from pyscan.utils.report import print_console


def main():
    parser = argparse.ArgumentParser(
        prog="pyscan",
        description="PyScan - TCP Port Scanner",
        epilog="""
Exemplos:
  pyscan 127.0.0.1 -p 80
  pyscan 127.0.0.1 -p 1-100
  pyscan 127.0.0.1 -p "top 10"
  pyscan 192.168.0.1 -p 1-1024 --scan-type syn
  pyscan scanme.nmap.org -p 80,443 --threads 200 --timeout 0.5
  pyscan 192.168.0.1 -p 1-100 --config 0.5 200 0
""",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    parser.add_argument("target", help="Host alvo para escaneamento (IP ou domínio)")

    parser.add_argument(
        "-p",
        "--ports",
        required=True,
        help='Porta específica (80), range (1-100) ou top N ("top 10")',
    )

    parser.add_argument(
        "--scan-type",
        choices=["connect", "syn"],
        default="connect",
        help="Tipo de varredura TCP (default: connect)",
    )

    parser.add_argument(
        "-t",
        "--threads",
        type=int,
        default=100,
        help="Número de threads (default: 100)",
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="Timeout por porta em segundos (default: 1.0)",
    )

    parser.add_argument(
        "--delay",
        type=float,
        default=0,
        help="Delay entre requisições em segundos (default: 0)",
    )

    parser.add_argument(
        "--config",
        nargs=3,
        metavar=("TIMEOUT", "THREADS", "DELAY"),
        help="Configuração global: timeout threads delay",
    )

    parser.add_argument("--version", action="version", version="pyscan 0.1.0")

    args = parser.parse_args()

    if args.config:

        timeout = float(args.config[0])
        threads = int(args.config[1])
        delay = float(args.config[2])

        config = ScanConfig(timeout, threads, delay)

        config.print_config()

        scanner = PortScanner(
            scan_type=args.scan_type,
            config=config,
        )

    else:

        print("[CONFIG]")
        print(f"Threads: {args.threads}")
        print(f"Timeout: {args.timeout}s")
        print(f"Delay: {args.delay}s\n")

        scanner = PortScanner(
            scan_type=args.scan_type,
            threads=args.threads,
            timeout=args.timeout,
            delay=args.delay,
        )

    print("Scan iniciado...\n")

    start_time = time.time()

    ports = scanner.parse_ports(args.ports)

    result = scanner.scan(args.target, ports)

    print_console(result)

    end_time = time.time()

    print(f"\nScan finalizado em {end_time - start_time:.2f}s")


if __name__ == "__main__":
    main()
