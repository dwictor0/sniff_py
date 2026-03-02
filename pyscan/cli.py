# pyscan/cli.py

import argparse
from pyscan.core.port_scanner import PortScanner
from pyscan.utils.report import print_console


def main():
    parser = argparse.ArgumentParser(
        prog="pyscan",
        description="TCP Port Scanner - Connect Scan ou SYN Scan",
        epilog="""
Exemplos:
  pyscan 127.0.0.1 -p 80
  pyscan 127.0.0.1 -p 1-100
  pyscan 127.0.0.1 -p "top 10"
  pyscan 192.168.0.1 -p 1-1024 --scan-type syn
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
    parser.add_argument("--version", action="version", version="pyscan 0.1.0")

    args = parser.parse_args()

    scanner = PortScanner(
        scan_type=args.scan_type,
        threads=args.threads,
        timeout=args.timeout,
    )

    ports = scanner.parse_ports(args.ports)
    result = scanner.scan(args.target, ports)
    print_console(result)


# permite rodar com: python -m pyscan.cli
if __name__ == "__main__":
    main()
