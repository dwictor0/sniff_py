# pyscan/cli.py

import argparse
import time
from pyscan.core.port_scanner import PortScanner
from pyscan.core.config import ScanConfig
from pyscan.utils.report import print_console

MODES = {
    "fast": {
        "ports": "top 100",
        "timeout": 1.0,
        "threads": 50,
        "delay": 0,
    },
    "full": {
        "ports": "1-65535",
        "timeout": 1.5,
        "threads": 200,
        "delay": 0,
    },
    "stealth": {
        "ports": "top 100",
        "timeout": 2.0,
        "threads": 20,
        "delay": 0.5,
    },
}


def main():
    parser = argparse.ArgumentParser(
        prog="pyscan",
        description="PyScan - TCP Port Scanner",
        epilog="""
Exemplos:

  Scan simples em uma porta
    pyscan 127.0.0.1 -p 80

  Scan em um range de portas
    pyscan 127.0.0.1 -p 1-100

  Scan nas top 10 portas mais comuns
    pyscan 127.0.0.1 -p "top 10"

  Scan SYN em múltiplas portas
    pyscan 192.168.0.1 -p 1-1024 --scan-type syn

  Scan com configuração personalizada
    pyscan scanme.nmap.org -p 80,443 --threads 200 --timeout 0.5

  Configuração global manual
    pyscan 192.168.0.1 -p 1-100 --config 0.5 200 0


Modos de execução:

  FAST
    Scan rápido nas 100 portas mais comuns
    Timeout: 1s | Threads: 50 | Delay: 0
    pyscan 192.168.0.1 --mode fast

  FULL
    Scan completo em todas as portas TCP
    Timeout: 1.5s | Threads: 200 | Delay: 0
    pyscan 192.168.0.1 --mode full

  STEALTH
    Scan mais discreto com menor paralelismo
    Timeout: 2s | Threads: 20 | Delay: 0.5
    pyscan 192.168.0.1 --mode stealth


Observação:
  Parâmetros definidos na CLI sobrescrevem os valores do modo.

  Exemplo:
    pyscan 192.168.0.1 --mode fast --threads 150
""",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    parser.add_argument("target", help="Host alvo para escaneamento (IP ou domínio)")

    parser.add_argument(
        "--mode",
        choices=["fast", "full", "stealth"],
        help="Modo de execução predefinido",
    )

    parser.add_argument(
        "-p",
        "--ports",
        required=False,
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

    if args.mode:

        mode = MODES[args.mode]

        if not args.ports:
            args.ports = mode["ports"]

        if args.timeout == 1.0:
            args.timeout = mode["timeout"]

        if args.threads == 100:
            args.threads = mode["threads"]

        if args.delay == 0:
            args.delay = mode["delay"]

        print(f"[MODE] {args.mode.upper()}")
        print(
            f"{args.ports} | Timeout: {args.timeout}s | Threads: {args.threads} | Delay: {args.delay}s\n"
        )

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
