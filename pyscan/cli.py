import argparse
import time

from pyscan.core.port_scanner import PortScanner
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
        description="PyScan - TCP Port Scanner",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    parser.add_argument("target", help="Host alvo")

    parser.add_argument(
        "--mode",
        choices=["fast", "full", "stealth"],
        help="Modo de execução predefinido",
    )

    parser.add_argument(
        "-p",
        "--ports",
        help='Porta específica (80), range (1-100) ou top N ("top 10")',
    )

    parser.add_argument(
        "--scan-type",
        choices=["connect", "syn"],
        default="connect",
    )

    parser.add_argument(
        "-t",
        "--threads",
        type=lambda x: validate_positive(int(x), "Threads"),
        default=100,
    )

    parser.add_argument(
        "--timeout",
        type=lambda x: validate_positive(float(x), "Timeout"),
        default=1.0,
    )

    parser.add_argument(
        "--delay",
        type=lambda x: validate_non_negative(float(x), "Delay"),
        default=0,
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

    start_time = time.time()

    ports = scanner.parse_ports(args.ports)
    result = scanner.scan(args.target, ports)

    print_console(result)

    end_time = time.time()

    print(f"\nScan finalizado em {end_time - start_time:.2f}s")


if __name__ == "__main__":
    main()
