from pyscan.model.scan_result import HostDiscoveryResult, ScanResult


def print_console(results):
    """
    Exibe o resultado formatado no console.
    """

    # =========================
    # PORT SCAN
    # =========================
    if isinstance(results, ScanResult):
        print(f"{'PORT':<8}{'STATE':<10}{'SERVICE':<15}{'VERSION':<20}")

        for r in results.results:
            print(
                f"{f'{r.port}/tcp':<8}"
                f"{r.state:<10}"
                f"{(r.service or 'Unknown'):<15}"
                f"{(r.version or 'Unknown'):<20}"
            )

        print(
            f"\nScanned {results.host} "
            f"in {results.duration:.2f}s. "
            f"Open ports: {results.open_ports}"
        )
        return

    # =========================
    # HOST DISCOVERY
    # =========================
    if isinstance(results, HostDiscoveryResult):
        up_hosts = [r for r in results.results if r.status == "UP"]

        print("\nHost discovery results:\n")
        print(f"{'HOST':<16}{'STATUS':<12}{'LATENCY':<15}{'MAC':<20}")

        for r in up_hosts:
            latency = (
                f"{r.latency:.2f} ms"
                if isinstance(r.latency, (int, float))
                else "Timeout"
            )
            mac = r.mac or "-"

            print(f"{r.host:<16}" f"{r.status:<12}" f"{latency:<15}" f"{mac:<20}")

        print(
            f"\nScan done: {len(results.results)} hosts scanned "
            f"in {results.duration:.2f}s"
        )
        print(f"Active hosts: {results.active_hosts}")
        return

    raise TypeError("Tipo de resultado não suportado em print_console.")
