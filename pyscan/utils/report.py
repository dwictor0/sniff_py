from datetime import datetime
from typing import Union
from pyscan.model.scan_result import HostDiscoveryResult, ScanResult
from pyscan.model.html_report_metadata import HTMLReportMetadata
from pyscan.model.html_report_host import HTMLReportHost
from pyscan.model.html_report_port import HTMLReportPort
from pyscan.core.html_response import HTMLReportGenerator


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


def export_html_report(
    results: Union[ScanResult, HostDiscoveryResult],
    start_time: datetime,
    target: str,
    mode: str,
    threads: int,
    timeout: float,
):
    """
    Exporta os resultados para um arquivo HTML utilizando templates.
    """
    metadata = HTMLReportMetadata(
        target=target,
        mode=mode.upper() if mode else "CUSTOM",
        threads=threads,
        timeout=timeout,
        start_time=start_time,
        duration=results.duration,
    )

    html_hosts = []

    if isinstance(results, ScanResult):
        host = HTMLReportHost(address=results.host)
        for r in results.results:
            port = HTMLReportPort(
                port=r.port,
                protocol=r.protocol,
                state=r.state,
                service=r.service,
                version=r.version,
            )
            host.add_port(port)
        html_hosts.append(host)

    elif isinstance(results, HostDiscoveryResult):
        for r in results.results:
            latency = (
                f"{r.latency:.2f} ms" if isinstance(r.latency, (int, float)) else None
            )
            host = HTMLReportHost(
                address=r.host,
                status=r.status,
                latency=latency,
                mac=r.mac,
            )
            html_hosts.append(host)
    else:
        raise TypeError("Tipo de resultado não suportado para HTML.")

    generator = HTMLReportGenerator(metadata=metadata, hosts=html_hosts)
    generator.save("report.html")
