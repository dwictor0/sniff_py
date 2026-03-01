from pyscan.core.port_scanner import PortResult, ScanResult


def test_open_ports_count():
    results = [
        PortResult(22, "tcp", "OPEN"),
        PortResult(80, "tcp", "OPEN"),
        PortResult(443, "tcp", "CLOSED"),
    ]

    scan = ScanResult("127.0.0.1", results, 1.23)

    assert scan.open_ports == 2
