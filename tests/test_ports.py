import time
from pyscan.core.port_scanner import PortScanner
from pyscan.model.port_result import PortResult
from pyscan.model.scan_result import ScanResult


def test_open_ports_count():
    results = [
        PortResult(22, "tcp", "OPEN"),
        PortResult(80, "tcp", "OPEN"),
        PortResult(443, "tcp", "CLOSED"),
    ]

    scan = ScanResult("127.0.0.1", results, 1.23)

    assert scan.open_ports == 2


def test_parse_single_port():
    scanner = PortScanner()
    ports = scanner.parse_ports("80")

    assert ports == [80]


def test_parse_range_ports():
    scanner = PortScanner()
    ports = scanner.parse_ports("20-23")

    assert ports == [20, 21, 22, 23]


def test_parse_top_ports():
    scanner = PortScanner()
    ports = scanner.parse_ports("top 3")

    assert ports == [21, 22, 23]


def test_delay_configuration():
    scanner = PortScanner(delay=0.2)

    start = time.time()
    scanner._connect_scan("127.0.0.1", 1)
    duration = time.time() - start

    assert duration >= 0.2


def test_scan_returns_result():
    scanner = PortScanner(threads=10, timeout=0.5)

    result = scanner.scan("127.0.0.1", [80, 22])

    assert result.host == "127.0.0.1"
    assert len(result.results) == 2


def test_scan_result_structure():
    scanner = PortScanner()

    result = scanner.scan("127.0.0.1", [80])

    port_result = result.results[0]

    assert hasattr(port_result, "port")
    assert hasattr(port_result, "state")
    assert hasattr(port_result, "protocol")
