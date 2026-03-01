import pytest
from pyscan.core.port_scanner import PortScanner


@pytest.fixture
def scanner():
    return PortScanner()


def test_single_port(scanner):
    assert scanner.parse_ports("80") == [80]


def test_range_ports(scanner):
    assert scanner.parse_ports("1-3") == [1, 2, 3]


def test_top_ports(scanner):
    ports = scanner.parse_ports("top 3")
    assert len(ports) == 3
