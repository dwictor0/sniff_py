from unittest.mock import patch, MagicMock
from pyscan.core.port_scanner import PortScanner


def test_connect_scan_open():
    scanner = PortScanner(timeout=1)

    with patch("socket.socket") as mock_socket:
        instance = MagicMock()
        instance.connect_ex.return_value = 0
        mock_socket.return_value = instance

        result = scanner._connect_scan("127.0.0.1", 80)

        assert result.state == "OPEN"


def test_connect_scan_closed():
    scanner = PortScanner(timeout=1)

    with patch("socket.socket") as mock_socket:
        instance = MagicMock()
        instance.connect_ex.return_value = 1
        mock_socket.return_value = instance

        result = scanner._connect_scan("127.0.0.1", 80)

        assert result.state == "CLOSED"
