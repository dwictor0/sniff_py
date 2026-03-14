from unittest.mock import patch, MagicMock
from pyscan.core.port_scanner import PortScanner


def test_connect_scan_open():
    scanner = PortScanner(timeout=1)
    with patch("socket.socket") as mock_socket:
        instance = MagicMock()
        instance.connect_ex.return_value = 0
        instance.recv.return_value = b"OpenSSH_8.9p1"
        mock_socket.return_value.__enter__.return_value = instance

        result = scanner._connect_scan("127.0.0.1", 22)

        assert result.state == "CLOSED"


def test_connect_scan_closed():
    scanner = PortScanner(timeout=1)
    with patch("socket.socket") as mock_socket:
        instance = MagicMock()
        instance.connect_ex.return_value = 1
        instance.recv.return_value = b""
        mock_socket.return_value.__enter__.return_value = instance

        result = scanner._connect_scan("127.0.0.1", 22)

        assert result.state == "CLOSED"


def test_syn_scan_open(monkeypatch):
    scanner = PortScanner(scan_type="syn")

    class MockResp:
        def __getitem__(self, key):
            class TCP:
                flags = 0x12

            return TCP()

        def haslayer(self, layer):
            return True

    monkeypatch.setattr(
        "pyscan.core.port_scanner.sr1", lambda pkt, timeout, verbose: MockResp()
    )
    monkeypatch.setattr("pyscan.core.port_scanner.send", lambda pkt, verbose: None)

    result = scanner._syn_scan("127.0.0.1", 80)
    assert result.state == "OPEN"


def test_syn_scan_closed(monkeypatch):
    scanner = PortScanner(scan_type="syn")

    class MockResp:
        def __getitem__(self, key):
            class TCP:
                flags = 0x14

            return TCP()

        def haslayer(self, layer):
            return True

    monkeypatch.setattr(
        "pyscan.core.port_scanner.sr1", lambda pkt, timeout, verbose: MockResp()
    )

    result = scanner._syn_scan("127.0.0.1", 80)
    assert result.state == "CLOSED"
