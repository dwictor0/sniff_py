from pyscan.core.version_detector import VersionDetector
from pyscan.model.port_result import PortResult


def test_detect_ssh():
    banner = "SSH-2.0-OpenSSH_7.4"
    service, version = VersionDetector.detect(banner)

    assert service == "OpenSSH"
    assert version == "7.4"


def test_detect_http():
    banner = "Server: Apache/2.4.41 (Ubuntu)"
    service, version = VersionDetector.detect(banner)

    assert service == "Apache"
    assert version == "2.4.41"


def test_banner_none():
    service, version = VersionDetector.detect(None)

    assert service is None
    assert version is None


def test_banner_bytes():
    banner = b"SSH-2.0-OpenSSH_8.2"
    service, version = VersionDetector.detect(banner)

    assert service == "OpenSSH"
    assert version == "8.2"


def test_format_output():
    result = PortResult(
        port=22,
        protocol="tcp",
        state="OPEN",
        service="OpenSSH",
        version="7.4",
    )

    output = str(result)

    assert "22/tcp" in output
    assert "OpenSSH" in output
    assert "7.4" in output


def test_detect_service_closed():
    detector = ServiceDetector(timeout=1)

    with patch("socket.socket") as mock_socket:
        instance = MagicMock()
        instance.connect.side_effect = ConnectionRefusedError
        mock_socket.return_value.__enter__.return_value = instance

        result = detector.detect_service("127.0.0.1", 22)

        assert result["status"] == "CLOSED"


def test_detect_service_open():
    detector = ServiceDetector(timeout=1)

    with patch("socket.socket") as mock_socket:
        instance = MagicMock()
        instance.connect.return_value = None
        instance.recv.return_value = b"SSH-2.0-OpenSSH_7.4"
        mock_socket.return_value.__enter__.return_value = instance

        result = detector.detect_service("127.0.0.1", 22)

        assert result["status"] == "OPEN"
        assert result["service"] == "SSH"
        assert "SSH" in result["banner"]
