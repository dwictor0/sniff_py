from unittest.mock import patch, MagicMock
from pyscan.core.services_fingerprinting import ServiceDetector


def test_detect_service_open_ssh():
    detector = ServiceDetector(timeout=1)

    with patch("socket.socket") as mock_socket_class:
        mock_sock_instance = MagicMock()
        mock_sock_instance.connect.return_value = None
        mock_sock_instance.recv.return_value = b"SSH-2.0-OpenSSH_8.2"

        mock_socket_class.return_value.__enter__.return_value = mock_sock_instance

        result = detector.detect_service("127.0.0.1", 22)

        assert result["status"] == "OPEN"
        assert "SSH" in result["banner"]


def test_detect_service_closed():
    detector = ServiceDetector(timeout=1)

    with patch("socket.socket") as mock_socket_class:
        mock_instance = MagicMock()
        mock_instance.connect.side_effect = ConnectionRefusedError

        mock_socket_class.return_value.__enter__.return_value = mock_instance

        result = detector.detect_service("127.0.0.1", 22)
        assert result["status"] == "CLOSED"


def test_detect_service_fallback_port():
    detector = ServiceDetector(timeout=1)

    with patch("socket.socket") as mock_socket_class:
        mock_sock_instance = MagicMock()
        mock_sock_instance.connect.return_value = None
        mock_sock_instance.recv.return_value = b""
        mock_socket_class.return_value.__enter__.return_value = mock_sock_instance
        result = detector.detect_service("127.0.0.1", 80)
        assert result["status"] == "OPEN"
        assert result["service"] == "HTTP"
