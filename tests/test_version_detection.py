from pyscan.core.version_detector import VersionDetector
from pyscan.core.models import ServiceVersion


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
    result = ServiceVersion(
        port=22,
        protocol="tcp",
        state="OPEN",
        service="OpenSSH",
        version="7.4",
    )

    output = result.format_output()
    assert "22/tcp" in output
    assert "OpenSSH" in output
    assert "7.4" in output
