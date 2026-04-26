from pyscan.core.config import ScanConfig


def test_config_dict():
    config = ScanConfig(timeout=0.5, threads=200, delay=0.1)

    data = config.to_dict()

    assert data["timeout"] == 0.5
    assert data["threads"] == 200
    assert data["delay"] == 0.1
