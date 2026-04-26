from pyscan.model.mode import MODES


def test_fast_mode():
    mode = MODES["fast"]

    assert mode.ports == "top 100"
    assert mode.timeout == 1.0
    assert mode.threads == 50
    assert mode.delay == 0


def test_mode_description():
    mode = MODES["fast"]

    desc = mode.describe()

    assert "Timeout" in desc
    assert "Threads" in desc
