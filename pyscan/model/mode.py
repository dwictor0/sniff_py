from dataclasses import dataclass
from typing import Dict
import re

TOP_PORTS_REGEX = re.compile(r"top \d+")
SINGLE_PORT_REGEX = re.compile(r"\d+")
RANGE_PORTS_REGEX = re.compile(r"\d+-\d+")


@dataclass(frozen=True)
class ModeConfig:
    """
    Representa um modo de execução do scanner.
    """

    name: str
    ports: str
    timeout: float
    threads: int
    delay: float

    def __post_init__(self) -> None:
        if not self._is_valid_ports(self.ports):
            raise ValueError(
                f"Valor inválido para ports: {self.ports}. "
                "Use formatos como 'top 100', '1-65535' ou '80'."
            )

        if self.timeout <= 0:
            raise ValueError("timeout deve ser maior que 0")

        if self.threads <= 0:
            raise ValueError("threads deve ser maior que 0")

        if self.delay < 0:
            raise ValueError("delay não pode ser negativo")

    @staticmethod
    def _is_valid_ports(value: str) -> bool:
        value = value.strip().lower()

        if TOP_PORTS_REGEX.fullmatch(value):
            return True

        if SINGLE_PORT_REGEX.fullmatch(value):
            port = int(value)
            return 1 <= port <= 65535

        if RANGE_PORTS_REGEX.fullmatch(value):
            start, end = map(int, value.split("-"))
            return 1 <= start <= end <= 65535

        return False

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "ports": self.ports,
            "timeout": self.timeout,
            "threads": self.threads,
            "delay": self.delay,
        }

    def describe(self) -> str:
        """
        Retorna descrição formatada do modo.
        """
        return (
            f"[{self.name}] "
            f"{self.ports} | "
            f"Timeout: {self.timeout}s | "
            f"Threads: {self.threads} | "
            f"Delay: {self.delay}s"
        )


MODES: Dict[str, ModeConfig] = {
    "fast": ModeConfig(
        name="FAST",
        ports="top 100",
        timeout=1.0,
        threads=50,
        delay=0.0,
    ),
    "full": ModeConfig(
        name="FULL",
        ports="1-65535",
        timeout=1.5,
        threads=200,
        delay=0.0,
    ),
    "stealth": ModeConfig(
        name="STEALTH",
        ports="top 100",
        timeout=2.0,
        threads=20,
        delay=0.5,
    ),
}


def get_mode(name: str) -> ModeConfig:
    try:
        return MODES[name.lower()]
    except KeyError as exc:
        raise ValueError(f"Modo inválido: {name}") from exc


def list_modes() -> list[str]:
    return list(MODES.keys())
