from dataclasses import dataclass
from typing import Dict


@dataclass(frozen=True)
class ModeConfig:
    """
    Representa um modo de execução do scanner.

    Attributes:
        name (str): Nome do modo (FAST, FULL, STEALTH)
        ports (str): Range de portas (ex: "top 100", "1-65535")
        timeout (float): Timeout por operação
        threads (int): Número de threads
        delay (float): Intervalo entre probes
    """

    name: str
    ports: str
    timeout: float
    threads: int
    delay: float

    def to_dict(self) -> dict:
        """
        Converte o modo para dicionário.
        """
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
            f"{self.ports} | "
            f"Timeout: {self.timeout}s | "
            f"Threads: {self.threads} | "
            f"Delay: {self.delay}s"
        )


# =========================
# MODOS PADRÃO
# =========================
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


# =========================
# HELPERS (melhora muito o código)
# =========================
def get_mode(name: str) -> ModeConfig:
    """
    Retorna um modo pelo nome.

    Args:
        name (str): Nome do modo (fast, full, stealth)

    Returns:
        ModeConfig

    Raises:
        ValueError: Se o modo não existir
    """
    try:
        return MODES[name.lower()]
    except KeyError:
        raise ValueError(f"Modo inválido: {name}")


def list_modes() -> list:
    """
    Retorna lista de modos disponíveis.
    """
    return list(MODES.keys())
