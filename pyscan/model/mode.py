from dataclasses import dataclass


@dataclass
class ModeConfig:
    """
    Representa um modo de execução predefinido do scanner.

    Attributes:
        name (str): Nome do modo (FAST, FULL, STEALTH)
        ports (str): Range de portas (ex: "top 100", "1-65535")
        timeout (float): Timeout padrão do modo
        threads (int): Número de threads
        delay (float): Delay entre probes
    """

    name: str
    ports: str
    timeout: float
    threads: int
    delay: float

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


# Modos centralizados
MODES = {
    "fast": ModeConfig(
        name="FAST",
        ports="top 100",
        timeout=1.0,
        threads=50,
        delay=0,
    ),
    "full": ModeConfig(
        name="FULL",
        ports="1-65535",
        timeout=1.5,
        threads=200,
        delay=0,
    ),
    "stealth": ModeConfig(
        name="STEALTH",
        ports="top 100",
        timeout=2.0,
        threads=20,
        delay=0.5,
    ),
}
