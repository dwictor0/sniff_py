from dataclasses import dataclass
from typing import List, Optional

from .port_result import PortResult


@dataclass
class HostResult:
    host: str
    status: str
    latency: Optional[float] = None
    mac: Optional[str] = None

    def __post_init__(self):
        if not isinstance(self.host, str) or not self.host.strip():
            raise ValueError("O host deve ser uma string não vazia.")

        if not isinstance(self.status, str) or not self.status.strip():
            raise ValueError("O status deve ser uma string não vazia.")

        allowed_status = {"UP", "DOWN", "FILTERED", "ERROR"}
        if self.status not in allowed_status:
            raise ValueError(
                f"Status inválido: {self.status}. "
                f"Use um dos valores: {sorted(allowed_status)}"
            )

        if self.latency is not None:
            if not isinstance(self.latency, (int, float)):
                raise ValueError("A latência deve ser numérica ou None.")
            if self.latency < 0:
                raise ValueError("A latência não pode ser negativa.")

        if self.mac is not None and not isinstance(self.mac, str):
            raise ValueError("O MAC deve ser uma string ou None.")


@dataclass
class ScanResult:
    """
    Representa o resultado de uma operação de varredura de portas.

    Atributos:
    host: Host de destino que foi varrido.
    resultados: Lista de objetos PortResult.
    duração: Tempo total de execução da varredura em segundos.
    """

    host: str
    results: List[PortResult]
    duration: float

    def __post_init__(self):
        if not isinstance(self.host, str) or not self.host.strip():
            raise ValueError("O host deve ser uma string não vazia.")

        if not isinstance(self.duration, (int, float)):
            raise ValueError("A duração deve ser um número.")

        if self.duration < 0:
            raise ValueError("A duração não pode ser negativa.")

        if not isinstance(self.results, list):
            raise ValueError("Os resultados devem ser uma lista de PortResult.")

        for item in self.results:
            if not isinstance(item, PortResult):
                raise ValueError(
                    "Todos os itens nos resultados devem ser instâncias de PortResult."
                )

    @property
    def open_ports(self) -> int:
        return sum(1 for r in self.results if r.state == "OPEN")


@dataclass
class HostDiscoveryResult:
    host: str
    results: List[HostResult]
    duration: float

    def __post_init__(self):
        if not isinstance(self.host, str) or not self.host.strip():
            raise ValueError("O host deve ser uma string não vazia.")

        if not isinstance(self.duration, (int, float)):
            raise ValueError("A duração deve ser um número.")

        if self.duration < 0:
            raise ValueError("A duração não pode ser negativa.")

        if not isinstance(self.results, list):
            raise ValueError("Os resultados devem ser uma lista de HostResult.")

        for item in self.results:
            if not isinstance(item, HostResult):
                raise ValueError(
                    "Todos os itens nos resultados devem ser instâncias de HostResult."
                )

    @property
    def active_hosts(self) -> int:
        return sum(1 for r in self.results if r.status == "UP")
