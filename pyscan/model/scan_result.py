from dataclasses import dataclass
from typing import List
from .port_result import PortResult


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
        """
        Retorna o número de portas abertas encontradas durante a varredura.
        """
        return sum(1 for r in self.results if r.state == "OPEN")
