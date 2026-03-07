from dataclasses import dataclass
from typing import Optional


@dataclass(slots=True)
class HTMLReportPort:
    """
    Model representando as port escaneado no relatorio
    """

    port: int
    protocol: str
    state: str
    service: Optional[str] = None
    version: Optional[str] = None

    def state_css_class(self) -> str:
        """
        Retorna a classe CSS baseada no estado da porta
        """
        return self.state.lower()
