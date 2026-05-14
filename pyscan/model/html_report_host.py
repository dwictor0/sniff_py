from dataclasses import dataclass, field
from typing import List, Optional
from .html_report_port import HTMLReportPort


@dataclass(slots=True)
class HTMLReportHost:
    """
    Model representando os host escaneado no relatorio
    """

    address: str
    ports: List[HTMLReportPort] = field(default_factory=list)
    status: Optional[str] = None
    latency: Optional[str] = None
    mac: Optional[str] = None

    def add_port(self, port: HTMLReportPort) -> None:
        """Adiciona uma porta ao host.

        Args:
            port (HTMLReportPort): _description_
        """
        self.ports.append(port)
