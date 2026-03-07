from dataclasses import dataclass, field
from typing import List
from .html_report_port import HTMLReportPort

@dataclass(slots=True)
class HTMLReportHost:
    """
    Model representando os host escaneado no relatorio
    """
    address: str
    ports: List[HTMLReportPort] = field(default_factory=list)
    def add_port(self,port: HTMLReportPort) -> None:
        """Adiciona uma porta ao host.

        Args:
            port (HTMLReportPort): _description_
        """