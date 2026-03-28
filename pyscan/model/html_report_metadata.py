from dataclasses import dataclass
from datetime import datetime


@dataclass(slots=True)
class HTMLReportMetadata:
    """
    Metadados do scan exibidos no relatorio HTML.
    """

    target: str
    mode: str
    threads: int
    timeout: float
    start_time: datetime
    duration: float

    def formatted_start_time(self) -> str:
        """Retorna data formatada para exibir no relatorio HTML"""
        return self.start_time.strftime("")

    def formatted_duration(self) -> str:
        """Retorna duracao formatada."""
        return f"{self.duration:.2f}s"
