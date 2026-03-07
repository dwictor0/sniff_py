from dataclasses import dataclass
from typing import List
from .html_report_host import HTMLReportHost
from .html_report_metadata  import HTMLReportMetadata

@dataclass(slots=True)
class HTMLReport:
    """Representa o relatorio completo
    """
    metadata: HTMLReportMetadata
    hosts: List[HTMLReportHost]