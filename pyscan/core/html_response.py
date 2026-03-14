from typing import List
from model.html_report_host import HTMLReportHost
from model.html_report_metadata import HTMLReportMetadata
from jinja2 import Environment, FileSystemLoader, select_autoescape
import html


class HTMLReportGenerator:
    """Classe para gerar relatório HTML usando template com a lib Jinja2"""

    def __init__(self, metadata: HTMLReportMetadata, hosts: List[HTMLReportHost]):
        self.metadata = metadata
        self.hosts = hosts

        self._sanitize_hosts()

        self.env = Environment(
            loader=FileSystemLoader("pyscan/templates"),
            autoescape=select_autoescape(["html", "xml"]),
        )
        self.template = self.env.get_template("report_template.html")

    def _sanitize_hosts(self):
        """Sanitiza strings de hosts e portas"""
        for host in self.hosts:
            host.address = self.sanitize(host.address)
            for port in host.ports:
                port.protocol = self.sanitize(port.protocol)
                port.state = self.sanitize(port.state)
                port.service = self.sanitize(port.service)
                port.version = self.sanitize(port.version)

    @staticmethod
    def sanitize(value: str) -> str:
        """Converte caracteres especiais em entidades HTML"""
        if not value:
            return "-"
        return html.escape(str(value))

    def generate(self) -> str:
        """Gera o HTML completo usando template"""
        try:
            html_content = self.template.render(
                metadata=self.metadata, hosts=self.hosts
            )
            return html_content
        except Exception as e:
            print(f"[ERROR] Falha ao gerar HTML: {e}")
            raise

    def save(self, path: str = "report.html"):
        """Salva o HTML gerado em arquivo"""
        try:
            html_content = self.generate()
            with open(path, "w", encoding="utf-8") as f:
                f.write(html_content)
            print(f"[INFO] Relatório HTML gerado em: {path}")
        except Exception as e:
            print(f"[ERROR] Falha ao salvar arquivo HTML: {e}")
            raise
