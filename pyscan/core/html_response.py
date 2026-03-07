from typing import List
from model.html_report_host import HTMLReportHost
from model.html_report_metadata import HTMLReportMetadata


class HTMLReportGenerator:
    """Classe para gerar relatório HTML"""

    def __init__(self, metadata: HTMLReportMetadata, hosts: List[HTMLReportHost]):
        try:
            self.metadata = metadata
            self.hosts = hosts
        except Exception as e:
            print(f"[ERROR] Falha ao inicializar HTMLReportGenerator: {e}")
            raise

    def generate(self) -> str:
        """Gera o HTML completo"""
        try:
            html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Scan Report</title>
<style>
body {{
    font-family: "Courier New", Courier, monospace;
    background: #ffffff;
    color: #000000;
    margin: 0;
    padding: 20px;
}}
h1 {{
    text-align: center;
    font-size: 24px;
    margin-bottom: 20px;
}}
h2 {{
    font-size: 20px;
    border-bottom: 1px solid #000;
    padding-bottom: 4px;
}}
h3 {{
    font-size: 16px;
    margin-top: 15px;
}}
.meta, .host {{
    margin-bottom: 20px;
}}
table {{
    width: 100%;
    border-collapse: collapse;
    margin-top: 10px;
}}
th, td {{
    padding: 6px 8px;
    border: 1px solid #000;
    font-size: 14px;
}}
th {{
    background-color: #e0e0e0;
}}
.open {{
    color: green;
    font-weight: bold;
}}
.closed {{
    color: red;
    font-weight: bold;
}}
.filtered {{
    color: orange;
    font-weight: bold;
}}
</style>
</head>
<body>

<h1>Scanner</h1>

{self._generate_metadata_section()}
{self._generate_hosts_section()}

</body>
</html>
"""
            return html
        except Exception as e:
            print(f"[ERROR] Falha ao gerar HTML: {e}")
            raise

    def _generate_metadata_section(self) -> str:
        """Gera a seção de metadados"""
        try:
            return f"""
<div class="meta">
<h2>Scan Metadata</h2>
<p><b>Target:</b> {self.metadata.target}</p>
<p><b>Mode:</b> {self.metadata.mode}</p>
<p><b>Threads:</b> {self.metadata.threads}</p>
<p><b>Timeout:</b> {self.metadata.timeout}</p>
<p><b>Start Time:</b> {self.metadata.start_time.strftime('%Y-%m-%d %H:%M:%S')}</p>
<p><b>Duration:</b> {self.metadata.duration:.2f}s</p>
</div>
"""
        except Exception as e:
            print(f"[ERROR] Falha ao gerar seção de metadados: {e}")
            raise

    def _generate_hosts_section(self) -> str:
        """Gera a seção de hosts com portas"""
        try:
            html = ""
            for host in self.hosts:
                html += f"""
<div class="host">
<h3>Host: {host.address}</h3>
<table>
<tr>
<th>Port</th>
<th>Protocol</th>
<th>State</th>
<th>Service</th>
<th>Version</th>
</tr>
"""
                for port in host.ports:
                    html += f"""
<tr>
<td>{port.port}</td>
<td>{port.protocol}</td>
<td class="{port.state.lower()}">{port.state}</td>
<td>{port.service or '-'}</td>
<td>{port.version or '-'}</td>
</tr>
"""
                html += "</table></div>"
            return html
        except Exception as e:
            print(f"[ERROR] Falha ao gerar seção de hosts: {e}")
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
