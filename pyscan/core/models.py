from dataclasses import dataclass
from typing import Optional


@dataclass
class ServiceVersion:
    port: int
    protocol: str
    state: str
    service: Optional[str]
    version: Optional[str]

    def format_output(self) -> str:
        try:
            service_display = self.service or "UNKNOWN"
            version_display = f" {self.version}" if self.version else ""
            return f"{self.port}/{self.protocol}  {self.state:<5}  {service_display}{version_display}"
        except Exception:
            return f"{self.port}/{self.protocol}  {self.state:<5}  UNKNOWN"
