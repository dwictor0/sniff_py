from dataclasses import dataclass
from typing import Optional

VALID_STATES = {"OPEN", "CLOSED", "FILTERED", "SCAPY_NOT_INSTALLED"}
VALID_PROTOCOLS = {"tcp", "udp"}


@dataclass
class PortResult:
    port: int
    protocol: str
    state: str
    service: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None

    def __post_init__(self):
        if not isinstance(self.port, int) or self.port < 0 or self.port > 65535:
            raise ValueError("Invalid port number")

        if not self.protocol or self.protocol.lower() not in VALID_PROTOCOLS:
            raise ValueError("Invalid protocol")

        if not self.state or self.state not in VALID_STATES:
            raise ValueError("Invalid state")

    def __str__(self) -> str:
        """
        Returns a formatted string representation similar to Nmap output.
        """
        service_part = self.service or "-"
        version_part = f" {self.version}" if self.version else ""

        return (
            f"{self.port}/{self.protocol}  "
            f"{self.state:<10}  "
            f"{service_part}{version_part}"
        )