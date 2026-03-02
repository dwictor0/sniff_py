import re
from typing import Optional, Tuple


class VersionDetector:
    SERVICE_REGEX = {
        "SSH": re.compile(r"(OpenSSH)[_/ ]?([\d\.p]+)?", re.IGNORECASE),
        "HTTP": re.compile(r"(Apache)[/ ]?([\d\.]+)?", re.IGNORECASE),
        "FTP": re.compile(r"(vsFTPd)[/ ]?([\d\.]+)?", re.IGNORECASE),
        "NGINX": re.compile(r"(nginx)[/ ]?([\d\.]+)?", re.IGNORECASE),
        "IIS": re.compile(r"(Microsoft-IIS)[/ ]?([\d\.]+)?", re.IGNORECASE),
    }

    @classmethod
    def detect(cls, banner: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
        """
        Detecta serviço e versão a partir do banner.
        Retorna (service, version).
        """

        try:
            if not banner:
                return None, None

            # Garante que é string
            if isinstance(banner, bytes):
                banner = banner.decode(errors="ignore")

            for pattern in cls.SERVICE_REGEX.values():
                match = pattern.search(banner)
                if match:
                    service = match.group(1)
                    version = None

                    try:
                        version = match.group(2)
                    except IndexError:
                        version = None

                    return service, version

            return None, None

        except Exception:
            return None, None
