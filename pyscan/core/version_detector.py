import re
from typing import Optional, Tuple


class VersionDetector:
    SERVICE_REGEX = {
        "SSH": re.compile(r"(OpenSSH)[_/ ]?([\d\.p]+)?", re.IGNORECASE),
        "APACHE": re.compile(r"(Apache)[/ ]?([\d\.]+)?", re.IGNORECASE),
        "NGINX": re.compile(r"(nginx)[/ ]?([\d\.]+)?", re.IGNORECASE),
        "IIS": re.compile(r"(Microsoft-IIS)[/ ]?([\d\.]+)?", re.IGNORECASE),
        "FTP": re.compile(r"(vsFTPd)[/ ]?([\d\.]+)?", re.IGNORECASE),
        "GENERIC_HTTP": re.compile(r"HTTP/[\d\.]+", re.IGNORECASE),
    }

    @classmethod
    def detect(cls, banner: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
        if not banner:
            return None, None

        if isinstance(banner, bytes):
            banner = banner.decode(errors="ignore")

        for name, pattern in cls.SERVICE_REGEX.items():
            match = pattern.search(banner)
            if match:
                if name == "GENERIC_HTTP":
                    return "HTTP", None

                service = match.group(1)
                version = match.group(2) if len(match.groups()) > 1 else None
                return service, version

        return None, None
