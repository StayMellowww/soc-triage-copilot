"""Redact private IPv4 addresses and Windows profile names from normalized alerts."""

import ipaddress
import re
from urllib.parse import unquote

from .parsers import IPV4_PATTERN

REDACTED = "[REDACTED]"
PRIVATE_NETWORKS = tuple(ipaddress.IPv4Network(cidr) for cidr in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
))
PROFILE_PATH = re.compile(
    r"(?P<prefix>[a-z]:[\\/]users[\\/])(?P<user>[^\\/\r\n\"'<>|:]+)", re.IGNORECASE
)
URL_USERINFO = re.compile(r"(https?://)[^\s/@?#<>\"']+@", re.I)


def _replace_ip(match):
    try:
        address = ipaddress.IPv4Address(match.group())
    except ipaddress.AddressValueError:
        return match.group()
    return REDACTED if any(address in network for network in PRIVATE_NETWORKS) else match.group()


def redact_text(text: str) -> str:
    text = IPV4_PATTERN.sub(_replace_ip, text)
    text = URL_USERINFO.sub(r"\g<1>[REDACTED]@", text)
    return PROFILE_PATH.sub(lambda match: match["prefix"] + REDACTED, text)


def _sanitize(value):
    if isinstance(value, str):
        redacted = redact_text(value)
        decoded = unquote(redacted)
        if decoded != redacted and redact_text(decoded) != decoded:
            return REDACTED
        return redacted
    if isinstance(value, list):
        return [_sanitize(item) for item in value]
    if isinstance(value, dict):
        return {key: _sanitize(item) for key, item in value.items()}
    return value


def sanitize_alert(alert: dict) -> dict:
    sanitized = _sanitize(alert)
    sanitized["iocs"] = {kind: list(dict.fromkeys(values)) for kind, values in sanitized["iocs"].items()}
    return sanitized
