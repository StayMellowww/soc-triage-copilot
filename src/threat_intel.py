"""Look up sanitized IOCs using VirusTotal v3 and AbuseIPDB v2."""

import base64
import ipaddress
import os
from urllib.parse import urlsplit

from .sanitizer import REDACTED

VIRUSTOTAL = "https://www.virustotal.com/api/v3"
ABUSEIPDB = "https://api.abuseipdb.com/api/v2/check"
LOOKUP_LIMIT = 4  # Per provider, per alert.
PROVIDERS = {"urls": ("URL", "VirusTotal"), "ipv4": ("IPv4", "AbuseIPDB"), "sha256": ("SHA-256", "VirusTotal")}
MOCK_IPS = {"198.51.100.27": 68, "203.0.113.45": 89}
MOCK_URL = "https://signin-review.example/session"
MOCK_HASH = "0123456789abcdef" * 4


def _is_public_address(address):
    return address.is_global and not address.is_multicast and not address.is_reserved


def _public_url(url):
    parts = urlsplit(url)
    if parts.username is not None or parts.password is not None:
        return False
    host = (parts.hostname or "").rstrip(".")
    try:
        return _is_public_address(ipaddress.ip_address(host))
    except ValueError:
        return "." in host and not host.endswith((".localhost", ".local", ".internal", ".test", ".example", ".invalid"))


def _mock_payload(kind, indicator):
    if kind == "ipv4":
        score = MOCK_IPS.get(indicator)
        if score is None:
            return None
        return {"data": {"ipAddress": indicator, "abuseConfidenceScore": score, "totalReports": score // 3}}
    if indicator not in {MOCK_URL, MOCK_HASH}:
        return None
    malicious = 12 if kind == "urls" else 7
    return {"data": {"type": "url" if kind == "urls" else "file", "attributes": {
        "last_analysis_stats": {"malicious": malicious, "suspicious": 2, "harmless": 54, "undetected": 11},
    }}}


def _score(kind, payload):
    data = payload["data"]
    if kind == "ipv4":
        confidence = int(data["abuseConfidenceScore"])
        reports = int(data["totalReports"])
        return f"Abuse confidence {confidence}/100 ({reports} reports)", confidence >= 75
    stats = data["attributes"]["last_analysis_stats"]
    malicious = int(stats["malicious"])
    suspicious = int(stats["suspicious"])
    return f"{malicious} malicious / {suspicious} suspicious engines", malicious >= 3


def _lookup(kind, indicator, api_key):
    import requests

    options = {"timeout": (3, 8), "allow_redirects": False}
    try:
        if kind == "ipv4":
            response = requests.get(ABUSEIPDB, params={"ipAddress": indicator, "maxAgeInDays": 90},
                                    headers={"Key": api_key, "Accept": "application/json"}, **options)
        else:
            resource = "files"
            if kind == "urls":
                resource = "urls"
                indicator = base64.urlsafe_b64encode(indicator.encode()).decode().rstrip("=")
            response = requests.get(f"{VIRUSTOTAL}/{resource}/{indicator}",
                                    headers={"x-apikey": api_key, "Accept": "application/json"}, **options)
        if response.status_code == 200:
            score, flagged = _score(kind, response.json())
            return "Found", score, flagged
        status = {404: "No record", 429: "Rate limited", 401: "Unauthorized", 403: "Forbidden"}
        return status.get(response.status_code, f"HTTP {response.status_code}"), "", False
    except requests.Timeout:
        return "Timed out", "", False
    except requests.RequestException:
        return "Request failed", "", False
    except (KeyError, TypeError, ValueError, OverflowError):
        return "Invalid response", "", False


def enrich_iocs(sanitized_iocs: dict, mode: str) -> list[dict]:
    """Return a row per sanitized IOC, including skipped or failed lookups."""
    keys = {"VirusTotal": os.getenv("VIRUSTOTAL_API_KEY", "").strip(),
            "AbuseIPDB": os.getenv("ABUSEIPDB_API_KEY", "").strip()} if mode == "live" else {}
    counts = dict.fromkeys(keys, 0)
    rate_limited = set()
    rows = []
    for kind, (label, provider) in PROVIDERS.items():
        for indicator in sanitized_iocs[kind]:
            status, score, flagged = "", "", False
            outcome = "Skipped"
            if REDACTED in indicator:
                status = "Redacted"
            elif mode == "local":
                status = "Local mode"
            elif mode == "mock":
                payload = _mock_payload(kind, indicator)
                status = "Mock result" if payload else "No mock record"
                outcome = "Simulated"
                if payload:
                    score, flagged = _score(kind, payload)
            elif kind == "ipv4" and not _is_public_address(ipaddress.IPv4Address(indicator)):
                status = "Non-public IP"
            elif kind == "urls" and not _public_url(indicator):
                status = "URL ineligible"
            elif not keys[provider]:
                status = "API key missing"
            elif provider in rate_limited:
                status = "Rate limited"
            elif counts[provider] >= LOOKUP_LIMIT:
                status = "Lookup limit reached"
            else:
                counts[provider] += 1
                status, score, flagged = _lookup(kind, indicator, keys[provider])
                outcome = {"Found": "Checked", "No record": "No record"}.get(status, "Failed")
                if status == "Rate limited":
                    rate_limited.add(provider)
            rows.append({"type": label, "indicator": indicator, "provider": provider,
                         "outcome": outcome, "status": status, "score": score, "flagged": flagged})
    return rows
