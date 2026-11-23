"""Normalize EML messages and Sysmon JSON into an alert with unique IOCs."""

import ipaddress
import json
import re
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit

MAX_BYTES = 2 * 1024 * 1024
URL_PATTERN = re.compile(r"https?://[^\s<>\"'`]+", re.IGNORECASE)
IPV4_PATTERN = re.compile(r"(?<![\d.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?!\d|\.[0-9])")
PERCENT_ESCAPE = re.compile(r"%[a-f0-9]{2}", re.IGNORECASE)
SHA256_PATTERN = re.compile(r"(?<![a-f0-9])[a-f0-9]{64}(?![a-f0-9])", re.IGNORECASE)


class AlertParseError(ValueError):
    """Input could not be parsed as a supported alert."""


class HTMLLinks(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
        self.text = []

    def handle_starttag(self, tag, attrs):
        self.links.extend(value for name, value in attrs if name in {"href", "src"} and value)

    def handle_data(self, data):
        self.text.append(data)


def _unique(values):
    return list(dict.fromkeys(values))


def _urls(text):
    for match in URL_PATTERN.finditer(text):
        url = match.group().rstrip(".,;!?")
        if len(url) > 8192:
            continue
        for opening, closing in (("(", ")"), ("[", "]"), ("{", "}")):
            excess = url.count(closing) - url.count(opening)
            trailing = len(url) - len(url.rstrip(closing))
            url = url[:len(url) - min(max(0, excess), trailing)]
        try:
            parts = urlsplit(url)
            if parts.hostname and (parts.port is None or 0 < parts.port <= 65535):
                yield url
        except ValueError:
            continue


def _iocs(fragments):
    urls, ipv4, sha256 = {}, {}, {}
    for text in fragments:
        urls.update(dict.fromkeys(_urls(text)))
        # URL escapes can masquerade as the first octet of a literal address.
        for match in IPV4_PATTERN.finditer(PERCENT_ESCAPE.sub(".", text)):
            try:
                ipv4[str(ipaddress.IPv4Address(match.group()))] = None
            except ipaddress.AddressValueError:
                continue
        sha256.update(dict.fromkeys(match.group().lower() for match in SHA256_PATTERN.finditer(text)))
    return {"urls": list(urls), "ipv4": list(ipv4), "sha256": list(sha256)}


def _message_text(part):
    if part.get_content_disposition() == "attachment" or part.get_content_maintype() == "message":
        return
    if part.is_multipart():
        for child in part.iter_parts():
            yield from _message_text(child)
        return
    if part.get_content_type() not in {"text/plain", "text/html"}:
        return
    payload = part.get_payload(decode=True) or b""
    try:
        body = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
    except (LookupError, UnicodeError):
        body = payload.decode("utf-8", errors="replace")
    if part.get_content_type() == "text/html":
        parser = HTMLLinks()
        parser.feed(body)
        yield from parser.links
        yield from parser.text
    else:
        yield body


def _email(raw):
    message = BytesParser(policy=policy.default).parsebytes(raw)
    if not list(message.keys()):
        raise AlertParseError("EML input must contain email headers.")

    def headers(name):
        return [str(value) for value in message.get_all(name, [])]

    def address(name):
        return next((address for _, address in getaddresses(headers(name)) if address), "")

    auth = headers("Authentication-Results") + headers("ARC-Authentication-Results")
    received_spf = headers("Received-SPF")
    dkim = headers("DKIM-Signature")
    evidence = {
        "subject": str(message.get("Subject", "")),
        "sender": address("From"),
        "reply_to": address("Reply-To"),
        "spf": received_spf + [value for value in auth if re.search(r"\bspf\s*=", value, re.I)],
        "dkim": [value for value in auth if re.search(r"\bdkim\s*=", value, re.I)],
        "dkim_signatures": dkim,
        "authentication_results": auth,
    }
    fragments = [str(value) for _, value in message.raw_items()]
    fragments.extend(_message_text(message))
    return {"source": "email", "evidence": evidence, "iocs": _iocs(fragments)}


FIELDS = (
    "EventID", "UtcTime", "Computer", "Image", "ParentImage", "CommandLine",
    "ParentCommandLine", "ProcessGuid", "SourceIp", "DestinationIp",
    "DestinationHostname", "DestinationPort", "Protocol", "Initiated", "Hashes",
    "QueryName", "QueryResults", "TargetFilename",
)


def _flatten_event(record):
    fields = {}
    for name, value in record.items():
        key = name.casefold().replace("_", "")
        if isinstance(value, (str, int, bool)):
            fields[key] = value
        if isinstance(value, dict):
            fields.update(_flatten_event(value))
            if key == "eventid" and isinstance(value.get("#text"), (str, int)):
                fields[key] = value["#text"]
        if key == "data" and isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    field_name = item.get("Name", item.get("@Name"))
                    field_value = item.get("Value", item.get("#text"))
                    if isinstance(field_name, str) and isinstance(field_value, (str, int, bool)):
                        fields[field_name.casefold()] = field_value

    return fields


def _event_fields(record):
    fields = _flatten_event(record)
    if "eventid" not in fields and "eventcode" in fields:
        fields["eventid"] = fields["eventcode"]
    return {name: fields[name.casefold()] for name in FIELDS if name.casefold() in fields}


def _sysmon(raw):
    try:
        document = json.loads(raw)
    except (ValueError, RecursionError) as exc:
        raise AlertParseError("Input is not readable Sysmon JSON.") from exc
    records = document.get("events", [document]) if isinstance(document, dict) else document
    if not isinstance(records, list) or not records or any(not isinstance(row, dict) for row in records):
        raise AlertParseError("Sysmon JSON must contain an event object or a nonempty list of event objects.")
    try:
        events = [_event_fields(record) for record in records]
    except RecursionError as exc:
        raise AlertParseError("The Sysmon export is nested too deeply.") from exc
    if any(not event for event in events):
        raise AlertParseError("Each Sysmon event must contain at least one recognized field.")
    commands = _unique(
        event[name] for event in events for name in ("CommandLine", "ParentCommandLine")
        if isinstance(event.get(name), str) and event[name]
    )
    return {
        "source": "sysmon",
        "evidence": {"events": events, "command_lines": commands},
        "iocs": _iocs(str(value) for event in events for value in event.values()),
    }


def parse_alert(filename: str | Path, raw: bytes) -> dict:
    """Parse uploaded bytes or file bytes using the filename extension."""
    if not raw or len(raw) > MAX_BYTES:
        raise AlertParseError("Provide a nonempty alert file of 2 MiB or less.")
    suffix = Path(filename).suffix.lower()
    if suffix == ".eml":
        try:
            return _email(raw)
        except RecursionError as exc:
            raise AlertParseError("The email MIME structure is nested too deeply.") from exc
    if suffix == ".json":
        return _sysmon(raw)
    raise AlertParseError("Use an .eml or .json alert file.")
