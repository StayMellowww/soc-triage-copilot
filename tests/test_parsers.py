import json
from email.message import EmailMessage

import pytest

from app import DATA
from src.parsers import AlertParseError, parse_alert
from src.sanitizer import REDACTED, sanitize_alert


def test_extracts_email_headers_and_iocs():
    path = DATA / "sample_phishing.eml"
    alert = parse_alert(path, path.read_bytes())
    assert alert["source"] == "email"
    assert alert["evidence"]["sender"] == "notices@signin-review.example"
    assert alert["evidence"]["reply_to"] == "help@review-queue.example"
    assert "softfail" in alert["evidence"]["spf"][0]
    assert "dkim=fail" in alert["evidence"]["dkim"][0]
    assert alert["iocs"]["urls"] == ["https://signin-review.example/session"]
    assert alert["iocs"]["ipv4"] == ["198.51.100.27", "10.42.5.10"]


def test_multipart_decoding_and_html_entities_without_attachment_iocs():
    message = EmailMessage()
    message["From"] = "sender@example.test"
    message["DKIM-Signature"] = "v=1; d=example.test; s=demo; b=fictional"
    message.set_content("(https://report.example/hello). 999.1.2.3", cte="base64")
    message.add_alternative('<a href="https://report.example/?a=1&amp;b=2">report</a> 192.0.2.1', subtype="html")
    message.add_attachment("https://attachment.example/ignore", filename="attachment.txt")
    alert = parse_alert("message.EML", message.as_bytes())
    assert alert["iocs"]["urls"] == ["https://report.example/hello", "https://report.example/?a=1&b=2"]
    assert alert["iocs"]["ipv4"] == ["192.0.2.1"]
    assert alert["evidence"]["dkim_signatures"] == ["v=1; d=example.test; s=demo; b=fictional"]


def test_extracts_sysmon_command_lines_and_normalizes_duplicate_hashes():
    path = DATA / "sample_sysmon.json"
    data = json.loads(path.read_bytes())
    data["EventData"]["Hashes"] += ",SHA256=" + ("0123456789ABCDEF" * 4)
    alert = parse_alert(path, json.dumps(data).encode())
    assert alert["evidence"]["events"][0]["EventID"] == 1
    assert "-EncodedCommand" in alert["evidence"]["command_lines"][0]
    assert alert["iocs"]["sha256"] == ["0123456789abcdef" * 4]


def test_sysmon_named_event_data_and_winlog_fields():
    events = [{"Event": {"System": {"EventID": {"#text": "3"}},
                         "EventData": {"Data": [{"@Name": "DestinationIp", "#text": "203.0.113.45"}]}}},
              {"winlog": {"event_id": "1", "event_data": {"ParentCommandLine": "viewer.exe"}}}]
    alert = parse_alert("export.json", json.dumps(events).encode())
    assert alert["evidence"]["command_lines"] == ["viewer.exe"]
    assert [event["EventID"] for event in alert["evidence"]["events"]] == ["3", "1"]
    assert alert["iocs"]["ipv4"] == ["203.0.113.45"]


def test_recursive_redaction_preserves_public_iocs_and_input():
    command = r'"C:\Users\Pat Example\tool.exe" http://10.0.0.1 http://demo:secret@example.org/a 172.16.0.1 172.32.0.1 192.168.0.1 https://example.org/%31%30.1.2.3'
    raw = json.dumps({"CommandLine": command}).encode()
    original = parse_alert("event.json", raw)
    sanitized = sanitize_alert(original)
    assert original["evidence"]["command_lines"] == [command]
    assert sanitized["iocs"]["ipv4"] == [REDACTED, "172.32.0.1"]
    output = json.dumps(sanitized)
    for private in ("Pat Example", "demo:secret", "10.0.0.1", "172.16.0.1", "192.168.0.1", "%31%30.1.2.3"):
        assert private not in output


@pytest.mark.parametrize("filename, raw", [
    ("alert.json", b"invalid"), ("alert.json", b'{"events": []}'),
    ("alert.json", b'[{"unrecognized": 1}]'), ("alert.eml", b"arbitrary text"),
    ("alert.txt", b"different extension"), ("alert.eml", b""),
])
def test_rejects_unsupported_or_malformed_inputs(filename, raw):
    with pytest.raises(AlertParseError):
        parse_alert(filename, raw)
