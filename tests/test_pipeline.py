import base64
import json
from types import SimpleNamespace
from unittest.mock import MagicMock

import openai
import pytest
import requests

from app import DATA, DEMO_ALERTS, main, triage
from src.threat_intel import ABUSEIPDB, VIRUSTOTAL, enrich_iocs
from src.ticket_generator import HEADINGS


def no_request(*args, **kwargs):
    pytest.fail("Offline mode attempted an external request")


def test_demo_is_offline_even_with_keys(monkeypatch, tmp_path):
    for name in ("OPENAI_API_KEY", "VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY"):
        monkeypatch.setenv(name, "unused-test-key")
    monkeypatch.setattr(requests, "get", no_request)
    monkeypatch.setattr(openai, "OpenAI", no_request)
    report = tmp_path / "demo.md"
    assert main(["--demo", "--output", str(report)]) == 0
    ticket = report.read_text(encoding="utf-8")
    assert ticket.count("simulated threat intelligence") == 3
    assert ticket.count("## Containment Checklist") == 3
    for label in DEMO_ALERTS:
        assert label in ticket
    for technique in ("T1566.002", "T1059.001", "T1071.001"):
        assert technique in ticket


def test_live_enrichment_withholds_non_public_indicators_and_handles_service_errors(monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "vt-test-key")
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "ip-test-key")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    lookup_url = "https://review.example.org/a?x=2"
    url_id = base64.urlsafe_b64encode(lookup_url.encode()).decode().rstrip("=")

    def response(url, **kwargs):
        assert kwargs["allow_redirects"] is False
        assert kwargs["timeout"] == (3, 8)
        if url == f"{VIRUSTOTAL}/urls/{url_id}":
            assert kwargs["headers"]["x-apikey"] == "vt-test-key"
            return SimpleNamespace(status_code=429)
        assert url == ABUSEIPDB
        assert kwargs["params"]["ipAddress"] == "8.8.8.8"
        assert kwargs["headers"]["Key"] == "ip-test-key"
        raise requests.Timeout()

    lookup = MagicMock(side_effect=response)
    monkeypatch.setattr(requests, "get", lookup)
    message = f"From: test@example.org\n\n{lookup_url} http://192.168.2.3 127.0.0.1 8.8.8.8 {'a' * 64}".encode()
    result = triage("report.eml", message, "live")
    assert lookup.call_count == 2
    assert [row["status"] for row in result.iocs] == [
        "Rate limited", "Redacted", "Redacted", "Non-public IP", "Timed out", "Rate limited",
    ]
    assert "192.168.2.3" not in result.ticket
    assert "OpenAI API key missing" in result.ticket


def test_live_hash_lookup_keeps_score_and_no_record_distinct(monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "vt-test-key")
    payload = {"data": {"attributes": {"last_analysis_stats": {"malicious": 4, "suspicious": 1}}}}
    get = MagicMock(side_effect=[SimpleNamespace(status_code=200, json=lambda: payload), SimpleNamespace(status_code=404)])
    monkeypatch.setattr(requests, "get", get)
    rows = enrich_iocs({"sha256": ["a" * 64, "b" * 64], "urls": [], "ipv4": []}, "live")
    assert get.call_args_list[0].args[0] == f"{VIRUSTOTAL}/files/{'a' * 64}"
    assert (rows[0]["status"], rows[0]["score"], rows[0]["flagged"]) == ("Found", "4 malicious / 1 suspicious engines", True)
    assert (rows[1]["status"], rows[1]["score"], rows[1]["flagged"]) == ("No record", "", False)


def test_openai_gets_only_sanitized_evidence_and_ticket_uses_real_rows(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "ai-test-key")
    for name in ("VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    draft = "\n\n".join(f"## {heading}\n\nDraft for {heading}." for heading in HEADINGS)
    sdk = MagicMock()
    create = sdk.return_value.__enter__.return_value.responses.create
    create.return_value = SimpleNamespace(status="completed", output_text=draft)
    monkeypatch.setattr(openai, "OpenAI", sdk)
    path = DATA / "sample_sysmon.json"
    result = triage(path, path.read_bytes(), "live")
    request = create.call_args.kwargs
    assert request["store"] is False
    assert "untrusted evidence" in request["instructions"]
    assert "demo-analyst" not in request["input"]
    assert "[REDACTED]" in request["input"]
    assert json.loads(request["input"])["threat_intel"][0]["status"] == "API key missing"
    assert "AI draft for analyst review" in result.ticket
    assert "Draft for Executive Summary" in result.ticket
    assert "Draft for Enriched IOC Table" not in result.ticket
    assert "API key missing" in result.ticket

    create.return_value = SimpleNamespace(status="completed", output_text="Unstructured reply")
    fallback = triage(path, path.read_bytes(), "live").ticket
    assert "unexpected ticket format" in fallback
    assert "T1059.001" in fallback


def test_ollama_overrides_openai_and_falls_back_locally(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "unused-test-key")
    monkeypatch.setenv("OLLAMA_MODEL", "local-test:1b")
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    monkeypatch.setattr(openai, "OpenAI", no_request)
    draft = "\n\n".join(f"## {heading}\n\nLocal draft." for heading in HEADINGS)
    factory = MagicMock()
    session = factory.return_value.__enter__.return_value
    session.post.return_value = SimpleNamespace(status_code=200, json=lambda: {
        "done": True, "message": {"content": draft},
    })
    monkeypatch.setattr(requests, "Session", factory)
    path = DATA / "sample_sysmon.json"
    result = triage(path, path.read_bytes(), "live", ollama=True)
    assert "AI draft for analyst review (Ollama)" in result.ticket
    assert session.trust_env is False
    assert session.post.call_args.args == ("http://127.0.0.1:11434/api/chat",)
    body = session.post.call_args.kwargs["json"]
    assert body["model"] == "local-test:1b"
    assert "demo-analyst" not in body["messages"][1]["content"]

    session.post.side_effect = requests.ConnectionError()
    fallback = triage(path, path.read_bytes(), ollama=True).ticket
    assert "Ollama request failed" in fallback
    assert "T1059.001" in fallback


def test_lm_studio_sanitizes_input_and_handles_failures(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "unused-test-key")
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    monkeypatch.setattr(openai, "OpenAI", no_request)
    draft = "\n\n".join(f"## {heading}\n\nLocal draft." for heading in HEADINGS)
    factory = MagicMock()
    session = factory.return_value.__enter__.return_value
    session.post.return_value = SimpleNamespace(status_code=200, json=lambda: {
        "choices": [{"finish_reason": "stop", "message": {"content": draft}}],
    })
    monkeypatch.setattr(requests, "Session", factory)
    path = DATA / "sample_sysmon.json"
    result = triage(path, path.read_bytes(), "live", lm_studio=True, model="qwen-test")
    assert "AI draft for analyst review (LM Studio)" in result.ticket
    assert session.trust_env is False
    assert session.post.call_args.args == ("http://127.0.0.1:1234/v1/chat/completions",)
    request = session.post.call_args.kwargs
    assert request["allow_redirects"] is False
    assert request["json"]["model"] == "qwen-test"
    assert "demo-analyst" not in request["json"]["messages"][1]["content"]
    assert "[REDACTED]" in request["json"]["messages"][1]["content"]
    session.post.side_effect = requests.ConnectionError()
    fallback = triage(path, path.read_bytes(), lm_studio=True, model="qwen-test").ticket
    assert "LM Studio request failed" in fallback
    assert "T1059.001" in fallback

    monkeypatch.delenv("LM_STUDIO_MODEL", raising=False)
    assert "Set an LM Studio model identifier" in triage(path, path.read_bytes(), lm_studio=True).ticket
