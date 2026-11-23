import pytest

from app import DATA, triage
from evaluate import CASES, assess_draft
from src.attack_validation import render_mappings, suggested_ids


@pytest.mark.parametrize("filename,expected_ids", CASES.items())
def test_fixture_mappings_follow_observed_evidence(filename, expected_ids):
    path = DATA / filename
    result = triage(path, path.read_bytes())
    assert set(suggested_ids(result.ticket)) == expected_ids


def test_model_mappings_validate_id_and_evidence_separately():
    rendered = render_mappings(
        {"T1566.002": "Candidate. Validate the link."},
        "T1059.001 (Phishing), T1059.000, and T1566.002 (Incorrect name).",
    )
    assert "T1059.001 (PowerShell)" in rendered
    assert "Evidence support not established" in rendered
    assert "T1059.000** — Absent" in rendered
    assert "T1566.002 (Spearphishing Link)" in rendered
    assert "Candidate. Validate the link." in rendered
    assert "Incorrect name" not in rendered


def test_evaluator_flags_known_errors_and_keeps_uncertainty():
    assert assess_draft("T1566.002 is a candidate. Reputation is unknown. If confirmed, isolate the host.",
                        {"T1566.002"}) == []
    assert assess_draft("T1059.001. No positive matches. The host was isolated.", {"T1566.002"}) == [
        "Unexpected ATT&CK IDs: T1059.001",
        "Missing expected ATT&CK IDs: T1566.002",
        "unknown reputation confused with a result",
        "completed containment reported",
    ]
