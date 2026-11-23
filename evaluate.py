"""Measure common model draft errors on fictional alerts using local LM Studio."""

import argparse
import re
from collections import Counter

from app import DATA
from src.attack_validation import suggested_ids
from src.llm_client import LLMClient, LMStudioClient
from src.parsers import parse_alert
from src.sanitizer import sanitize_alert
from src.threat_intel import enrich_iocs
from src.ticket_generator import generate_ticket

CASES = {
    "sample_phishing.eml": {"T1566.002"},
    "sample_sysmon.json": {"T1059.001"},
    "sample_beacon.json": {"T1071.001"},
    "evaluation/benign_link.eml": set(),
    "evaluation/isolated_connection.json": set(),
}

# These phrase checks flag specific regressions for review. They cannot judge prose meaning.
CLAIMS = {
    "unknown reputation confused with a result": r"\b(?:no (?:positive |negative )?matches|returned no record|clean reputation)\b",
    "completed containment reported": r"\b(?:we (?:have )?(?:isolated|blocked|quarantined)|(?:host|indicator|email|account) (?:has been|was) (?:isolated|blocked|quarantined|disabled))\b",
}


def assess_draft(draft, expected_ids):
    ids = set(suggested_ids(draft))
    findings = []
    if ids - expected_ids:
        findings.append("Unexpected ATT&CK IDs: " + ", ".join(sorted(ids - expected_ids)))
    if expected_ids - ids:
        findings.append("Missing expected ATT&CK IDs: " + ", ".join(sorted(expected_ids - ids)))
    findings.extend(label for label, pattern in CLAIMS.items() if re.search(pattern, draft, re.IGNORECASE))
    return findings


class RecordedDraft(LLMClient):
    provider = "LM Studio"

    def __init__(self, model):
        self.client = LMStudioClient(model)
        self.text = ""

    def complete(self, instructions, evidence_json):
        self.text = self.client.complete(instructions, evidence_json)
        return self.text


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", required=True, help="Loaded LM Studio model identifier")
    args = parser.parse_args()
    totals = Counter()
    for filename, expected_ids in CASES.items():
        path = DATA / filename
        alert = sanitize_alert(parse_alert(path, path.read_bytes()))
        client = RecordedDraft(args.model)
        ticket = generate_ticket(alert, enrich_iocs(alert["iocs"], "local"), "local", client)
        findings = assess_draft(client.text, expected_ids) if client.text else []
        verdict = "flagged" if findings else "passed phrase and ID checks"
        if "rule-based draft" in ticket.splitlines()[2]:
            verdict = "fallback"
            findings.insert(0, ticket.splitlines()[2].removeprefix("> "))
        totals[verdict] += 1
        print(f"{filename}: {verdict}", flush=True)
        for finding in findings:
            print(f"  - {finding}", flush=True)
    print(f"{totals['passed phrase and ID checks']}/{len(CASES)} passed, "
          f"{totals['flagged']} flagged, {totals['fallback']} fell back.")


if __name__ == "__main__":
    main()
