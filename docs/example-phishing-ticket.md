# SOC Incident Ticket

> Offline demo · simulated threat intelligence · rule-based draft

## Severity Rating

**High** (provisional)

## Executive Summary

A reported email was inspected for phishing indicators. The From and Reply-To domains differ. The supplied headers report an authentication failure. Verify it at the mail gateway. The message contains a URL. Recipient interaction and credential exposure are unverified. At least one IOC crossed the configured reputation threshold. Confirm the result in context.

## MITRE ATT&CK Tactic/Technique ID

- **T1566.002 (Spearphishing Link)** · Initial Access — Candidate. The message contains a link and a sender or authentication anomaly. Validate the link.

## Enriched IOC Table

**Lookup outcomes** — 0 checked, 0 no record, 1 skipped, 0 failed, 2 simulated.

Skipped, failed, and no-record lookups leave reputation unknown. Simulated results use fictional data.

| Type | Indicator | Provider | Outcome | Status | Reputation |
| --- | --- | --- | --- | --- | --- |
| URL | `hxxps://signin-review[.]example/session` | VirusTotal | Simulated | Mock result | 12 malicious / 2 suspicious engines |
| IPv4 | `198[.]51[.]100[.]27` | AbuseIPDB | Simulated | Mock result | Abuse confidence 68/100 (22 reports) |
| IPv4 | `[REDACTED]` | AbuseIPDB | Skipped | Redacted | — |

## Containment Checklist

- [ ] Preserve the original message and verify authentication against trusted mail gateway records.
- [ ] Search message trace for related deliveries and check whether recipients visited the link.
- [ ] If phishing is confirmed, quarantine matching mail through the approved workflow.
- [ ] If credential exposure is confirmed, revoke sessions and reset affected credentials through the identity team.
