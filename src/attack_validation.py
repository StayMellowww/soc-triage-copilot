"""Check suggested techniques against the offline Enterprise ATT&CK index."""

import json
import re
from functools import lru_cache
from pathlib import Path

TECHNIQUE_ID = re.compile(r"\bT\d{4}(?:\.\d{3})?\b(?!\.\d)", re.IGNORECASE | re.ASCII)


@lru_cache(maxsize=1)
def technique_index():
    path = Path(__file__).resolve().parents[1] / "data" / "attack_enterprise_index.json"
    return json.loads(path.read_text(encoding="utf-8"))["techniques"]


def suggested_ids(text):
    return list(dict.fromkeys(match.upper() for match in TECHNIQUE_ID.findall(text)))


def render_mappings(evidence_mappings, model_mapping):
    index = technique_index()
    proposals = suggested_ids(model_mapping)
    lines = []
    for technique in dict.fromkeys([*evidence_mappings, *proposals]):
        if technique not in index:
            lines.append(f"- **{technique}** — Absent from the active Enterprise ATT&CK index.")
            continue
        name, phases = index[technique]
        tactics = ", ".join(phase.replace("-", " ").title() for phase in phases)
        assessment = evidence_mappings.get(technique, "Evidence support not established by the current rules.")
        lines.append(f"- **{technique} ({name})** · {tactics} — {assessment}")
    return "\n".join(lines) or "Undetermined from the supplied evidence."
