"""Run with `python -m streamlit run streamlit_app.py`."""

from hashlib import sha256

import streamlit as st

from app import DATA, DEMO_ALERTS, triage
from src.parsers import AlertParseError
from src.ticket_generator import display_indicator

st.set_page_config(page_title="SOC Triage Copilot", layout="wide")
st.title("SOC Triage Copilot")
st.caption("Review email and Sysmon evidence, check IOC reputation, and draft an incident ticket.")

with st.sidebar:
    st.header("Alert source")
    source = st.radio("Input", ("Demo alert", "Upload a file"), label_visibility="collapsed")
    if source == "Demo alert":
        selection = st.selectbox("Scenario", tuple(DEMO_ALERTS))
        path = DATA / DEMO_ALERTS[selection]
        name, raw, mode, provider, model = path.name, path.read_bytes(), "mock", "Rule-based", ""
    else:
        upload = st.file_uploader("Drop an EML or Sysmon JSON file", type=("eml", "json"), max_upload_size=2)
        name, raw = (upload.name, upload.getvalue()) if upload else ("", b"")
        label = st.selectbox("Enrichment", ("Local only", "Mock results", "Live APIs"))
        mode = {"Local only": "local", "Mock results": "mock", "Live APIs": "live"}[label]
        default_draft = "OpenAI if configured" if mode == "live" else "Rule-based"
        provider = st.selectbox("Ticket drafting", (default_draft, "LM Studio (local)", "Ollama (local)"))
        model = st.text_input("LM Studio model identifier", help="Copy the model identifier from LM Studio or set LM_STUDIO_MODEL.") if provider == "LM Studio (local)" else ""
        if mode == "live":
            st.caption("Eligible IOCs go to configured intel providers.")
            if provider == "OpenAI if configured":
                st.caption("Sanitized alert evidence goes to OpenAI when configured.")
    run = st.button("Run triage", type="primary", disabled=not raw)

# Bind the result to the selected source, file contents, and enrichment mode.
selection_id = (source, name, sha256(raw).digest(), mode, provider, model)
if run:
    st.session_state.pop("triage_result", None)
    with st.spinner("Analyzing alert…"):
        try:
            st.session_state.triage_result = (selection_id, triage(
                name, raw, mode, ollama=provider == "Ollama (local)",
                lm_studio=provider == "LM Studio (local)", model=model,
            ))
        except AlertParseError as exc:
            st.error(str(exc))

stored = st.session_state.get("triage_result")
if stored is None or stored[0] != selection_id:
    st.info("Choose an alert and select Run triage to create a ticket.")
    st.stop()

result = stored[1]
st.text(name)
indicators, flagged = st.columns(2)
indicators.metric("Unique sanitized IOCs", len(result.iocs))
flagged.metric("Above reputation threshold", sum(row["flagged"] for row in result.iocs))

st.subheader("Enriched indicators")
if result.iocs:
    st.dataframe([
        {"Type": row["type"], "Indicator": display_indicator(row["indicator"]), "Provider": row["provider"],
         "Status": row["status"], "Reputation": row["score"] or "—"}
        for row in result.iocs
    ], hide_index=True, width="stretch")
else:
    st.caption("No supported indicators were extracted.")

st.subheader("Incident ticket")
st.caption("Use the copy icon in the code block to copy the Markdown to your clipboard.")
st.code(result.ticket, language="markdown", wrap_lines=True)
st.download_button("Download Markdown", result.ticket, file_name="incident-ticket.md", mime="text/markdown")
