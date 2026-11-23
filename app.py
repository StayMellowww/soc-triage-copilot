"""Run defensive triage from the command line or call triage() from a UI."""

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path

from src.llm_client import LMStudioClient, OllamaClient, OpenAIClient
from src.parsers import MAX_BYTES, AlertParseError, parse_alert
from src.sanitizer import sanitize_alert
from src.threat_intel import enrich_iocs
from src.ticket_generator import generate_ticket

DATA = Path(__file__).resolve().parent / "data"
DEMO_ALERTS = {
    "Credential-harvesting email": "sample_phishing.eml",
    "Encoded PowerShell execution": "sample_sysmon.json",
    "Suspected outbound beaconing": "sample_beacon.json",
}


@dataclass
class TriageResult:
    iocs: list[dict]
    ticket: str
    evidence: dict


def triage(filename: str | Path, raw: bytes, mode: str = "local", *, ollama: bool = False,
           lm_studio: bool = False, model: str = "") -> TriageResult:
    alert = sanitize_alert(parse_alert(filename, raw))
    rows = enrich_iocs(alert["iocs"], mode)
    if ollama and lm_studio:
        raise ValueError("Choose one local model provider")
    client = (LMStudioClient(model) if lm_studio else OllamaClient() if ollama
              else OpenAIClient.from_environment() if mode == "live" else None)
    return TriageResult(rows, generate_ticket(alert, rows, mode, client), alert["evidence"])


def _read_alert(path):
    with path.open("rb") as handle:
        return handle.read(MAX_BYTES + 1)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("alert", type=Path, nargs="?", help="An EML message or Sysmon JSON export")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--demo", action="store_true", help="Run the three offline sample alerts")
    modes.add_argument("--mock", action="store_true", help="Use simulated threat intelligence and a local ticket")
    modes.add_argument("--live", action="store_true", help="Enable configured external threat intel and OpenAI by default")
    providers = parser.add_mutually_exclusive_group()
    providers.add_argument("--ollama", action="store_true", help="Draft with a local Ollama model")
    providers.add_argument("--lm-studio", action="store_true", help="Draft with a local LM Studio model")
    parser.add_argument("--model", default="", help="LM Studio model identifier (or set LM_STUDIO_MODEL)")
    parser.add_argument("--output", "-o", type=Path, help="Write the Markdown report to this file")
    args = parser.parse_args(argv)
    if args.demo == (args.alert is not None):
        parser.error("Provide one alert file or use --demo.")
    if args.demo and (args.ollama or args.lm_studio):
        parser.error("Use a local model with an alert file to keep --demo dependency-free.")
    if args.model and not args.lm_studio:
        parser.error("Use --model with --lm-studio.")

    try:
        if args.demo:
            reports = []
            for label, filename in DEMO_ALERTS.items():
                path = DATA / filename
                ticket = triage(path, _read_alert(path), "mock").ticket
                reports.append(ticket.replace("# SOC Incident Ticket", f"# Demo - {label}", 1))
            report = "\n---\n\n".join(reports)
        else:
            mode = "live" if args.live else "mock" if args.mock else "local"
            if args.output and args.output.resolve() == args.alert.resolve():
                parser.error("Use a different output path to preserve the original alert.")
            report = triage(args.alert, _read_alert(args.alert), mode, ollama=args.ollama,
                            lm_studio=args.lm_studio, model=args.model).ticket
        if args.output:
            with args.output.open("x", encoding="utf-8") as handle:
                handle.write(report)
            print(f"Wrote {args.output}")
        else:
            if hasattr(sys.stdout, "reconfigure"):
                sys.stdout.reconfigure(encoding="utf-8")
            print(report, end="")
    except (AlertParseError, OSError) as exc:
        parser.exit(1, f"Triage failed: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
