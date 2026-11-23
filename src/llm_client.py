"""Provider interface for drafting a ticket from sanitized evidence."""

import os
from abc import ABC, abstractmethod


class LLMError(RuntimeError):
    """The provider could not return a complete draft."""


class LLMClient(ABC):
    provider = "LLM"

    @abstractmethod
    def complete(self, instructions: str, evidence_json: str) -> str:
        """Return a Markdown draft."""


class OpenAIClient(LLMClient):
    provider = "OpenAI"

    def __init__(self, api_key: str, model: str):
        self.api_key = api_key
        self.model = model

    @classmethod
    def from_environment(cls):
        key = os.getenv("OPENAI_API_KEY", "").strip()
        model = os.getenv("OPENAI_MODEL", "").strip() or "gpt-5-mini"
        return cls(key, model) if key else None

    def complete(self, instructions: str, evidence_json: str) -> str:
        try:
            from openai import OpenAI, OpenAIError
        except ImportError as exc:
            raise LLMError("OpenAI SDK unavailable") from exc
        try:
            with OpenAI(api_key=self.api_key, timeout=25, max_retries=0) as client:
                response = client.responses.create(
                    model=self.model, instructions=instructions, input=evidence_json,
                    max_output_tokens=2000, store=False,
                )
        except OpenAIError as exc:
            raise LLMError(type(exc).__name__) from exc
        if response.status != "completed" or not response.output_text.strip():
            raise LLMError("OpenAI returned an incomplete draft")
        return response.output_text.strip()


class OllamaClient(LLMClient):
    provider = "Ollama"

    def __init__(self):
        self.model = os.getenv("OLLAMA_MODEL", "").strip() or "llama3.2"

    def complete(self, instructions: str, evidence_json: str) -> str:
        try:
            import requests
        except ImportError as exc:
            raise LLMError("Install the project requirements to use Ollama") from exc

        if self.model.casefold().endswith(("-cloud", ":cloud")):
            raise LLMError("Ollama requires a locally installed model")
        try:
            with requests.Session() as session:
                session.trust_env = False
                response = session.post(
                    "http://127.0.0.1:11434/api/chat", timeout=(3, 120), allow_redirects=False,
                    json={"model": self.model, "stream": False, "options": {"num_predict": 2000},
                          "messages": [{"role": "system", "content": instructions},
                                       {"role": "user", "content": evidence_json}]},
                )
            if response.status_code == 404:
                raise LLMError("Ollama model not found. Pull the selected model first")
            if response.status_code != 200:
                raise LLMError(f"Ollama returned HTTP {response.status_code}")
            data = response.json()
            draft = data["message"]["content"]
            if data.get("done") is True and data.get("done_reason") != "length" and isinstance(draft, str) and draft.strip():
                return draft.strip()
        except requests.Timeout as exc:
            raise LLMError("Ollama timed out") from exc
        except requests.RequestException as exc:
            raise LLMError("Ollama request failed. Check that Ollama is running") from exc
        except (ValueError, TypeError, KeyError) as exc:
            raise LLMError("Ollama returned an invalid response") from exc
        raise LLMError("Ollama returned an incomplete draft")


class LMStudioClient(LLMClient):
    provider = "LM Studio"

    def __init__(self, model: str = ""):
        self.model = model.strip() or os.getenv("LM_STUDIO_MODEL", "").strip()

    def complete(self, instructions: str, evidence_json: str) -> str:
        try:
            import requests
        except ImportError as exc:
            raise LLMError("Install the project requirements to use LM Studio") from exc

        if not self.model:
            raise LLMError("Set an LM Studio model identifier before running triage")
        try:
            with requests.Session() as session:
                session.trust_env = False
                response = session.post(
                    "http://127.0.0.1:1234/v1/chat/completions",
                    timeout=(3, 300), allow_redirects=False,
                    json={"model": self.model, "stream": False, "max_tokens": 8192,
                          "messages": [{"role": "system", "content": instructions},
                                       {"role": "user", "content": evidence_json}]},
                )
            if response.status_code != 200:
                raise LLMError(f"LM Studio returned HTTP {response.status_code}. Check the model identifier and server settings")
            choice = response.json()["choices"][0]
            draft = choice["message"]["content"]
            if choice.get("finish_reason") == "stop" and isinstance(draft, str) and draft.strip():
                return draft.strip()
        except requests.Timeout as exc:
            raise LLMError("LM Studio timed out") from exc
        except requests.RequestException as exc:
            raise LLMError("LM Studio request failed. Check that its local server is running") from exc
        except (ValueError, TypeError, KeyError, IndexError) as exc:
            raise LLMError("LM Studio returned an invalid response") from exc
        raise LLMError("LM Studio returned an incomplete draft")
