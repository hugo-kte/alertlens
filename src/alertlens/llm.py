"""LLM clients: Ollama (local) with JSON-schema constrained decoding, and a scripted mock."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any, Protocol

import httpx


class ChatModel(Protocol):
    name: str

    def complete(self, system: str, user: str, schema: dict[str, Any]) -> str: ...


class OllamaModel:
    """Calls Ollama's /api/chat with ``format`` set to a JSON schema.

    Constrained decoding guarantees syntactically valid JSON of the right shape; whether the
    *content* is right (allowed IDs, sensible verdict) is checked by the caller.
    """

    def __init__(
        self,
        name: str = "llama3.2:3b",
        base_url: str = "http://localhost:11434",
        timeout_s: float = 300.0,
        num_ctx: int = 4096,
        seed: int = 42,
    ) -> None:
        self.name = name
        self.client = httpx.Client(base_url=base_url, timeout=timeout_s)
        self.options = {"temperature": 0, "seed": seed, "num_ctx": num_ctx, "num_predict": 400}

    def complete(self, system: str, user: str, schema: dict[str, Any]) -> str:
        resp = self.client.post(
            "/api/chat",
            json={
                "model": self.name,
                "stream": False,
                "format": schema,
                "options": self.options,
                "keep_alive": "30m",
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
            },
        )
        resp.raise_for_status()
        return resp.json()["message"]["content"]


class ScriptedModel:
    """Deterministic stand-in for tests: maps the user prompt to a JSON answer."""

    def __init__(
        self, respond: Callable[[str], dict[str, Any] | str], name: str = "scripted"
    ) -> None:
        self.respond = respond
        self.name = name
        self.calls: list[str] = []

    def complete(self, system: str, user: str, schema: dict[str, Any]) -> str:
        self.calls.append(user)
        out = self.respond(user)
        return out if isinstance(out, str) else json.dumps(out)
