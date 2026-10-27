import os

import httpx

from sentinel.llm.base import LLMProvider


class GeminiProvider(LLMProvider[str]):
    """Gemini REST provider usable by Scout, Red Team, and Blue Team."""

    model_name = "gemini-3.5-flash-lite"

    def __init__(self, model_name: str = "gemini-3.5-flash-lite", client: httpx.Client | None = None) -> None:
        self.model_name = model_name
        self.client = client

    def generate(self, prompt: str) -> str:
        if not os.getenv("GOOGLE_API_KEY"):
            raise RuntimeError("GOOGLE_API_KEY is not configured for the Gemini provider")
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model_name}:generateContent"
        try:
            # Patch diffs can require considerably more reasoning and output than
            # Scout summaries, especially for a multi-contract Foundry target.
            client = self.client or httpx.Client(timeout=90.0)
            response = client.post(
                url,
                headers={"x-goog-api-key": os.environ["GOOGLE_API_KEY"]},
                json={"contents": [{"parts": [{"text": prompt}]}]},
            )
            response.raise_for_status()
            payload = response.json()
            text = payload["candidates"][0]["content"]["parts"][0]["text"]
        except (httpx.HTTPError, KeyError, IndexError, TypeError, ValueError) as exc:
            raise RuntimeError(f"Gemini request failed: {exc}") from exc
        if not isinstance(text, str) or not text.strip():
            raise RuntimeError("Gemini returned no text output")
        return text


# Kept as a compatibility name for code importing the earlier Scout-only adapter.
GeminiScout = GeminiProvider
