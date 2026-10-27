import httpx

from sentinel.llm.base import LLMProvider


class OllamaBlueTeam(LLMProvider[str]):
    model_name = "deepseek-coder:7b"

    def __init__(self, host: str = "http://127.0.0.1:11434", model_name: str = "deepseek-coder:7b", client: httpx.Client | None = None) -> None:
        self.host = host.rstrip("/")
        self.model_name = model_name
        self.client = client

    def generate(self, prompt: str) -> str:
        try:
            client = self.client or httpx.Client(timeout=60.0)
            response = client.post(f"{self.host}/api/generate", json={"model": self.model_name, "prompt": prompt, "stream": False})
            response.raise_for_status()
            text = response.json().get("response")
        except (httpx.HTTPError, ValueError) as exc:
            raise RuntimeError(f"Ollama Blue Team request failed at {self.host}: {exc}") from exc
        if not isinstance(text, str) or not text.strip():
            raise RuntimeError("Ollama Blue Team returned no text output")
        return text
