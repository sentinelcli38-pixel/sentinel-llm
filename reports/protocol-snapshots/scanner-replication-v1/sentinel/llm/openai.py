import os

from sentinel.llm.base import LLMProvider


class OpenAIRedTeam(LLMProvider[str]):
    model_name = "gpt-4o"

    def __init__(self, model_name: str = "gpt-4o", client=None) -> None:
        self.model_name = model_name
        self.client = client

    def generate(self, prompt: str) -> str:
        if not os.getenv("OPENAI_API_KEY"):
            raise RuntimeError("OPENAI_API_KEY is not configured for the GPT-4o Red Team")
        try:
            if self.client is None:
                from openai import OpenAI

                self.client = OpenAI()
            response = self.client.responses.create(model=self.model_name, input=prompt, store=False)
            text = response.output_text
        except Exception as exc:  # SDK exception classes vary by installed version.
            raise RuntimeError(f"OpenAI Red Team request failed: {exc}") from exc
        if not isinstance(text, str) or not text.strip():
            raise RuntimeError("OpenAI Red Team returned no text output")
        return text
