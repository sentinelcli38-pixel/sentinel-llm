from sentinel.llm.base import LLMProvider


class MockProvider(LLMProvider[str]):
    model_name = "mock"

    def generate(self, prompt: str) -> str:
        return '{"decision":"candidate","reasoning":"Mock mode preserves deterministic routing."}'
