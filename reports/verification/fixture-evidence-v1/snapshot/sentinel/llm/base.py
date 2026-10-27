from abc import ABC, abstractmethod
from typing import Generic, TypeVar

ResponseT = TypeVar("ResponseT")


class LLMProvider(ABC, Generic[ResponseT]):
    model_name: str

    @abstractmethod
    def generate(self, prompt: str) -> ResponseT:
        """Return a structured response; implementations must not execute commands."""
