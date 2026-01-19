import os
from abc import ABC, abstractmethod

import requests
from dotenv import load_dotenv

load_dotenv()


class Model(ABC):
    """Abstract base class for LLM models."""

    DEFAULT_SYSTEM_PROMPT = "You are a helpful assistant with broad knowledge. Answer questions accurately and concisely."

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the model identifier as 'provider:model_name'."""
        pass

    @abstractmethod
    def generate(self, prompt: str) -> str:
        """Generate a response for the given prompt."""
        pass


def create_model(spec: str) -> Model:
    """Create a model from a spec string.

    Args:
        spec: Format "<provider>:<model>" or "<provider>".

    Returns:
        Model instance.

    Raises:
        ValueError: If provider is not recognized.
    """
    PROVIDERS = {
        "ollama": _OllamaModel,
        "openai": _OpenAIModel,
        "anthropic": _AnthropicModel,
    }

    parts = spec.split(":", 1)
    provider = parts[0].lower()
    model_name = parts[1] if len(parts) > 1 else None

    if provider not in PROVIDERS:
        raise ValueError(
            f"Unknown provider: {provider}. Must be one of: {', '.join(PROVIDERS.keys())}"
        )

    model_class = PROVIDERS[provider]
    return model_class(name=model_name) if model_name else model_class()


class _OllamaModel(Model):
    def __init__(
        self,
        name: str = "llama3.2",
        base_url: str = "http://localhost:11434",
        system_prompt: str = Model.DEFAULT_SYSTEM_PROMPT,
    ):
        self.model_name = name
        self.base_url = base_url
        self.system_prompt = system_prompt

    @property
    def name(self) -> str:
        return f"ollama:{self.model_name}"

    def generate(self, prompt: str) -> str:
        response = requests.post(
            f"{self.base_url}/api/generate",
            json={
                "model": self.model_name,
                "prompt": prompt,
                "system": self.system_prompt,
                "stream": False,
            },
        )
        response.raise_for_status()
        return response.json()["response"]


class _OpenAIModel(Model):
    def __init__(
        self,
        name: str = "gpt-4o-mini",
        system_prompt: str = Model.DEFAULT_SYSTEM_PROMPT,
    ):
        from openai import OpenAI

        self.model_name = name
        self.system_prompt = system_prompt
        self.client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))

    @property
    def name(self) -> str:
        return f"openai:{self.model_name}"

    def generate(self, prompt: str) -> str:
        response = self.client.chat.completions.create(
            model=self.model_name,
            messages=[
                {"role": "system", "content": self.system_prompt},
                {"role": "user", "content": prompt},
            ],
        )
        return response.choices[0].message.content


class _AnthropicModel(Model):
    """
    Claude models as of Jan 20, 2026:
    - claude-haiku-4-5: Fast, lightweight model for simple tasks
    - claude-sonnet-4-5: Balanced performance and capability
    - claude-opus-4-5: Most capable model for complex tasks

    See: https://docs.anthropic.com/en/docs/about-claude/models

    Requires ANTHROPIC_API_KEY environment variable.
    """

    def __init__(
        self,
        name: str = "claude-haiku-4-5",
        system_prompt: str = Model.DEFAULT_SYSTEM_PROMPT,
    ):
        from anthropic import Anthropic

        self.model_name = name
        self.system_prompt = system_prompt
        self.client = Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))

    @property
    def name(self) -> str:
        return f"anthropic:{self.model_name}"

    def generate(self, prompt: str) -> str:
        response = self.client.messages.create(
            model=self.model_name,
            max_tokens=1024,
            system=self.system_prompt,
            messages=[{"role": "user", "content": prompt}],
        )
        return response.content[0].text


class Models:
    """Predefined model instances for common use cases."""

    class _LazyModel:
        def __init__(self, spec):
            self.spec = spec
            self._instance = None

        def __get__(self, obj, objtype=None):
            if self._instance is None:
                self._instance = create_model(self.spec)
            return self._instance

    # Ollama
    Llama_3_2 = _LazyModel("ollama:llama3.2")

    # OpenAI
    GPT_5_2 = _LazyModel("openai:gpt-5.2")
    GPT_5_2_Mini = _LazyModel("openai:gpt-5.2-mini")

    # Anthropic (Haiku < Sonnet < Opus)
    Claude_Haiku = _LazyModel("anthropic:claude-haiku-4-5")
    Claude_Sonnet = _LazyModel("anthropic:claude-sonnet-4-5")
    Claude_Opus = _LazyModel("anthropic:claude-opus-4-5")
