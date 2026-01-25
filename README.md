# snyk-ai

A hybrid RAG system for security vulnerability data.

## Setup

```bash
uv sync
```

## Supported LLM Providers

### Ollama

Install Ollama; e.g. on MacOS:

```bash
brew install ollama
```

Start the server (runs on port 11434)

```bash
ollama serve
```

Pull a model (once)

```bash
ollama pull llama3.2
```

### Anthropic

- [Models overview - Claude Docs](https://platform.claude.com/docs/en/about-claude/models/overview)
  - *Haiku* < *Sonnet* < *Opus*
- [API Keys - Claude Developer Platform](https://platform.claude.com/settings/keys)

Requires `ANTHROPIC_API_KEY` env variable.

### OpenAI

- [Models | OpenAI API](https://platform.openai.com/docs/models)
  - *GPT-5.2*, *GPT-5-mini*

- [API keys - OpenAI API](https://platform.openai.com/api-keys)

Requires `OPENAI_API_KEY` env variable.

## Usage

```bash
# Default (Ollama with llama3.2)
uv run snyk-ai

# Specify provider only (uses default model)
uv run snyk-ai ollama
uv run snyk-ai openai
uv run snyk-ai anthropic

# Specify provider and model
uv run snyk-ai ollama:mistral
uv run snyk-ai openai:gpt-5.2
uv run snyk-ai anthropic:claude-haiku-4-5
```

## Vector Database (Advisories)

The `Advisories` class includes ChromaDB integration for semantic search over security advisories.

```python
from snyk_ai.advisories import Advisories
from snyk_ai.models import create_model

# Load advisories from directory
advisories = Advisories("data/advisories")

# Initialize vector DB (requires model for code block summarization)
model = create_model("ollama:llama3.2")
advisories.init_vectordb(model)

# Semantic search - returns (Advisory, section_indices) tuples
results = advisories.search("How does SQL injection work?", top_k=3)

for advisory, section_indices in results:
    print(f"{advisory.title}")
    for idx in section_indices:
        section = advisory.sections[idx]
        print(f"  - {section.header.content}")
        print(section.to_text())
```

Chunks are stored with metadata: `advisory_filename`, `section_index`.

## Notebooks

```bash
uv run jupyter notebook notebooks/advisories.ipynb
uv run jupyter notebook notebooks/explore_advisories
```
