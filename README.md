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

## Notebooks

```bash
uv run jupyter notebook notebooks/advisories.ipynb
uv run jupyter notebook notebooks/explore_advisories
```
