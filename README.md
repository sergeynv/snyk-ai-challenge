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

## Structured Database

The `Database` class loads CSV vulnerability data into SQLite and exposes it via tool-use interface.

```python
from snyk_ai.database import Database

# Load from directory containing CSV files
db = Database("data/csv")

# Get tool definitions (OpenAI-compatible format)
print(db.tools)

# Call tools directly
print(db.call_tool("get_vulnerability", {"cve_id": "CVE-2024-1234"}))
print(db.call_tool("search_vulnerabilities", {"severity": "Critical"}))
print(db.call_tool("list_packages", {"ecosystem": "npm"}))
print(db.call_tool("get_statistics", {"group_by": "severity"}))
```

Available tools:
- `get_vulnerability(cve_id)` - Get details for a specific CVE
- `search_vulnerabilities(ecosystem?, severity?, type?, min_cvss?, max_cvss?)` - Filter vulnerabilities
- `list_packages(ecosystem?)` - List packages
- `get_statistics(group_by?)` - Aggregate by ecosystem/severity/type

## Query Router

The `Router` classifies user queries and transforms them for downstream processing. It uses an LLM to determine whether a query needs advisory search (unstructured), database lookup (structured), both (hybrid), or neither (none).

```python
from snyk_ai.router import Router, RouteType, RouteValidationError
from snyk_ai.advisories import Advisories
from snyk_ai.models import create_model

model = create_model("ollama:llama3.2")
advisories = Advisories("data/advisories")

router = Router(model, advisories)
result = router.route("How does SQL injection work?")

print(result.route_type)          # RouteType.UNSTRUCTURED
print(result.unstructured_query)  # Transformed query for semantic search
print(result.structured_query)    # Transformed query for database (or None)
print(result.reasoning)           # Explanation of routing decision
```

Route types:
- `UNSTRUCTURED` - Query advisory content (explanations, attack patterns, remediation)
- `STRUCTURED` - Query database (CVE lookups, filtering, statistics)
- `HYBRID` - Query both sources (default when uncertain)
- `NONE` - Off-topic, not security-related

Raises `RouteValidationError` if LLM response is malformed.

## Advisories RAG

The `AdvisoriesRag` class handles unstructured queries by performing semantic search over advisories and synthesizing answers using an LLM.

```python
from snyk_ai.advisories_rag import AdvisoriesRag, AdvisoryResult
from snyk_ai.advisories import Advisories
from snyk_ai.models import create_model

model = create_model("ollama:llama3.2")
advisories = Advisories("data/advisories")
advisories.init_vectordb(model)

rag = AdvisoriesRag(model, advisories)
result = rag.query("How do I prevent SQL injection?")

print(result.answer)   # Synthesized answer from LLM
print(result.query)    # Original query
for src in result.sources:
    print(f"  - {src.advisory_title}: {src.section_header}")
```

Result fields:
- `answer` - LLM-synthesized answer based on retrieved context
- `sources` - List of `SourceReference` (advisory_title, section_header, advisory_filename)
- `query` - The original query

## Notebooks

```bash
uv run jupyter notebook notebooks/advisories.ipynb
uv run jupyter notebook notebooks/explore_advisories
```
