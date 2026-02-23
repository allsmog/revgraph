# RevGraph

**Reverse Engineering Graph Intelligence SDK**

A Python SDK for automating reverse engineering with Neo4j graph databases, LLM-powered analysis, embedding-based similarity search, and agentic workflows.

## Features

- **Binary extraction** — Parse BCC protobuf files (via Blackfyre/Ghidra) into normalized artifacts
- **Graph loading** — Batch load into Neo4j with full schema (functions, blocks, instructions, strings, imports)
- **NL2GQL** — Natural language to Cypher translation with LLM, few-shot examples, and error refinement
- **BBR (Basic Block Rank)** — PageRank on control flow graphs to identify critical code
- **Embeddings** — Generate and store function/block embeddings via LiteLLM
- **Similarity analysis** — Cosine similarity search, clustering (HDBSCAN/KMeans), cross-binary comparison
- **LLM tasks** — Function summarization, labeling, vulnerability reports, YARA rule generation
- **Agent workflows** — Multi-agent teams for analysis, patch impact, N-day triage, YARA, firmware
- **MCP servers** — Expose graph, extraction, and embedding tools via Model Context Protocol
- **Provider-agnostic** — Claude, OpenAI, Gemini, Ollama, or any LiteLLM-supported provider

## Installation

```bash
pip install -e .

# Start Neo4j
docker compose up neo4j -d
```

## Quick Start

```python
from revgraph import RevGraphContext
from revgraph.config.loader import load_config
from revgraph.extraction.bcc_loader import load_bcc_file
from revgraph.graph.loader import GraphLoader
from revgraph.graph.schema import create_schema
from revgraph.graph.query_engine import QueryEngine

# Initialize
ctx = RevGraphContext()
ctx.config = load_config()
driver = ctx.ensure_neo4j()
create_schema(driver)

# Load a binary into the graph
artifact = load_bcc_file("path/to/binary.bcc")
loader = GraphLoader(driver)
stats = loader.load_binary(artifact)

# Query the graph
engine = QueryEngine(driver)
functions = engine.execute(
    "MATCH (b:BinaryFile)-[:DEFINES]->(f:Function) "
    "RETURN f.name AS function, f.address AS address "
    "ORDER BY f.address LIMIT 20"
)

# Natural language queries
llm = ctx.ensure_llm()
from revgraph.nl2gql.translator import NL2CypherTranslator

translator = NL2CypherTranslator(llm, driver)
cypher, results = translator.translate_and_execute("What functions call malloc?")

ctx.close()
```

### Cross-binary analysis

```python
from revgraph.graph.cross_binary import diff_functions, find_shared_imports

shared = find_shared_imports(driver, sha256_a, sha256_b)
diff = diff_functions(driver, sha256_a, sha256_b)
```

### Embeddings and similarity

```python
from revgraph.embeddings.generator import EmbeddingGenerator
from revgraph.embeddings.similarity import SimilaritySearch

generator = EmbeddingGenerator(llm, driver)
search = SimilaritySearch(driver)
similar = search.find_similar(function_address, top_k=10)
```

### LLM-powered analysis

```python
from revgraph.llm.summarizer import Summarizer
from revgraph.llm.vuln_reporter import VulnReporter
from revgraph.llm.yara_generator import YARAGenerator

summarizer = Summarizer(llm, driver)
reporter = VulnReporter(llm, driver)
yara = YARAGenerator(llm, driver)
```

## Configuration

Create `revgraph.yaml` in your project root:

```yaml
neo4j:
  uri: "bolt://localhost:7687"
  password: "${NEO4J_PASSWORD}"

llm:
  default_model: "claude-sonnet-4-20250514"  # or gpt-4o, ollama/llama3.1, etc.
  api_keys:
    anthropic: "${ANTHROPIC_API_KEY}"

embeddings:
  default_model: "text-embedding-3-large"
```

## Docker

```bash
docker compose up neo4j -d                              # Just Neo4j
docker compose --profile local-llm up -d                # + Ollama
docker compose --profile local-llm --profile mcp up -d  # Everything
```

## CLI

RevGraph also ships with a CLI for common operations:

| Command | Description |
|---------|-------------|
| `revgraph extract <BCC>` | Parse BCC protobuf files |
| `revgraph load <BCC>` | Load artifacts into Neo4j |
| `revgraph query <Q>` | Cypher or natural language query |
| `revgraph embed` | Generate embeddings |
| `revgraph analyze bbr` | Compute Basic Block Rank |
| `revgraph analyze cluster` | Cluster functions by similarity |
| `revgraph analyze similarity` | Find similar functions |
| `revgraph llm summarize` | Summarize function/binary |
| `revgraph llm label` | Label functions with descriptive names |
| `revgraph llm vuln-report` | Generate vulnerability report |
| `revgraph llm yara` | Generate YARA rules |
| `revgraph agent run` | Run agent workflow |
| `revgraph serve` | Start MCP server(s) |
| `revgraph schema create\|drop\|show` | Manage graph schema |

## Development

```bash
pip install -e ".[dev]"
make test-unit          # Fast tests, no external deps
make test-integration   # Requires Neo4j
make lint
make typecheck
```

## License

Apache 2.0
