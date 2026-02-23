"""RevGraph Quickstart — load a binary and run basic analysis."""

from pathlib import Path

from revgraph import RevGraphContext
from revgraph.config.loader import load_config
from revgraph.extraction.bcc_loader import load_bcc_file
from revgraph.graph.loader import GraphLoader
from revgraph.graph.query_engine import QueryEngine
from revgraph.graph.schema import create_schema


def main():
    # 1. Load configuration
    ctx = RevGraphContext()
    ctx.config = load_config()

    # 2. Connect to Neo4j
    driver = ctx.ensure_neo4j()
    create_schema(driver)

    # 3. Load a BCC file
    bcc_path = Path("tests/fixtures/sample.bcc")
    artifact = load_bcc_file(bcc_path)
    if artifact is None:
        print("No BCC file found. Using sample data.")
        return

    # 4. Load into graph
    loader = GraphLoader(driver)
    stats = loader.load_binary(artifact)
    print(f"Loaded: {stats}")

    # 5. Query
    engine = QueryEngine(driver)
    functions = engine.execute(
        "MATCH (b:BinaryFile)-[:DEFINES]->(f:Function) "
        "RETURN b.name AS binary, f.name AS function, f.address AS address "
        "ORDER BY f.address LIMIT 20"
    )
    for func in functions:
        print(f"  {func['binary']}: {func['function']} @ {hex(func['address'])}")

    # 6. Natural language query (requires LLM API key)
    try:
        llm = ctx.ensure_llm()
        from revgraph.nl2gql.translator import NL2CypherTranslator

        translator = NL2CypherTranslator(llm, driver)
        cypher, results = translator.translate_and_execute(
            "What functions call malloc?"
        )
        print(f"\nNL Query -> Cypher: {cypher}")
        for r in results:
            print(f"  {r}")
    except Exception as e:
        print(f"\nNL query skipped (no API key?): {e}")

    ctx.close()


if __name__ == "__main__":
    main()
