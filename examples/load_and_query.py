"""Example: Load multiple binaries and perform cross-binary analysis."""

from revgraph import RevGraphContext
from revgraph.config.loader import load_config
from revgraph.graph.cross_binary import diff_functions, find_shared_imports
from revgraph.graph.query_engine import QueryEngine


def main():
    ctx = RevGraphContext()
    ctx.config = load_config()
    driver = ctx.ensure_neo4j()
    engine = QueryEngine(driver)

    # List loaded binaries
    binaries = engine.execute(
        "MATCH (b:BinaryFile) "
        "OPTIONAL MATCH (b)-[:DEFINES]->(f:Function) "
        "RETURN b.name AS name, b.sha256 AS sha256, count(f) AS functions "
        "ORDER BY b.name"
    )
    print("Loaded binaries:")
    for b in binaries:
        print(f"  {b['name']}: {b['functions']} functions ({b['sha256'][:12]}...)")

    if len(binaries) >= 2:
        sha_a = binaries[0]["sha256"]
        sha_b = binaries[1]["sha256"]

        # Cross-binary analysis
        print(f"\nCross-binary analysis: {binaries[0]['name']} vs {binaries[1]['name']}")

        shared = find_shared_imports(driver, sha_a, sha_b)
        print(f"  Shared imports: {len(shared)}")
        for s in shared[:5]:
            print(f"    {s['import_name']} ({s['library']})")

        diff = diff_functions(driver, sha_a, sha_b)
        print(f"  Only in {binaries[0]['name']}: {len(diff['only_in_a'])} functions")
        print(f"  Only in {binaries[1]['name']}: {len(diff['only_in_b'])} functions")
        print(f"  Size changed: {len(diff['size_changed'])} functions")

    # Query for dangerous functions
    dangerous = engine.execute(
        "MATCH (f:Function)-[:REFERENCES_IMPORT]->(i:Import) "
        "WHERE i.name IN ['strcpy', 'sprintf', 'gets', 'strcat', 'system'] "
        "RETURN f.name AS function, collect(i.name) AS dangerous_apis, "
        "f.binary_sha256 AS binary "
        "ORDER BY f.name"
    )
    if dangerous:
        print(f"\nDangerous API usage ({len(dangerous)} functions):")
        for d in dangerous[:10]:
            print(f"  {d['function']}: {d['dangerous_apis']}")

    ctx.close()


if __name__ == "__main__":
    main()
