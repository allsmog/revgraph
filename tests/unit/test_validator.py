"""Tests for Cypher query validation."""

from revgraph.nl2gql.validator import sanitize_cypher, validate_cypher


def test_valid_match_query():
    is_valid, err = validate_cypher(
        "MATCH (f:Function) RETURN f.name LIMIT 10"
    )
    assert is_valid
    assert err == ""


def test_empty_query():
    is_valid, err = validate_cypher("")
    assert not is_valid
    assert "Empty" in err


def test_invalid_starter():
    is_valid, err = validate_cypher("SELECT * FROM functions")
    assert not is_valid
    assert "valid Cypher clause" in err


def test_unbalanced_parens():
    is_valid, err = validate_cypher("MATCH (f:Function RETURN f.name")
    assert not is_valid
    assert "parentheses" in err


def test_write_blocked_in_read_mode():
    is_valid, err = validate_cypher(
        "CREATE (n:Node {name: 'test'}) RETURN n", allow_writes=False
    )
    assert not is_valid
    assert "Write operation" in err


def test_write_allowed():
    is_valid, err = validate_cypher(
        "CREATE (n:Node {name: 'test'}) RETURN n", allow_writes=True
    )
    assert is_valid


def test_missing_return():
    is_valid, err = validate_cypher("MATCH (f:Function)")
    assert not is_valid
    assert "RETURN" in err


def test_sanitize_code_fences():
    raw = "```cypher\nMATCH (f:Function) RETURN f.name\n```"
    result = sanitize_cypher(raw)
    assert result == "MATCH (f:Function) RETURN f.name"


def test_sanitize_strips_explanation():
    raw = "Here is the query:\nMATCH (f:Function) RETURN f.name"
    result = sanitize_cypher(raw)
    assert result == "MATCH (f:Function) RETURN f.name"
