"""Tests for few-shot example selection."""

from revgraph.nl2gql.few_shot import classify_question, get_few_shots


def test_classify_import_question():
    assert classify_question("What functions call malloc?") == "import"


def test_classify_callgraph_question():
    assert classify_question("Show the call graph for main") == "callgraph"


def test_classify_string_question():
    assert classify_question("Find functions referencing 'password'") == "string"


def test_classify_bbr_question():
    assert classify_question("What are the most important blocks?") == "bbr"


def test_classify_vuln_question():
    assert classify_question("Find dangerous functions using strcpy") == "vulnerability"


def test_classify_general_question():
    assert classify_question("How many nodes are in the graph?") == "general"


def test_get_few_shots_by_category():
    shots = get_few_shots(category="import", max_examples=2)
    assert len(shots) <= 2
    assert all(s.category == "import" for s in shots)


def test_get_few_shots_default():
    shots = get_few_shots(max_examples=5)
    assert len(shots) == 5
