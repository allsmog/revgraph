"""Tests for LLM prompt templates."""

from revgraph.llm.prompts import (
    EXPLOIT_CHAIN,
    EXPLOIT_IDENTIFY,
    EXPLOIT_VALIDATE,
    LABEL_FUNCTION,
    NL2CYPHER_SYSTEM,
    NL2CYPHER_USER,
    SUMMARIZE_FUNCTION,
)


def test_nl2cypher_prompt_renders():
    system = NL2CYPHER_SYSTEM.render(schema="(:Function)-[:CALLS]->(:Function)")
    assert "Function" in system
    assert "CALLS" in system
    assert "Cypher" in system

    user = NL2CYPHER_USER.render(
        question="What functions call malloc?",
        few_shots=[{"question": "List all functions", "cypher": "MATCH (f:Function) RETURN f"}],
    )
    assert "malloc" in user
    assert "MATCH" in user


def test_summarize_prompt_includes_code():
    rendered = SUMMARIZE_FUNCTION.render(
        name="sub_401000",
        address="0x401000",
        decompiled_code="void sub_401000() { malloc(0x100); }",
        strings=["error", "debug"],
        imports=["malloc", "free"],
        callers=["main"],
        callees=["malloc"],
    )
    assert "sub_401000" in rendered
    assert "malloc(0x100)" in rendered
    assert "error" in rendered
    assert "malloc" in rendered


def test_label_prompt_requests_json():
    rendered = LABEL_FUNCTION.render(
        name="FUN_00401234",
        address="0x401234",
        decompiled_code="int FUN_00401234(char *s) { return strlen(s); }",
        strings=[],
        imports=["strlen"],
    )
    assert "JSON" in rendered
    assert "label" in rendered
    assert "confidence" in rendered
    assert "strlen" in rendered


def test_exploit_identify_prompt_requires_structured_output():
    rendered = EXPLOIT_IDENTIFY.render(
        name="scanner",
        architecture="x86-64",
        protections="PIE, NX, Partial RELRO",
        libc_version="GLIBC 2.31",
        disassembly="scanner_naive2:\n  cmpl $0xfff, -0x4(%rbp)",
        strings=["flag.txt", "Enter parameters:"],
        imports=["memcmp", "scanf", "malloc", "free"],
    )
    # Must require structured fields that force validation thinking
    assert "survives" in rendered
    assert "constraints" in rendered
    assert "trigger" in rendered
    assert "read_or_write" in rendered
    assert "caller_impact" in rendered
    assert "JSON array" in rendered
    # Must teach saved frame pointer corruption pattern
    assert "saved RBP" in rendered or "saved frame pointer" in rendered
    assert "scanf" in rendered.lower() or "%Ns" in rendered


def test_exploit_validate_prompt_is_adversarial():
    rendered = EXPLOIT_VALIDATE.render(
        name="scanner",
        architecture="x86-64",
        protections="PIE, NX",
        disassembly="read_parameters:\n  ...",
        vulns_json='[{"id":"oob-1","type":"OOB read"}]',
    )
    # Must instruct adversarial checking
    assert "DISPROVE" in rendered or "adversarial" in rendered
    assert "kill_reason" in rendered
    assert "confirmed" in rendered
    # Must distinguish "check fails but function continues" from "check halts execution"
    assert "CONTINUES" in rendered or "continues" in rendered
    assert "caller_impact" in rendered
    # Must NOT encourage false kills from non-halting validation failures
    assert "over-kill" in rendered or "NOT a kill reason" in rendered


def test_exploit_chain_prompt_requires_concrete_steps():
    rendered = EXPLOIT_CHAIN.render(
        name="scanner",
        architecture="x86-64",
        protections="PIE, NX",
        libc_version="GLIBC 2.31",
        disassembly="main:\n  ...",
        confirmed_json='[{"id":"oob-1","primitive":"OOB read"}]',
    )
    assert "EXACT sequence" in rendered
    assert "ONLY confirmed" in rendered
    assert "NOT possible" in rendered or "not feasible" in rendered.lower() or "NOT feasible" in rendered
    assert "exploit_skeleton" in rendered
    # Must understand frame pointer corruption → caller variable shift
    assert "caller" in rendered.lower()
    assert "rbp-relative" in rendered or "rbp" in rendered.lower()
