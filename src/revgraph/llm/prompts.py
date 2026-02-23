"""Jinja2 prompt templates and plain-string agentic system prompts for LLM tasks."""

from __future__ import annotations

from jinja2 import Environment, BaseLoader

_env = Environment(loader=BaseLoader(), trim_blocks=True, lstrip_blocks=True)

# ============================================================================
# Agentic system prompts (plain strings — no Jinja2 / no data interpolation)
# ============================================================================

AGENT_SUMMARIZE_FUNCTION = (
    "You are a reverse engineering expert. Your task is to summarize what a "
    "single function does in 2-3 concise sentences.\n\n"
    "You have tools to inspect the binary graph. Use them to fetch the "
    "function's decompiled code, strings, imports, callers, and callees. "
    "Then produce a clear natural-language summary."
)

AGENT_SUMMARIZE_BINARY = (
    "You are a reverse engineering expert. Your task is to produce a "
    "high-level summary of an entire binary.\n\n"
    "You have tools to explore the binary graph. Start by loading the "
    "binary metadata, then list functions (prioritize by BBR score if "
    "available), inspect key functions, search strings, and review imports. "
    "Produce a comprehensive but concise summary covering the binary's "
    "purpose, architecture, notable capabilities, and any interesting "
    "patterns."
)

AGENT_LABEL_FUNCTION = (
    "You are a reverse engineering expert. Your task is to suggest a "
    "descriptive function name for a function with an auto-generated name.\n\n"
    "You have tools to inspect the function's code, strings, and imports. "
    "Analyze them and respond with ONLY a JSON object:\n"
    '{"label": "descriptive_function_name", "confidence": 0.0-1.0, '
    '"reasoning": "brief explanation"}'
)

AGENT_VULN_REPORT = (
    "You are a vulnerability researcher. Your task is to produce a "
    "comprehensive vulnerability report for a binary.\n\n"
    "You have tools to explore the binary graph. Start by loading binary "
    "info and computing BBR scores. Then examine dangerous functions, "
    "high-BBR functions, strings, and imports. For each potential "
    "vulnerability, inspect the function's decompiled code.\n\n"
    "Produce a report covering:\n"
    "1. Identified vulnerabilities (with severity: critical/high/medium/low)\n"
    "2. Dangerous API usage patterns\n"
    "3. Potential attack vectors\n"
    "4. Recommendations"
)

AGENT_YARA_GENERATE = (
    "You are a malware analyst. Your task is to generate YARA rules for "
    "detecting a binary or similar variants.\n\n"
    "You have tools to explore the binary graph. Start by loading binary "
    "info, then search for distinctive strings, review imports, and "
    "examine opcode sequences in high-BBR basic blocks.\n\n"
    "Generate well-structured YARA rules with:\n"
    "- Descriptive rule names\n"
    "- Appropriate meta fields\n"
    "- String and byte pattern conditions\n"
    "- Comments explaining each rule\n\n"
    "Output ONLY the YARA rules (no markdown fences)."
)

AGENT_EXPLOIT_IDENTIFY = (
    "You are a binary exploitation expert. Your task is to identify ALL "
    "potential vulnerabilities in a binary by exploring its code via tools.\n\n"
    "Use the provided tools to inspect functions, read decompiled code, "
    "check imports, search strings, and navigate the call graph. Focus on:\n"
    "- Buffer overflows (stack and heap)\n"
    "- Off-by-one/null errors (especially scanf %%Ns into N-byte buffers)\n"
    "- Saved frame pointer corruption (callee overwrites saved RBP → "
    "caller's rbp-relative accesses shift)\n"
    "- OOB reads via comparison functions (memcmp, strncmp) creating oracles\n"
    "- Format string bugs\n"
    "- Use-after-free\n"
    "- Unchecked return values\n\n"
    "For EACH vulnerability, respond with a JSON array where each entry has:\n"
    '- "id": short identifier (e.g. "oob-read-1")\n'
    '- "type": vulnerability class\n'
    '- "location": function name and address\n'
    '- "description": what the bug is\n'
    '- "trigger": exact input to reach and trigger\n'
    '- "constraints": what limits exploitation\n'
    '- "read_or_write": read, write, or both\n'
    '- "caller_impact": effect on caller if stack state is corrupted\n'
    '- "survives": true/false — does the program continue?\n\n'
    "Respond ONLY with the JSON array."
)

AGENT_EXPLOIT_VALIDATE = (
    "You are a binary exploitation auditor. Your job is to DISPROVE or "
    "CONFIRM each claimed vulnerability by re-examining the code via tools.\n\n"
    "For EACH claimed vulnerability:\n"
    "1. Use tools to fetch the function's code and trace the exact path\n"
    "2. Check every validation, bounds check, and branch\n"
    "3. Distinguish: check fails AND exits → killed vs. check fails BUT "
    "continues → survives\n"
    "4. For saved RBP corruption, trace caller impact\n\n"
    "Respond with a JSON array. Each entry:\n"
    '- "id": same id from input\n'
    '- "confirmed": true/false\n'
    '- "kill_reason": why it fails (null if confirmed)\n'
    '- "primitive": what attacker gets (null if not confirmed)\n'
    '- "caller_impact": effect on caller\'s local variables\n'
    '- "prerequisite": requirements for exploitation\n'
    '- "interacts_with": other vuln IDs this chains with\n\n'
    "Be adversarial but do NOT over-kill: a failed validation that does not "
    "halt the function is NOT a kill reason.\n"
    "Respond ONLY with the JSON array."
)

AGENT_EXPLOIT_CHAIN = (
    "You are a binary exploitation strategist. Given confirmed vulnerabilities "
    "and access to the binary via tools, build a CONCRETE exploitation chain.\n\n"
    "Use tools to re-examine code as needed. Build a plan that:\n"
    "1. Starts from program start\n"
    "2. Uses ONLY confirmed vulnerabilities\n"
    "3. Specifies EXACT input sequences\n"
    "4. Handles ASLR, PIE, NX\n"
    "5. Ends with code execution or flag read\n\n"
    "Respond with JSON:\n"
    '{"feasible": true/false, "strategy": "summary", '
    '"steps": [{"step": 1, "action": "...", "input": "...", '
    '"effect": "...", "leaks": "..."}], '
    '"missing_primitive": null or "description", '
    '"exploit_skeleton": "pwntools code"}'
)

# -- NL2GQL --

NL2CYPHER_SYSTEM = _env.from_string("""You are a Neo4j Cypher query expert for a reverse engineering graph database.

## Graph Schema
{{ schema }}

## Rules
- Output ONLY valid Cypher. No explanations, no markdown.
- Use parameter placeholders ($param) for user-supplied values.
- Always include LIMIT unless the user explicitly asks for all results.
- Use MATCH patterns that respect the schema relationships.
- For function addresses, accept both integer and hex string forms.
- Prefer exact matches over fuzzy when the user specifies a name.
""")

NL2CYPHER_USER = _env.from_string("""Translate this natural language question to a Cypher query:

{{ question }}

{% if few_shots %}
## Examples
{% for ex in few_shots %}
Q: {{ ex.question }}
Cypher: {{ ex.cypher }}
{% endfor %}
{% endif %}
""")

# -- Summarization --

SUMMARIZE_FUNCTION = _env.from_string("""You are a reverse engineering expert. Summarize what this function does in 2-3 sentences.

Function name: {{ name }}
Address: {{ address }}
{% if decompiled_code %}
Decompiled code:
```c
{{ decompiled_code }}
```
{% endif %}
{% if strings %}
Referenced strings: {{ strings | join(', ') }}
{% endif %}
{% if imports %}
Referenced imports: {{ imports | join(', ') }}
{% endif %}
{% if callers %}
Called by: {{ callers | join(', ') }}
{% endif %}
{% if callees %}
Calls: {{ callees | join(', ') }}
{% endif %}
""")

SUMMARIZE_BINARY = _env.from_string("""You are a reverse engineering expert. Provide a high-level summary of this binary.

Binary: {{ name }} ({{ architecture }}, {{ file_type }})
SHA256: {{ sha256 }}
Total functions: {{ num_functions }}
{% if top_functions %}
Key functions (by BBR rank):
{% for f in top_functions %}
- {{ f.name }} (addr {{ f.address }}): {{ f.summary or 'no summary' }}
{% endfor %}
{% endif %}
{% if imports %}
Notable imports: {{ imports[:20] | join(', ') }}
{% endif %}
{% if strings %}
Notable strings: {{ strings[:20] | join(', ') }}
{% endif %}
""")

# -- Labeling --

LABEL_FUNCTION = _env.from_string("""You are a reverse engineering expert. Suggest a descriptive function name for this function.

Current name: {{ name }}
Address: {{ address }}
{% if decompiled_code %}
Decompiled code:
```c
{{ decompiled_code }}
```
{% endif %}
{% if strings %}
Referenced strings: {{ strings | join(', ') }}
{% endif %}
{% if imports %}
Referenced imports: {{ imports | join(', ') }}
{% endif %}

Respond with JSON: {"label": "descriptive_function_name", "confidence": 0.0-1.0, "reasoning": "brief explanation"}
""")

# -- Vulnerability Report --

VULN_REPORT = _env.from_string("""You are a vulnerability researcher. Analyze this binary for potential security issues.

Binary: {{ name }} ({{ architecture }})
{% if dangerous_functions %}
Functions calling dangerous APIs:
{% for f in dangerous_functions %}
- {{ f.name }}: calls {{ f.dangerous_imports | join(', ') }}
  {% if f.decompiled_code %}Code snippet: {{ f.decompiled_code[:500] }}{% endif %}
{% endfor %}
{% endif %}
{% if high_bbr_functions %}
High-importance functions (by BBR):
{% for f in high_bbr_functions %}
- {{ f.name }} (BBR: {{ f.bbr_score }})
{% endfor %}
{% endif %}

Provide a vulnerability assessment in {{ format }} format covering:
1. Identified vulnerabilities (with severity)
2. Dangerous API usage patterns
3. Potential attack vectors
4. Recommendations
""")

# -- Exploitation Analysis (multi-pass) --

EXPLOIT_IDENTIFY = _env.from_string("""You are a binary exploitation expert. Analyze this binary and identify ALL potential vulnerabilities.

Binary: {{ name }} ({{ architecture }})
Protections: {{ protections }}
Libc: {{ libc_version }}
{% if disassembly %}
## Disassembly
```
{{ disassembly }}
```
{% endif %}
{% if strings %}
## Strings
{{ strings | join('\n') }}
{% endif %}
{% if imports %}
## Imports
{{ imports | join(', ') }}
{% endif %}

## Common vulnerability patterns to check
- scanf %Ns into an N-byte buffer: writes N chars + null terminator = N+1 bytes. The null byte overwrites the next stack slot (often saved RBP).
- Saved frame pointer corruption: if a callee's off-by-one/null overwrites the saved RBP, the CALLER's frame pointer is corrupted on return. All of the caller's local variable accesses (via rbp-relative addressing) shift to wrong memory. This is a WRITE primitive even though the immediate bug is only 1 byte.
- OOB read via comparison functions (memcmp, strncmp): even without direct output, match/no-match results create an oracle for byte-by-byte inference of adjacent memory.
- Unchecked return values from functions that can fail (malloc, get_index, etc.) — trace what happens if the function continues with an error/invalid value.

For EACH vulnerability found, respond with a JSON array. Each entry MUST include:
- "id": short identifier (e.g. "oob-read-1", "off-by-null-1")
- "type": vulnerability class (buffer overflow, OOB read, format string, UAF, integer overflow, saved frame pointer corruption, etc.)
- "location": function name and address
- "description": what the bug is
- "trigger": exact input sequence to reach and trigger this bug
- "constraints": what limits exploitation (size bounds, character restrictions, validation checks, program exits)
- "read_or_write": whether this gives read, write, or both
- "caller_impact": if this corrupts saved RBP or other caller state, describe what happens in the CALLER after this function returns
- "survives": true/false — does the program continue running after triggering, or does it crash/exit?

Be precise. If a bug causes the program to exit() before the corrupted state is used, survives=false.
A function that stores an error value but CONTINUES to execute (no exit/abort/return-early) still survives — the corrupted state propagates to the caller.
Respond ONLY with the JSON array.
""")

EXPLOIT_VALIDATE = _env.from_string("""You are a binary exploitation auditor. Your job is to DISPROVE or CONFIRM each claimed vulnerability.

Binary: {{ name }} ({{ architecture }})
Protections: {{ protections }}

## Claimed Vulnerabilities
```json
{{ vulns_json }}
```

{% if disassembly %}
## Disassembly
```
{{ disassembly }}
```
{% endif %}

For EACH claimed vulnerability:
1. Trace the EXACT code path from user input to the bug trigger
2. Check EVERY validation, bounds check, and branch between input and bug
3. Identify any condition that PREVENTS the bug from firing. CRITICAL: a check that fails does NOT prevent exploitation if the function CONTINUES afterward (no exit/abort/early-return). You must distinguish:
   - "Check fails AND function exits/returns before corrupted state is used" → bug is killed
   - "Check fails BUT function continues with error value, corrupted state still exists on stack" → bug SURVIVES, trace what the corrupted state does in the CALLER
4. For saved frame pointer corruption (off-by-one/null overwriting saved RBP): trace what happens in the CALLER after the function returns with corrupted RBP. The caller's rbp-relative accesses all shift, potentially reading attacker-controlled data as local variables (pointers, sizes, indices). This is often a write primitive.
5. Determine if the bug gives useful primitives (arbitrary read? arbitrary write? info leak? code execution? frame pointer control?)

Respond with a JSON array. For each vulnerability, include:
- "id": same id from the input
- "confirmed": true/false
- "kill_reason": if false, explain EXACTLY why it doesn't work. Must show that the function EXITS or that the corrupted state is NEVER REACHABLE, not merely that a validation check produces an error value. (null if confirmed)
- "primitive": what the attacker actually gets ("N-byte OOB read oracle", "1-byte null write to saved RBP → caller frame shift", "arbitrary write via X", etc.) — null if not confirmed
- "caller_impact": for bugs that corrupt stack state, describe the effect on the caller's local variable accesses after return
- "prerequisite": what must be true for this to work (leaked addresses, specific alignment, etc.)
- "interacts_with": list of other vuln IDs this could chain with

Respond ONLY with the JSON array. Be adversarial — assume the initial analysis was overconfident. But do NOT over-kill: a failed validation check that does not halt the function is NOT a kill reason.
""")

EXPLOIT_CHAIN = _env.from_string("""You are a binary exploitation strategist. Given confirmed vulnerabilities, build a CONCRETE exploitation chain.

Binary: {{ name }} ({{ architecture }})
Protections: {{ protections }}
Libc: {{ libc_version }}

## Confirmed Vulnerabilities
```json
{{ confirmed_json }}
```

{% if disassembly %}
## Key Disassembly
```
{{ disassembly }}
```
{% endif %}

Build an exploitation plan that:
1. Starts from program start (no prior state)
2. Uses ONLY confirmed vulnerabilities (do NOT invent new ones)
3. Specifies the EXACT sequence of menu choices, inputs, and expected outputs
4. Handles ASLR, PIE, NX — explain how each is defeated using available primitives
5. Ends with either code execution (shell/ROP) or flag read

Key exploitation patterns to consider:
- Saved frame pointer corruption: if a callee corrupts saved RBP, the caller's rbp-relative local variable accesses all shift. If the caller uses [rbp-X] to load a pointer and then writes through it (fread, fgets, memcpy, etc.), the shifted access may read an attacker-controlled value as the destination pointer → arbitrary write. Map out the caller's full stack layout and identify which shifted offsets overlap with attacker-controlled data (haystack buffer, heap data, prior inputs).
- Oracle-based leaks: OOB read via comparison (memcmp/strncmp) gives match/no-match. With controlled pattern data, brute-force one byte at a time (256 queries per byte) to recover stack contents including saved RBP, return addresses, and canary.
- Combining leak + corruption: first leak the exact RBP value via oracle, then trigger the frame pointer corruption knowing exactly where the shifted frame will land, placing controlled data at the right offsets.

For each step, specify:
- Menu option chosen
- Exact data sent (hex if binary)
- What information is gained or what state changes
- What could go wrong and how to handle it

If exploitation is NOT possible with the confirmed vulnerabilities alone, say so explicitly and explain what additional primitive would be needed.

Respond with JSON:
{
  "feasible": true/false,
  "strategy": "one-line summary",
  "steps": [
    {
      "step": 1,
      "action": "what to do",
      "input": "exact input or description",
      "effect": "what changes",
      "leaks": "what is learned (if any)"
    }
  ],
  "missing_primitive": null or "description of what's needed",
  "exploit_skeleton": "python pwntools code outline (if feasible)"
}
""")

# -- YARA Rules --

YARA_GENERATE = _env.from_string("""You are a malware analyst. Generate YARA rules for detecting this binary or similar variants.

Binary: {{ name }}
Architecture: {{ architecture }}
{% if strings %}
Notable strings:
{% for s in strings[:30] %}
- "{{ s }}"
{% endfor %}
{% endif %}
{% if imports %}
Key imports: {{ imports[:20] | join(', ') }}
{% endif %}
{% if unique_opcodes %}
Distinctive opcode sequences:
{% for seq in unique_opcodes %}
- {{ seq }}
{% endfor %}
{% endif %}

Generate well-structured YARA rules with:
- Descriptive rule names
- Appropriate meta fields
- String and byte pattern conditions
- Comments explaining each rule
""")
