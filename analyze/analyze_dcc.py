#!/usr/bin/env python3
"""Analyze phase: Dynamic Call Context classification with dual memory.

This implements Algorithm 2 of the paper. Functions are processed in the
callee-first batch order produced by harvest/build_callgraph_batches.py, so that
by the time a caller is analysed, every callee it depends on already has a
verdict. Each prompt is assembled from four parts:

  1. the rule rubric (the SMM vulnerability rules, read from a prompt file);
  2. SHORT-TERM MEMORY -- the pseudocode of the function's immediate callees;
  3. LONG-TERM MEMORY  -- the verdict JSON of callees that were themselves
     flagged, followed transitively down the call chain for as long as each
     successive function was also flagged, plus a one-line summary of the chain;
  4. the pseudocode of the function under analysis.

The chain in (3) is what carries cross-function state. If A calls A1, A1 calls B1,
and both A1 and B1 were flagged, then when A is analysed its context holds the
sources of A, A1, A2, A3 (short-term), the verdicts of A1 and B1 with the source
of B1, and the line "A -> A1 -> B1". A function judged clean terminates the chain:
nothing below it is pulled in, which is what keeps the context bounded instead of
growing with the size of the call graph.

Usage:
    export OPENAI_API_KEY=...            # any value for a local server
    export OPENAI_BASE_URL=http://<host>:<port>/v1/
    python analyze_dcc.py <extracted_functions_dir> <prompt_file> [--model NAME]

<extracted_functions_dir> must contain the per-function .c files together with the
function_batches.txt and function_call_relations.txt written by the Harvest phase.
Results are written to output/<module>/{json,thinkchain}/.
"""
import argparse
import json
import os
import re
import sys

import openai

DEFAULT_MODEL = "qwen3-30b-a3b"

client = openai.OpenAI(
    api_key=os.environ.get("OPENAI_API_KEY", ""),
    base_url=os.environ.get("OPENAI_BASE_URL", "http://localhost:8000/v1/"),
    timeout=3600,
    max_retries=3,
)

JSON_BLOCK_RE = re.compile(r"```json(.*?)```", re.DOTALL)


# --------------------------------------------------------------------------
# Harvest-phase artefacts
# --------------------------------------------------------------------------

def read_batches(path):
    """Parse function_batches.txt into a list of batches (analysis order)."""
    batches = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if ":" not in line:
                continue
            names = [n.strip() for n in line.split(":", 1)[1].split(",")]
            names = [n for n in names if n]
            if names:
                batches.append(names)
    return batches


def read_call_relations(path):
    """Parse function_call_relations.txt into {caller: [callees]}."""
    relations = {}
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if ":" not in line:
                continue
            caller, callees = line.split(":", 1)
            relations[caller.strip()] = [
                c.strip() for c in callees.split(",") if c.strip()
            ]
    return relations


def read_source(folder, name):
    path = os.path.join(folder, name + ".c")
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()


# --------------------------------------------------------------------------
# Dual memory
# --------------------------------------------------------------------------

def short_term_memory(func, relations, folder):
    """Pseudocode of the immediate callees."""
    parts = []
    for callee in relations.get(func, []):
        src = read_source(folder, callee)
        if src:
            parts.append(f"// callee: {callee}\n```c\n{src}\n```")
    return "\n\n".join(parts)


def long_term_memory(func, relations, folder, flagged, verdicts):
    """Findings along call chains of consecutively flagged functions.

    Walks down from `func`, following only callees that were themselves flagged.
    A clean function terminates that branch, so unflagged subtrees never enter the
    context. Returns (context_text, [chain_paths]).
    """
    entries, chains, seen = [], [], set()

    def walk(node, path):
        for callee in relations.get(node, []):
            if not flagged.get(callee):
                continue                      # chain breaks at a clean function
            chain = path + [callee]
            if callee not in seen:
                seen.add(callee)
                block = [f"// flagged callee: {callee}",
                         f"// on chain: {' -> '.join(chain)}",
                         "```json",
                         json.dumps(verdicts.get(callee, {}), ensure_ascii=False,
                                    indent=2),
                         "```"]
                src = read_source(folder, callee)
                if src and callee not in relations.get(func, []):
                    # Direct callees already appear in short-term memory; deeper
                    # ones need their source supplied here.
                    block.append(f"```c\n{src}\n```")
                entries.append("\n".join(block))
            chains.append(" -> ".join(chain))
            walk(callee, chain)

    walk(func, [func])
    return "\n\n".join(entries), chains


# --------------------------------------------------------------------------
# Inference
# --------------------------------------------------------------------------

def extract_json(text):
    if not text:
        return None
    match = JSON_BLOCK_RE.search(text)
    candidates = [match.group(1).strip()] if match else []
    candidates.append(text)
    for candidate in candidates:
        try:
            return json.loads(candidate)
        except (json.JSONDecodeError, TypeError):
            continue
    return None


def is_flagged(text, verdict):
    """A function counts as flagged when the model says so in either channel."""
    if verdict:
        risk = str(verdict.get("risk_level", "")).lower()
        if risk in {"high", "medium"}:
            return True
        if verdict.get("vulnerability_type"):
            return True
    return "vulnerable: yes" in (text or "").lower()


def build_prompt(rules, func, source, st_mem, lt_mem, chains):
    parts = [rules]
    if st_mem:
        parts.append("### Immediate callees (short-term memory)\n" + st_mem)
    if lt_mem:
        parts.append("### Findings on flagged call chains (long-term memory)\n"
                     + lt_mem)
    if chains:
        parts.append("### Call chains reaching this function\n"
                     + "\n".join(chains))
    parts.append(f"### Function under analysis: {func}\n```c\n{source}\n```")
    return "\n\n".join(parts)


def analyse(prompt, model):
    response = client.chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": prompt}],
        temperature=0.6,
        top_p=0.95,
        timeout=3000,
    )
    message = response.choices[0].message
    reasoning = getattr(message, "reasoning_content", "") or ""
    content = message.content or ""
    return reasoning, content


def save(out_dir, func, reasoning, content):
    for sub in ("json", "thinkchain"):
        os.makedirs(os.path.join(out_dir, sub), exist_ok=True)
    with open(os.path.join(out_dir, "thinkchain", f"{func}_thinkchain.txt"),
              "w", encoding="utf-8") as fh:
        fh.write(reasoning or content)
    with open(os.path.join(out_dir, "json", f"{func}_output.json"),
              "w", encoding="utf-8") as fh:
        fh.write(content)


def process_module(folder, rules, model, out_root):
    batch_file = os.path.join(folder, "function_batches.txt")
    rel_file = os.path.join(folder, "function_call_relations.txt")
    if not (os.path.exists(batch_file) and os.path.exists(rel_file)):
        return 0

    batches = read_batches(batch_file)
    relations = read_call_relations(rel_file)
    out_dir = os.path.join(out_root, os.path.basename(folder.rstrip(os.sep)))

    flagged, verdicts, done = {}, {}, 0
    # Batches are processed in order and sequentially within a module: a caller's
    # long-term memory is only correct once its callees have verdicts.
    for index, batch in enumerate(batches, start=1):
        for func in batch:
            source = read_source(folder, func)
            if source is None:
                continue
            st_mem = short_term_memory(func, relations, folder)
            lt_mem, chains = long_term_memory(func, relations, folder,
                                              flagged, verdicts)
            prompt = build_prompt(rules, func, source, st_mem, lt_mem, chains)
            try:
                reasoning, content = analyse(prompt, model)
            except Exception as exc:                      # noqa: BLE001
                print(f"  {func}: inference failed: {exc}", file=sys.stderr)
                continue
            verdict = extract_json(content) or extract_json(reasoning)
            verdicts[func] = verdict or {}
            flagged[func] = is_flagged(content, verdict)
            save(out_dir, func, reasoning, content)
            done += 1
        print(f"  batch {index}/{len(batches)}: {len(batch)} functions "
              f"({sum(flagged.values())} flagged so far)")

    with open(os.path.join(out_dir, "combined_results.json"), "w",
              encoding="utf-8") as fh:
        json.dump({"flagged": flagged, "verdicts": verdicts}, fh,
                  ensure_ascii=False, indent=2)
    return done


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("functions_dir")
    ap.add_argument("prompt_file")
    ap.add_argument("--model", default=os.environ.get("EFIHUNTER_MODEL",
                                                      DEFAULT_MODEL))
    ap.add_argument("--out", default="output")
    args = ap.parse_args()

    if not client.api_key:
        print("set OPENAI_API_KEY (any value for a local server)",
              file=sys.stderr)
        return 1

    with open(args.prompt_file, "r", encoding="utf-8") as fh:
        rules = fh.read().strip()

    modules = [
        root for root, _, files in os.walk(args.functions_dir)
        if "function_batches.txt" in files
    ]
    if not modules:
        print(f"no Harvest output under {args.functions_dir}; run "
              f"harvest/build_callgraph_batches.py first", file=sys.stderr)
        return 1

    total = 0
    for module in modules:
        print(f"{module}:")
        total += process_module(module, rules, args.model, args.out)
    print(f"analysed {total} functions with model {args.model}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
