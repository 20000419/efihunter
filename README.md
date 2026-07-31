# EFIhunter — Dynamic Call Context (DCC) Framework

EFIhunter detects inter-procedural memory-corruption vulnerabilities in
closed-source binary firmware (and general C/C++) by wrapping a self-hosted
open-weight LLM in a static-analysis harness: cycle-aware callee-first scheduling
of the call graph, a dual memory that carries a function's callees and the
verdicts along flagged call chains, and a curated domain-rule rubric. It targets
**air-gapped** use — proprietary binaries never leave the analyst's machine.

Accompanies the paper *"Dynamic Call Context: LLM-Driven Vulnerability Detection
in Closed-Source Binaries."*

## Layout
```
efihunter/
  harvest/      build_callgraph_batches.py  call graph + cycle-aware batching (Algorithm 1)
                extract-ida.py, process_folder.py  IDA/efiXplorer extraction
                adjacency_degrees.py, clean_json.py, reorganize_extracted.py
  analyze/      analyze_dcc.py              dual-memory context + inference (Algorithm 2)
                analyze_nomemory_baseline.py  the no-memory ablation baseline
                prompts/                    prompt.txt (zh), prompt_english.txt (en)
  rules/        rules_v3_enhanced.txt       the five SMM rule classes / rubric
  eval/         eval.py, utils.py           scoring
                export_predictions.py       regenerate the CSVs below from run DBs
  predictions/  68,492 per-function prediction records, 11 configurations
  example/      SmmLockBox/                 a worked SMM module: verdicts + reasoning traces
  benchmark/    pointer to the efi-vuln repository (see below)
  track/        design notes only — the symbolic filter is NOT automated
```

## What is and is not implemented

Implemented and used for every number in the paper: the Harvest scheduler,
short-term memory (immediate-callee pseudocode), long-term memory (verdicts along
chains of consecutively flagged callees, terminating at the first clean one), and
the rule rubric, which is injected in full at the head of each prompt.

**Not** implemented: query-time top-*k* rule retrieval (the rubric is small enough
to carry whole at this scale), and the Track phase (VCFG + symbolic validation) —
the validation of the disclosed vulnerabilities was manual. All reported figures
are raw Analyze-phase output with no downstream filtering.

## Requirements
- Python 3.10+, `openai` client, `networkx`
- IDA Pro (headless) with the efiXplorer plugin, for the extraction step
- An OpenAI-compatible endpoint serving an open-weight model
  (default: `qwen3-30b-a3b` in non-thinking mode)

## Configuration (no secrets in code)
```bash
export OPENAI_API_KEY="<your key, or any string for a local server>"
export OPENAI_BASE_URL="http://<your-llm-host>:<port>/v1/"
```

## Quick start
```bash
# 1. Harvest: call graph + callee-first batches (writes function_batches.txt
#    and function_call_relations.txt next to the extracted .c files)
python harvest/build_callgraph_batches.py  <extracted_functions_dir>

# 2. Analyze: classify each function with the rubric + dual memory
python analyze/analyze_dcc.py  <extracted_functions_dir>  rules/rules_v3_enhanced.txt

# 3. Score, or regenerate the paper's per-function records
python eval/eval.py                <predictions>  <ground_truth>
python eval/export_predictions.py  <runs_dir>  predictions/
```

## Reproducing the paper's tables
`predictions/*.csv` hold one row per (function, query type, shot setting, trial)
for all 11 configurations — 68,492 records. Because LLM inference is
non-deterministic, the tables are reproducible from these fixed outputs rather
than from a fresh run. Label rule: a response asserting `VULNERABLE: YES` is a
positive prediction; anything else, including an unparseable response, is
negative.

## Benchmark
`efi-vuln` — 150 patch-verified vulnerability pairs (300 function-level C
snippets) with CWE annotations and provenance to public advisories:
**https://github.com/20000419/efi-vuln**

## Responsible disclosure
The vulnerabilities reported in the paper (EDK2, SQLite, Deno) were disclosed to
the respective vendors and are fixed or under coordinated disclosure. Use
EFIhunter only on binaries you are authorized to analyze.

## License
MIT (see `LICENSE`).
