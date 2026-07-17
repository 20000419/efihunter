# EFIhunter — Dynamic Call Context (DCC) Framework for LLM-Driven Binary Vulnerability Detection

EFIhunter detects inter-procedural memory-corruption vulnerabilities in
closed-source binary firmware (and general C/C++) by wrapping a self-hosted
open-weight LLM in a static-analysis harness: a dual-memory context architecture
plus a retrieval-augmented domain-rule layer. It is designed for **air-gapped**
use — proprietary binaries never leave the analyst's machine.

This repository accompanies the paper *"Closing the Context and Domain-Knowledge
Gaps: A Dynamic Call Context Framework for LLM-Driven Memory-Corruption Detection
in Closed-Source Binaries."*

## Layout
```
efihunter/
  harvest/    IDA-headless extraction, call-graph recovery, cycle-aware batching (Algorithm 1)
              extract-ida.py, process_folder.py, linjie.py
  analyze/    context construction + inference driver (Algorithm 2)
              analyze_smm.py, prompts/ (prompt.txt zh, prompt_english.txt en)
  rules/      the five SMM rule classes + RAG knowledge base (rules_v3_enhanced.txt)
  track/      VCFG construction + symbolic-validation stub            [to add]
  eval/       metric + scoring scripts (eval.py, utils.py)
  benchmark/  efi-vuln: patch-verified pairs + CWE labels             [link below]
  example/    one worked SMM module: input + verdicts + reasoning     [to add]
```

## Requirements
- Python 3.10+, `openai` client
- IDA Pro (headless) with the efiXplorer plugin for the Harvest phase
- A self-hosted OpenAI-compatible endpoint serving an open-weight model
  (default config targets QWEN3-30B-A3B in non-thinking mode)
- `angr` for control-flow recovery (Harvest)

## Configuration (no secrets in code)
Credentials and endpoints are read from the environment:
```bash
export OPENAI_API_KEY="<your key or any string for a local server>"
export OPENAI_BASE_URL="http://<your-llm-host>:<port>/v1/"
```

## Quick start
```bash
# 1. Harvest: decompile + build call graph + batch
python harvest/process_folder.py  <firmware_module_dir>
# 2. Analyze: classify each function with rules + dual memory
python analyze/analyze_smm.py     <batched_functions>  <call_relations>
# 3. Evaluate against labels
python eval/eval.py               <predictions>  <ground_truth>
```

## Benchmark
`efi-vuln` (150 patch-verified vulnerability pairs, 5 types, CWE-annotated) is
released separately at the anonymized mirror in the paper and will be linked here
on de-anonymization.

## Responsible disclosure
The zero-days reported in the paper (EDK2, SQLite, Deno) were disclosed to the
respective vendors and are fixed or under coordinated disclosure. Use EFIhunter
only on binaries you are authorized to analyze.

## License
Released under the MIT License (see `LICENSE`).
