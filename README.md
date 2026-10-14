# EFIhunter — Dynamic Call Context (DCC) Framework

EFIhunter detects inter-procedural memory-corruption vulnerabilities in
closed-source binary firmware (and general C/C++) by wrapping a self-hosted
open-weight LLM in a static-analysis harness: cycle-aware callee-first scheduling
of the call graph, a dual memory that carries a function's callees and the
verdicts along flagged call chains, and a curated domain-rule rubric. It supports local, **air-gapped** analysis when the inference endpoint is hosted
within the analyst's environment. Endpoint configuration determines where code is sent.

Accompanies the paper *"Dynamic Call Context: LLM-Driven Vulnerability Detection
in Closed-Source Binaries."* **Accepted as a Regular Paper at IEEE CSCloud 2026.**
Publication DOI and proceedings metadata will be added when available.

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
  predictions/  legacy prediction exports (preserved)
                cscloud2026/               verified headline export and provenance
  tests/        offline graph and archived-metric checks
  docs/         CSCloud2026.md              release and evidence notes
  example/      SmmLockBox/                 a worked SMM module: verdicts + reasoning traces
  benchmark/    pointer to the efi-vuln repository (see below)
  track/        design notes only — the symbolic filter is NOT automated
```

## What is and is not implemented

The current implementation provides a cycle-aware scheduler, immediate-callee
pseudocode, stored findings along flagged callee chains, and the complete rule
rubric in each prompt. The context builder visits each retained function once
and records one representative path. Each batch reads an earlier-batch snapshot;
findings from a peer in the same batch do not enter its input.

Query-time top-k rule retrieval and the Track symbolic-validation stage are not
implemented. Flag gating reduces context but is not a fixed token-budget policy.
The tool prioritizes candidates for human review rather than reliably recognizing
patched functions. The archived headline specificity is 0.504.

Historical predictions are separate from the current implementation. They permit
metric recomputation, but do not establish that every historical run used all
current components. See [experiment provenance](docs/CSCloud2026.md).

## Requirements
- Python 3.10+, `openai` client, `networkx`
- IDA Pro (headless) with the efiXplorer plugin, for the extraction step
- An OpenAI-compatible endpoint serving an open-weight model
  (default model alias: `qwen3-30b-a3b`; configure any thinking-mode control
  on the serving endpoint explicitly)

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

# 3. Recompute the verified CSCloud headline from archived outputs (no model call)
python eval/reproduce_cscloud_headline.py

# 4. Run offline correctness checks (standard library only)
python -m unittest discover -s tests -v
```

## Recomputing the CSCloud headline

`predictions/cscloud2026/` contains 1,500 binary records for 300 function
identifiers and five trials, plus a source manifest and expected metrics.
The standard-library scorer above reproduces accuracy **0.696667**, F1
**0.745668**, precision **0.641963**, recall **0.889333**, and specificity **0.504**.
These are fixed-output metrics, not a new inference experiment.

Legacy `predictions/*.csv` files remain unchanged. In particular, the older
`qwen3-30b-dcc-nothink.csv` is a different run and is not the source of the 0.697
headline. Legacy exports omit explicit trial identifiers; the new compact export
preserves them. The archived settings do not support separate numerical claims
for short-term and long-term memory gains.

## Benchmark
`efi-vuln` — 150 patch-verified vulnerability pairs (300 function-level C
snippets) with CWE annotations and provenance to public advisories:
**https://github.com/20000419/efi-vuln**

## Case studies and remediation

The EDK2 investigation used a maintainer commit as the initial review unit,
which can include several files and functions, and supplemented it with directly
called functions. This source-review workflow applies the DCC context-selection
idea; it is distinct from automatically retrieving callers for a single function.
The original discovery request is not available for component-level attribution.

Our EDK2 correction was merged upstream in
[PR #12950](https://github.com/tianocore/edk2/pull/12950) on September 22, 2026
(commit `c76be9ac2cef97bab3e20c1424c1ad90de582f70`). The paper also discusses
SQLite and Deno findings. Historical discovery evidence is not replaced by the
new software-correctness tests.

## Citation

The accompanying paper is accepted at IEEE CSCloud 2026; it is not yet identified
by a final DOI or proceedings page range. Authors and software metadata are in
[CITATION.cff](CITATION.cff). The `cscloud2026-revision-20261014` tag identifies
this repository revision associated with the manuscript update; it is not a
claim that this code generated the historical predictions.

## License
MIT (see `LICENSE`).
