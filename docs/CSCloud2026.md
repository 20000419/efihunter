# CSCloud 2026 revision and experiment provenance

The accompanying paper, *Dynamic Call Context: LLM-Driven Vulnerability Detection
in Closed-Source Binaries*, is accepted as a Regular Paper at IEEE CSCloud 2026.
The tag `cscloud2026-revision-20261014.1` identifies this implementation and archive
update. Final publication metadata is pending.

## Current implementation

The analyzer injects the complete rule rubric, includes immediate-callee code,
and follows previously flagged callee chains for historical findings. There is
no query-time top-k rule retrieval and no automated symbolic Track filter.

The context traversal uses an explicit stack and checks a per-query visited set
before expanding a function. Each retained function contributes one representative
path; shared descendants do not generate all possible paths. A clean function
stops its branch. Batch members read a common earlier-batch snapshot, including
when the driver processes them serially. The scheduler remains a cycle-breaking
heuristic; it does not guarantee an ordering for every original call edge.

The revision fixes software behavior. It does not claim that revised code
generated existing model predictions or that the historical inference was rerun.

## Headline records

`predictions/cscloud2026/manifest.json` identifies the original database by SHA-256
and states the exact row selection. `headline_predictions.csv` contains the
binary verdicts, labels, explicit trial identifiers, and hashes of the stored
code. It contains no code bodies, credentials, or model-response text.

The selected archive contains 300 function identifiers, including 150 positive
and 150 negative functions, evaluated in five trials. The 1,500 rows are repeated
measurements of those functions, not 1,500 independent functions.

| Metric | Recomputed value |
|---|---:|
| Accuracy | 0.696667 |
| Precision | 0.641963 |
| Recall | 0.889333 |
| F1 | 0.745668 |
| Specificity | 0.504000 |

The confusion counts are TP=667, FP=372, TN=378, and FN=83. The scorer follows
the historical evaluation rule: a case-insensitive literal `VULNERABLE: YES`
anywhere in the response is positive; other responses are negative. The
`parseable` field is diagnostic and does not change that rule.

Run from the repository root, without model access or third-party packages:

```sh
python eval/reproduce_cscloud_headline.py
python -m unittest discover -s tests -v
```

The expected aggregates and trial metrics are in `metrics.json`. A holder of the
original database can regenerate the compact export with:

```sh
python eval/reproduce_cscloud_headline.py --source-db /path/to/latest/query_result.db --csv /path/to/headline_predictions.csv
```

The exporter requires the manifest's database hash and opens SQLite read-only.
It refuses a different database instead of identifying runs by a folder name.

## Historical scope

The raw database model label is `qwen3-30b-a3b-deepthink`. It is recorded as
metadata, not used to infer an exact checkpoint or thinking-mode setting. Full
request snapshots and launch settings are unavailable. Metric recomputation from
saved verdicts is supported; exact replay of the historical prompt pipeline is
not established. Independently attributable short-only and long-only runs are
not supplied, so this release makes no separate numerical memory-gain claim.

Legacy prediction files remain unchanged. The earlier
`predictions/qwen3-30b-dcc-nothink.csv` corresponds to a different run from the
headline archive. Legacy exports do not retain an explicit trial column. They
should not be silently relabeled as the headline or treated as a complete
controlled component experiment. The legacy regex exporter is distinct from
the literal scoring rule documented above.

## EDK2 case

The EDK2 review started from a maintainer commit and supplemented the affected
code with directly called functions. A commit can involve several files and
functions; this initial context differs from the analyzer's single-function
input. The disclosure record does not preserve the full discovery request or
identify the exact analysis-entry commit. Affected-version and original-
introduction commits must not be substituted for that missing identifier.

The correction is publicly merged in
[TianoCore PR #12950](https://github.com/tianocore/edk2/pull/12950), dated
September 22, 2026, with merge commit
`c76be9ac2cef97bab3e20c1424c1ad90de582f70`. This is remediation evidence, not a
controlled attribution of the discovery to one memory component.
