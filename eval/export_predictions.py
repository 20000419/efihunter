#!/usr/bin/env python3
"""Export per-function prediction records from the run databases.

Each experimental configuration is logged to a SQLite `query_result.db` with one
row per (function, query type, shot setting). This script exports those rows into
CSV for inspection of available fixed outputs. This legacy regex exporter omits
explicit trial identifiers; it is not the authoritative CSCloud headline export.
Use reproduce_cscloud_headline.py for the verified headline and its literal
scoring rule, without re-running non-deterministic LLM inference.

Two levels are produced:

  index  : identifier, dataset, query_type, prompt_type, ground_truth, predicted
           (compact; one file per configuration)
  traces : the above plus the model's full response text, i.e. the reasoning
           trace behind each verdict (large; gzip-compressed)

Usage:
    python export_predictions.py <runs_dir> <out_dir> [--traces]

where <runs_dir> contains one subdirectory per configuration, each holding a
`query_result.db`.
"""
import argparse
import csv
import gzip
import os
import re
import sqlite3
import sys

VULN_RE = re.compile(r"VULNERABLE\s*:\s*(YES|NO)", re.I)


def extract_verdict(text):
    """Recover the binary verdict from a model response, '' if not parseable."""
    if not text:
        return ""
    m = VULN_RE.search(text)
    if m:
        return "vulnerable" if m.group(1).upper() == "YES" else "safe"
    return ""


def export(db_path, out_base, with_traces=False):
    conn = sqlite3.connect(db_path)
    rows = conn.execute(
        "SELECT identifier, dataset, dataset_type, query_type, prompt_type, "
        "reference, content FROM result"
    ).fetchall()

    index_path = out_base + ".csv"
    with open(index_path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["identifier", "dataset", "dataset_type", "query_type",
                    "prompt_type", "ground_truth", "predicted"])
        for identifier, ds, dst, qt, pt, ref, content in rows:
            w.writerow([identifier, ds, dst, qt, pt, ref, extract_verdict(content)])

    n_traces = 0
    if with_traces:
        trace_path = out_base + "_traces.csv.gz"
        with gzip.open(trace_path, "wt", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["identifier", "dataset", "query_type", "prompt_type",
                        "ground_truth", "model_response"])
            for identifier, ds, dst, qt, pt, ref, content in rows:
                w.writerow([identifier, ds, qt, pt, ref, content])
                n_traces += 1
    return len(rows), n_traces


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("runs_dir", help="directory containing <config>/query_result.db")
    ap.add_argument("out_dir", help="destination directory for the CSV exports")
    ap.add_argument("--traces", action="store_true",
                    help="also export full model responses (gzip, large)")
    args = ap.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)
    total = 0
    for entry in sorted(os.listdir(args.runs_dir)):
        db = os.path.join(args.runs_dir, entry, "query_result.db")
        if not os.path.isfile(db):
            continue
        out_base = os.path.join(args.out_dir, entry.replace(" ", "_"))
        n, t = export(db, out_base, args.traces)
        total += n
        print(f"{entry}: {n} records" + (f" (+{t} traces)" if t else ""))
    print(f"total: {total} prediction records")
    return 0


if __name__ == "__main__":
    sys.exit(main())
