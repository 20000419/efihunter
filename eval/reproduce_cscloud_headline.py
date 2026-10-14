#!/usr/bin/env python3
"""Recompute archived CSCloud headline metrics without running a model.

Optional --source-db exports the matching historical SQLite run read-only.
No credentials, source code, or response text are included in the compact export.
"""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import statistics

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CSV = ROOT / 'predictions/cscloud2026/headline_predictions.csv'
SOURCE_SHA256 = '5a0e7678ec7322ecd461badf15cde8d9f66252b8876197819047538fda21e78d'
FIELDS = ['run_id', 'identifier', 'trial', 'ground_truth', 'prediction',
          'parseable', 'code_sha256']


def parse_bool(value):
    if value.lower() not in ('true', 'false'):
        raise ValueError('Boolean fields must contain true or false')
    return value.lower() == 'true'


def load_predictions(path):
    with Path(path).open(newline='', encoding='utf-8') as stream:
        rows = list(csv.DictReader(stream))
    if not rows:
        raise ValueError('No predictions')
    seen, labels, code_hashes = set(), {}, {}
    for row in rows:
        row['trial'] = int(row['trial'])
        for field in ('ground_truth', 'prediction', 'parseable'):
            row[field] = parse_bool(row[field])
        key = (row['identifier'], row['trial'])
        if key in seen:
            raise ValueError('Duplicate function/trial key')
        seen.add(key)
        identifier = row['identifier']
        if identifier in labels and labels[identifier] != row['ground_truth']:
            raise ValueError('Ground truth changes across trials')
        if identifier in code_hashes and code_hashes[identifier] != row['code_sha256']:
            raise ValueError('Stored code changes across trials')
        labels[identifier] = row['ground_truth']
        code_hashes[identifier] = row['code_sha256']
    return rows


def score(rows):
    tp = sum(r['ground_truth'] and r['prediction'] for r in rows)
    fp = sum(not r['ground_truth'] and r['prediction'] for r in rows)
    tn = sum(not r['ground_truth'] and not r['prediction'] for r in rows)
    fn = sum(r['ground_truth'] and not r['prediction'] for r in rows)
    def divide(a, b):
        return a / b if b else None
    return dict(records=len(rows), tp=tp, fp=fp, tn=tn, fn=fn,
                accuracy=divide(tp+tn, len(rows)), precision=divide(tp, tp+fp),
                recall=divide(tp, tp+fn), f1=divide(2*tp, 2*tp+fp+fn),
                specificity=divide(tn, tn+fp),
                unparseable=sum(not r['parseable'] for r in rows))


def summarize(rows):
    result = score(rows)
    result['functions'] = len({r['identifier'] for r in rows})
    trials = sorted({r['trial'] for r in rows})
    result['trials'] = len(trials)
    result['per_trial'] = [dict(trial=t, **score([r for r in rows if r['trial']==t]))
                           for t in trials]
    accuracies = [t['accuracy'] for t in result['per_trial']]
    result['trial_accuracy_sample_sd'] = statistics.stdev(accuracies) if len(trials)>1 else None
    return result


def export_source(db_path, output):
    db_path = Path(db_path).resolve()
    if hashlib.sha256(db_path.read_bytes()).hexdigest() != SOURCE_SHA256:
        raise ValueError('This database is not the archived headline source (SHA-256 mismatch)')
    with sqlite3.connect(db_path.as_uri()+'?mode=ro', uri=True) as connection:
        rows = connection.execute(
            "SELECT identifier, trial, reference, content, code FROM result "
            "WHERE dataset='UEFI' AND dataset_type='UEFI' "
            "AND query_type='binary_classification_single_function' "
            "AND prompt_type='2_shot' ORDER BY identifier, trial"
        ).fetchall()
    records = []
    for identifier, trial, reference, content, code in rows:
        truth = json.loads(reference)
        if not isinstance(truth, bool):
            raise ValueError('Expected Boolean ground truth')
        response = content or ''
        records.append(dict(run_id='latest_headline', identifier=identifier,
            trial=trial, ground_truth=truth,
            prediction='vulnerable: yes' in response.lower(),
            parseable=bool(re.search(r'VULNERABLE\s*:\s*(YES|NO)', response, re.I)),
            code_sha256=hashlib.sha256(code.encode('utf-8')).hexdigest()))
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open('w', newline='', encoding='utf-8') as stream:
        writer = csv.DictWriter(stream, fieldnames=FIELDS, lineterminator='\n')
        writer.writeheader()
        writer.writerows(records)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--csv', type=Path, default=DEFAULT_CSV)
    parser.add_argument('--source-db', type=Path, help='Re-export the exact historical database')
    args = parser.parse_args()
    if args.source_db:
        export_source(args.source_db, args.csv)
    print(json.dumps(summarize(load_predictions(args.csv)), indent=2))


if __name__ == '__main__':
    main()
