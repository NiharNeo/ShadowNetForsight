"""Evaluate exported forecast windows against hash-bound, curator-supplied labels.

This measures supplied artifacts; it does not authenticate labels or certify a model.
"""
import argparse
import hashlib
import json
import math
from pathlib import Path
import re


def number(value, name, lower=0, upper=float('inf')):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not lower <= value <= upper:
        raise ValueError(f'{name} must be a finite number between {lower} and {upper}')
    return float(value)


def fingerprint(value, name):
    if not isinstance(value, str) or not re.fullmatch(r'[0-9a-f]{64}', value):
        raise ValueError(f'{name} requires a lowercase SHA-256 fingerprint')
    return value


def metrics(rows):
    tp = sum(y == 1 and p for y, p in rows)
    fp = sum(y == 0 and p for y, p in rows)
    fn = sum(y == 1 and not p for y, p in rows)
    tn = sum(y == 0 and not p for y, p in rows)
    ratio = lambda a, b: a / b if b else None
    return {'support': len(rows), 'tp': tp, 'fp': fp, 'fn': fn, 'tn': tn,
            'precision': ratio(tp, tp + fp), 'recall': ratio(tp, tp + fn),
            'false_positive_rate': ratio(fp, fp + tn), 'f1': ratio(2 * tp, 2 * tp + fp + fn)}


def evaluate(report, labels):
    if not isinstance(report, dict) or report.get('schema_version') != 1 or not isinstance(labels, dict):
        raise ValueError('Expected a schema-version-1 analysis export and a JSON label object')
    capture = report.get('capture')
    if not isinstance(capture, dict):
        raise ValueError('Analysis export requires capture metadata')
    digest = fingerprint(capture.get('capture_sha256'), 'Capture')
    checkpoint = fingerprint(capture.get('checkpoint_sha256'), 'Checkpoint')
    entries = labels.get('captures', [labels])
    if not isinstance(entries, list) or len(entries) > 1000 or not all(isinstance(e, dict) for e in entries):
        raise ValueError('Expected at most 1000 labelled capture entries')
    matches = [entry for entry in entries if entry.get('sha256') == digest]
    if len(matches) != 1:
        raise ValueError('Labels must match exactly one capture SHA-256 from the analysis export')
    entry = matches[0]
    duration = number(entry.get('duration_seconds'), 'Capture duration', 0.000001)
    timeline = entry.get('timeline')
    if not isinstance(timeline, list) or not 1 <= len(timeline) <= 1000:
        raise ValueError('A timeline of 1–1000 contiguous labelled intervals is required')
    intervals = []
    end = 0.0
    for item in timeline:
        if not isinstance(item, dict):
            raise ValueError('Timeline intervals must be objects')
        start = number(item.get('start_seconds'), 'Interval start', 0, duration)
        stop = number(item.get('end_seconds'), 'Interval end', 0, duration)
        label = item.get('label')
        if type(label) is not int or label not in (0, 1) or start != end or stop <= start:
            raise ValueError('Timeline must cover the capture without gaps/overlap, using integer labels 0 or 1')
        # Merge adjacent intervals with identical binary labels; stage changes are not new attacks.
        if intervals and intervals[-1][2] == label:
            intervals[-1] = (intervals[-1][0], stop, label)
        else:
            intervals.append((start, stop, label))
        end = stop
    if end != duration:
        raise ValueError('Timeline must end at duration_seconds')
    updates = report.get('updates')
    if not isinstance(updates, list) or not 1 <= len(updates) <= 720:
        raise ValueError('Analysis export must contain 1–720 retained updates')
    horizon = {offset: {'raw': [], 'accepted': [], 'rejected_attack': 0, 'rejected_benign': 0,
                        'outside_observed_capture': 0, 'ambiguous_label_windows': 0} for offset in (5, 10, 15)}
    previous = -1
    for update in updates:
        if not isinstance(update, dict):
            raise ValueError('Each replay update must be an object')
        elapsed = number(update.get('elapsed_seconds'), 'Elapsed seconds', 0, duration)
        if elapsed <= previous:
            raise ValueError('Replay updates must have strictly increasing elapsed timestamps')
        previous = elapsed
    observed_end = previous
    for update in updates:
        inference = update.get('inference', {})
        if not isinstance(inference, dict):
            raise ValueError('Inference must be an object')
        if inference.get('model_ready') is not True:
            continue
        forecast = inference.get('forecast')
        if not isinstance(forecast, list) or len(forecast) != 3:
            raise ValueError('Model-ready updates require exactly three forecast horizons')
        uncertainty = inference.get('uncertainty', {})
        contract = inference.get('feature_compatibility', {})
        if not isinstance(uncertainty, dict) or not isinstance(contract, dict):
            raise ValueError('Invalid uncertainty or feature compatibility metadata')
        accepted = uncertainty.get('status') == 'in_distribution' and contract.get('compatible') is True
        seen = set()
        for point in forecast:
            if not isinstance(point, dict):
                raise ValueError('Forecast points must be objects')
            offset = number(point.get('offset_seconds'), 'Forecast horizon', 5, 15)
            if offset not in horizon or offset in seen:
                raise ValueError('Forecast horizons must be uniquely 5, 10 and 15 seconds')
            seen.add(offset)
            risk = number(point.get('risk'), 'Risk percentage', 0, 100)
            threshold = number(point.get('threshold'), 'Threshold percentage', 0, 100)
            start = update['elapsed_seconds'] + offset - 5
            stop = start + 5
            bucket = horizon[offset]
            if stop > observed_end:
                bucket['outside_observed_capture'] += 1
                continue
            truth = next((label for a, b, label in intervals if a <= start and stop <= b), None)
            if truth is None:
                bucket['ambiguous_label_windows'] += 1
                continue
            row = (truth, risk >= threshold)
            bucket['raw'].append(row)
            if accepted:
                bucket['accepted'].append(row)
            else:
                bucket['rejected_attack' if truth else 'rejected_benign'] += 1
    results = []
    for offset, bucket in horizon.items():
        total = len(bucket['raw'])
        results.append({'offset_seconds': offset, 'raw_classifier': metrics(bucket['raw']),
                        'accepted_only': metrics(bucket['accepted']),
                        'rejection_rate': (total - len(bucket['accepted'])) / total if total else None,
                        **{k: v for k, v in bucket.items() if k not in ('raw', 'accepted')}})
    return {'schema_version': 1, 'capture_sha256': digest, 'checkpoint_sha256': checkpoint,
            'label_document_sha256': hashlib.sha256(json.dumps(labels, sort_keys=True, allow_nan=False).encode()).hexdigest(),
            'label_provenance': labels.get('status', 'curator_supplied_unverified'),
            'observed_until_seconds': observed_end, 'capture_duration_seconds': duration,
            'retained_updates': len(updates), 'omitted_older_updates': report.get('omitted_older_updates', 0),
            'horizons': results, 'claims_allowed': False,
            'limitations': ['Supplied exports and labels are not authenticated or independently verified.',
                           'Metrics use exported rounded scores and thresholds; no threshold fitting is performed.',
                           'Rejected windows are not counted as correct benign predictions.',
                           'Accepted-only results require both in-distribution status and matching extraction contracts; they are not operational alerts.',
                           'Targets use complete five-second future windows. Mixed-label windows and targets beyond processed capture history are excluded.',
                           'Retained export windows may overlap; these counts do not represent independent attack sessions.']}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--labels', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = evaluate(json.loads(args.report.read_text()), json.loads(args.labels.read_text()))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, allow_nan=False) + '\n')
    print(args.output)
