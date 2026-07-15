# Frozen Detection Governance

This document describes the current public detection-metric and frozen-governance release
contracts. It is an operational control, not a claim that the committed corpora represent an
external population.

## Current Artifacts and Results

The public corpus is `tests/corpus`. The frozen gate reads only the committed
`tests/heldout/frozen-governance.zip` whose digest is pinned by
`tests/heldout/frozen-governance.sha256`; the frozen source used by the reviewed update procedure is
under `tests/heldout/source`.

| Corpus | Cases | Labels / predictions | Release gates | Current result |
|---|---:|---:|---:|---|
| Public training/calibration + validation | 45 (34 + 11) | 1,916 / 1,916 | 19 | PASS, 19/19 |
| Frozen governance | 11 | 2,193 / 2,193 | 19 | PASS, 19/19 |

The public result also has zero parser, completeness, invariance, graph, and regression failures.
Its current corpus fingerprint is
`6f05f32528f5a55e6777236ee3a8f37c066cb5e40220ce0c92820c0d150ef8bb`. These values are
reproducible results for the committed fixtures only; they are not estimates of universal
precision or recall.

## Purpose and Statistical Limits

The frozen archive is frozen and independently partitioned from the public training/calibration
and validation cases. It is visible in the repository. It is not
secret, unseen, private, or evidence of performance on an external population.

Across the public and frozen sets, the rounded 60/20/20 allocation is 34/11/11. Validation rejects
case, semantic-group, vendor-family, exact-source, and lexical/structural near-clone overlap across
the public and governance partitions. It also rejects near clones between governance cases,
including short sources.

Metric positive/negative case counts count manifest cases. They are not group-aware or
vendor-family-aware sample counts. In particular, all frozen governance cases share one frozen
vendor-family identity, so the 11 cases must not be presented as 11 independent vendor samples.
Group and vendor metadata is a leakage and partition gate, not an estimator of statistical
independence. Repeated generated labels also do not turn one fixture family into independent
real-world observations. Wilson lower bounds and minimum sample gates remain useful corpus guards,
but a corpus precision/recall of 1.0 does not imply 100% performance outside these fixtures.

## Workflow Trigger Contract

The workflow itself is triggered by pull requests, pushes to `main`, `v*` tag pushes, the weekly
schedule, `release: published`, and manual workflow dispatch. The public metric command
`python scripts/run_detection_metrics.py --corpus tests/corpus --fail-on-regression` is in the
unconditional `quality` job, so it runs on every one of those workflow triggers.

The frozen job is intentionally conditional:

| Workflow trigger | Public metrics | Frozen governance | Operational role |
|---|---|---|---|
| Pull request | Always | No | Public regression feedback |
| Push to `main` | Always | No | Public branch regression feedback |
| Push of a `v*` tag | Always | Yes | Pre-publication governance run |
| Weekly schedule (`17 3 * * 1`) | Always | Yes | Periodic drift check |
| `release: published` | Always | Yes | Post-publication recheck only |
| Manual dispatch, input false | Always | No | Public/manual verification |
| Manual dispatch, `run_heldout_governance=true` | Always | Yes | Explicit frozen verification |

A `v*` tag run is the release steward's pre-publication gate. Publish a release only after that tag
run passes. The repository does not contain an automated publishing workflow that prevents a steward
from publishing early, so this sequencing remains an operator responsibility. The
`release: published` event happens after publication and repeats both public and frozen checks; it
cannot retroactively serve as the publication blocker.

## Frozen Artifact Boundary

Only the committed archive and checksum are supported by the frozen runner. There is no URL/digest secret override:
credentials with the same authority as a remote archive cannot establish artifact authenticity. A
future external artifact requires a separately reviewed signature, protected approval, and key
management design.

The frozen job prints only aggregate schema, split, case count, pass/fail, and a bounded reason. It
does not upload extracted corpus content or label diagnostics. This limits accidental log
disclosure, but it does not make repository-visible data confidential. The public metric job emits
the detailed metrics for the already-public corpus and is not subject to the frozen job's bounded
output projection.

## Reviewed Update Procedure

Stop after any failed command. Never edit the ZIP, checksum, metadata, or baseline by hand.

```bash
python scripts/build_heldout_governance_corpus.py
python scripts/run_detection_metrics.py --corpus tests/heldout/source/corpus
python scripts/update_detection_baseline.py --corpus tests/heldout/source/corpus --output tests/heldout/source/corpus/baseline.json
python scripts/update_heldout_governance_artifact.py --replace
python scripts/run_heldout_detection_gate.py run
python -m pytest -q tests/test_scripts/test_heldout_detection_gate.py tests/test_scripts/test_heldout_governance_artifact.py
```

Review the source, manifest labels, gate/baseline fingerprint, metadata, ZIP, checksum, public
partition identity, group/vendor assignment, and aggregate metric diff together. The artifact
updater validates identities and clone policy, executes the complete gate before publication, then
transactionally replaces metadata, ZIP, and checksum. CI never updates these files automatically.
