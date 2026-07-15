"""Strict labeled-corpus metrics for BundleInspector detectors.

The runner intentionally treats every unmatched prediction in an evaluated category as a false
positive. Labels and predictions are matched one-to-one, so duplicate findings cannot inflate
recall. Release gates include sample-size checks and Wilson confidence bounds; a small or selectively
labeled corpus therefore cannot report a misleading green result.
"""

from __future__ import annotations

import hashlib
import json
import math
from collections import Counter, defaultdict
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from bundleInspector.config import Config
from bundleInspector.correlator.graph import CorrelationGraph, Correlator
from bundleInspector.parser.ir_builder import build_ir
from bundleInspector.parser.js_parser import parse_js
from bundleInspector.parser.tree_sitter_backend import LanguageHint
from bundleInspector.rules.base import AnalysisContext
from bundleInspector.rules.engine import RuleEngine
from bundleInspector.storage.models import Category, Edge, EdgeType, Finding

CANONICALIZER_VERSION = 2
MAX_WILSON_MARGIN = 0.03
BASELINE_SCHEMA_VERSION = 1
RELEASE_PROFILE = "bundleinspector-detection-release-v1"
MAX_VALIDATION_COUNT = (1 << 63) - 1
SUPPORTED_LANGUAGES = frozenset({"javascript", "typescript", "jsx", "tsx", "minified"})
SUPPORTED_CATEGORIES = frozenset(category.value for category in Category)
SUPPORTED_EDGE_TYPES = frozenset(edge_type.value for edge_type in EdgeType)
SUPPORTED_CORPUS_SUFFIXES = frozenset({".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"})
RELEASE_GATE_KEYS = frozenset({
    "secret/aws_access_key",
    "secret/potential_secret",
    "endpoint",
    "endpoint/api_endpoint",
    "contract/method",
    "contract/headers",
    "contract/auth",
    "contract/query_params",
    "contract/body",
    "endpoint/client_route",
    "sink/taint_flow@confirmed",
    "sink/taint_flow@probable",
    "sink/dom_html_sink",
    "location",
    "domain",
    "flag",
    "debug",
    "upload",
    "endpoint/webpack_named_chunk",
})
RELEASE_BASELINE_METRIC_KEYS = RELEASE_GATE_KEYS | frozenset({"secret", "sink"})
_BASELINE_FIELDS = frozenset({
    "schema_version",
    "profile",
    "canonicalizer_version",
    "corpus_fingerprint",
    "gate_profile_fingerprint",
    "required_gate_keys",
    "case_count",
    "label_count",
    "prediction_count",
    "metrics",
    "invariants",
    "graph_observations",
})
_BASELINE_METRIC_FIELDS = frozenset({
    "tp",
    "fp",
    "fn",
    "tn",
    "precision",
    "recall",
    "f1",
    "precision_wilson_lower",
    "recall_wilson_lower",
    "f1_wilson_lower",
    "positive_case_count",
    "negative_case_count",
})
_BASELINE_INVARIANT_FIELDS = frozenset({
    "failed_gate_count",
    "forbidden_hit_count",
    "completeness_failure_count",
    "parser_failure_count",
    "invariance_failure_count",
    "graph_failure_count",
})
_BASELINE_GRAPH_FIELDS = frozenset({
    "edge_count",
    "cluster_count",
    "edge_types",
    "semantic_sha256",
})
_LANGUAGE_HINTS: Mapping[str, LanguageHint] = {
    "javascript": "javascript",
    "typescript": "typescript",
    "jsx": "jsx",
    "tsx": "tsx",
    "minified": "javascript",
}

_ITEM_FIELDS = frozenset({
    "category",
    "value",
    "subtype",
    "method",
    "line",
    "line_tolerance",
    "contract",
    "metadata",
    "expected_state",
})
_CASE_FIELDS = frozenset({
    "case_id",
    "asset",
    "language",
    "parser_expectation",
    "labels",
    "forbidden",
    "evaluated_categories",
    "evaluated_subtypes",
    "negative_opportunities",
    "completeness",
    "graph",
    "semantic_group",
    "tags",
})
_COMPLETENESS_FIELDS = frozenset({"must_not_be_partial"})
_GRAPH_FIELDS = frozenset({
    "must_not_truncate",
    "required_edge_types",
    "min_edges",
    "permutation_invariant",
})
_CONTRACT_FIELDS = frozenset({"method", "headers", "auth", "query_params", "body"})
_AUTH_FIELDS = frozenset({"scheme", "in"})
_BODY_FIELDS = frozenset({"kind", "shape"})
_GATE_FIELDS = frozenset({
    "name",
    "key",
    "precision",
    "recall",
    "f1",
    "min_positives",
    "min_negatives",
    "min_positive_cases",
    "min_negative_cases",
    "hard_zero_fp",
    "hard_zero_fn",
    "wilson_margin",
})


class CorpusError(ValueError):
    """Raised when corpus data is ambiguous, unsafe, or malformed."""


class _StrictJSONError(ValueError):
    """Internal marker for JSON constructs that Python accepts but RFC 8259 rejects."""


def _strict_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _StrictJSONError(f"duplicate object key {key!r}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> Any:
    raise _StrictJSONError(f"non-finite number {value!r} is not valid JSON")


def _parse_finite_json_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise _StrictJSONError(f"non-finite number {value!r} is not valid JSON")
    return parsed


def _load_strict_json(text: str, location: str) -> Any:
    try:
        return json.loads(
            text,
            object_pairs_hook=_strict_json_object,
            parse_constant=_reject_json_constant,
            parse_float=_parse_finite_json_float,
        )
    except json.JSONDecodeError as exc:
        raise CorpusError(f"{location}: invalid JSON: {exc.msg}") from exc
    except _StrictJSONError as exc:
        raise CorpusError(f"{location}: invalid JSON: {exc}") from exc


@dataclass(frozen=True)
class ExpectedItem:
    """One expected or forbidden prediction."""

    category: str
    value: str
    subtype: str = ""
    method: str = ""
    line: int | None = None
    line_tolerance: int = 0
    contract: Mapping[str, Any] = field(default_factory=dict)
    metadata: Mapping[str, Any] = field(default_factory=dict)
    expected_state: str = "kept"


@dataclass(frozen=True)
class GraphExpectation:
    """Strict graph quality gates for one labeled-corpus case."""

    must_not_truncate: bool = False
    required_edge_types: tuple[EdgeType, ...] = ()
    min_edges: int = 0
    permutation_invariant: bool = False


@dataclass(frozen=True)
class CorpusCase:
    """Validated manifest case."""

    case_id: str
    asset: Path
    asset_identity: str
    asset_fingerprint: str
    language: str
    labels: tuple[ExpectedItem, ...]
    forbidden: tuple[ExpectedItem, ...]
    evaluated_categories: tuple[str, ...]
    evaluated_subtypes: Mapping[str, tuple[str, ...]]
    negative_opportunities: Mapping[str, int]
    parser_expectation: str
    must_not_be_partial: bool
    graph: GraphExpectation | None
    semantic_group: str
    tags: tuple[str, ...]


@dataclass(frozen=True)
class Prediction:
    """Canonical metric projection of a finding."""

    category: str
    subtype: str
    value: str
    method: str
    line: int
    contract: Mapping[str, Any]
    metadata: Mapping[str, Any]
    finding_id: str

    @classmethod
    def from_finding(cls, finding: Finding) -> Prediction:
        metadata = finding.metadata if isinstance(finding.metadata, dict) else {}
        raw_contract = metadata.get("contract") or metadata.get("request_contract") or {}
        contract = raw_contract if isinstance(raw_contract, dict) else {}
        method = str(metadata.get("method") or contract.get("method") or "").upper()
        return cls(
            category=finding.category.value.lower(),
            subtype=(finding.value_type or "").strip().lower(),
            value=canonicalize_value(finding.category.value, finding.extracted_value),
            method=method,
            line=max(0, finding.evidence.line),
            contract=contract,
            metadata=metadata,
            finding_id=finding.id,
        )

    def signature(self) -> tuple[str, str, str, str, bool, str, str]:
        evidence = str(self.metadata.get("evidence") or "")
        confirmed = bool(self.metadata.get("confirmed"))
        contract = json.dumps(
            _contract_view(self.contract, self.method),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
        return (
            self.category,
            self.subtype,
            self.value,
            self.method,
            confirmed,
            evidence,
            contract,
        )


@dataclass
class DetectionMetric:
    """Counts and derived values for one category or subtype."""

    key: str
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0
    positive_case_ids: set[str] = field(default_factory=set)
    negative_case_ids: set[str] = field(default_factory=set)
    positive_case_fingerprints: set[str] = field(default_factory=set)
    negative_case_fingerprints: set[str] = field(default_factory=set)

    @property
    def precision(self) -> float | None:
        total = self.tp + self.fp
        return self.tp / total if total else None

    @property
    def recall(self) -> float | None:
        total = self.tp + self.fn
        return self.tp / total if total else None

    @property
    def f1(self) -> float | None:
        precision = self.precision
        recall = self.recall
        if precision is None or recall is None or precision + recall == 0:
            return None
        return 2 * precision * recall / (precision + recall)

    @property
    def fpr(self) -> float | None:
        total = self.fp + self.tn
        return self.fp / total if total else None

    @property
    def precision_wilson_lower(self) -> float | None:
        return wilson_lower(self.tp, self.tp + self.fp)

    @property
    def recall_wilson_lower(self) -> float | None:
        return wilson_lower(self.tp, self.tp + self.fn)

    @property
    def f1_wilson_lower(self) -> float | None:
        precision = self.precision_wilson_lower
        recall = self.recall_wilson_lower
        if precision is None or recall is None or precision + recall == 0:
            return None
        return 2 * precision * recall / (precision + recall)

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "tp": self.tp,
            "fp": self.fp,
            "fn": self.fn,
            "tn": self.tn,
            "precision": self.precision,
            "recall": self.recall,
            "f1": self.f1,
            "fpr": self.fpr,
            "precision_wilson_lower": self.precision_wilson_lower,
            "recall_wilson_lower": self.recall_wilson_lower,
            "f1_wilson_lower": self.f1_wilson_lower,
            "positive_case_count": len(self.positive_case_fingerprints),
            "negative_case_count": len(self.negative_case_fingerprints),
            "positive_case_id_count": len(self.positive_case_ids),
            "negative_case_id_count": len(self.negative_case_ids),
            "positive_case_ids": sorted(self.positive_case_ids),
            "negative_case_ids": sorted(self.negative_case_ids),
        }


@dataclass(frozen=True)
class GateSpec:
    """Machine-enforced release gate."""

    name: str
    key: str
    precision: float | None = None
    recall: float | None = None
    f1: float | None = None
    min_positives: int = 0
    min_negatives: int = 0
    min_positive_cases: int = 0
    min_negative_cases: int = 0
    hard_zero_fp: bool = False
    hard_zero_fn: bool = False
    wilson_margin: float = 0.03


@dataclass(frozen=True)
class GateResult:
    """Outcome for one release gate."""

    name: str
    key: str
    passed: bool
    reasons: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "key": self.key,
            "passed": self.passed,
            "reasons": list(self.reasons),
        }


@dataclass
class ValidationResult:
    """Complete corpus run suitable for JSON output and CI exit status."""

    metrics: dict[str, DetectionMetric]
    gates: list[GateResult]
    case_count: int
    prediction_count: int
    label_count: int
    forbidden_hits: list[str]
    completeness_failures: list[str]
    parser_failures: list[str]
    invariance_failures: list[str]
    graph_failures: list[str]
    corpus_fingerprint: str
    gate_profile_fingerprint: str
    graph_observations: dict[str, Mapping[str, Any]]
    canonicalizer_version: int = CANONICALIZER_VERSION

    @property
    def passed(self) -> bool:
        return (
            all(gate.passed for gate in self.gates)
            and not self.forbidden_hits
            and not self.completeness_failures
            and not self.parser_failures
            and not self.invariance_failures
            and not self.graph_failures
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "canonicalizer_version": self.canonicalizer_version,
            "case_count": self.case_count,
            "prediction_count": self.prediction_count,
            "label_count": self.label_count,
            "corpus_fingerprint": self.corpus_fingerprint,
            "gate_profile_fingerprint": self.gate_profile_fingerprint,
            "metrics": {key: metric.to_dict() for key, metric in sorted(self.metrics.items())},
            "gates": [gate.to_dict() for gate in self.gates],
            "forbidden_hits": self.forbidden_hits,
            "completeness_failures": self.completeness_failures,
            "parser_failures": self.parser_failures,
            "invariance_failures": self.invariance_failures,
            "graph_failures": self.graph_failures,
            "graph_observations": {
                key: dict(value)
                for key, value in sorted(self.graph_observations.items())
            },
        }


def canonicalize_value(category: str, value: object) -> str:
    """Apply the versioned value canonicalization used for matching."""
    text = str(value).strip()
    if category.lower() not in {"endpoint", "domain"}:
        return text
    if text.lower().startswith(("http://", "https://", "ws://", "wss://")):
        try:
            parts = urlsplit(text)
            host = (parts.hostname or "").lower()
            port_number = parts.port
        except (UnicodeError, ValueError):
            return text
        if not host:
            return text
        rendered_host = f"[{host}]" if ":" in host else host
        default_port = {
            "http": 80,
            "https": 443,
            "ws": 80,
            "wss": 443,
        }.get(parts.scheme.lower())
        port = f":{port_number}" if port_number is not None and port_number != default_port else ""
        raw_userinfo = parts.netloc.rsplit("@", 1)[0] + "@" if "@" in parts.netloc else ""
        return urlunsplit(
            (
                parts.scheme.lower(),
                f"{raw_userinfo}{rendered_host}{port}",
                parts.path,
                parts.query,
                parts.fragment,
            )
        )
    return text


def wilson_lower(successes: int, total: int, z: float = 1.959963984540054) -> float | None:
    """Return the two-sided 95% Wilson interval lower bound."""
    if total <= 0:
        return None
    proportion = successes / total
    denominator = 1 + z * z / total
    centre = proportion + z * z / (2 * total)
    spread = z * math.sqrt((proportion * (1 - proportion) + z * z / (4 * total)) / total)
    return max(0.0, (centre - spread) / denominator)


def _required_string(raw: Mapping[str, Any], field_name: str, location: str) -> str:
    value = raw.get(field_name)
    if not isinstance(value, str) or not value.strip():
        raise CorpusError(f"{location}: {field_name} must be a non-empty string")
    return value.strip()


def _non_negative_int(value: object, location: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 <= value <= MAX_VALIDATION_COUNT
    ):
        raise CorpusError(
            f"{location} must be a non-negative integer no greater than "
            f"{MAX_VALIDATION_COUNT}"
        )
    return value


def _strict_bool(value: object, location: str) -> bool:
    if not isinstance(value, bool):
        raise CorpusError(f"{location} must be a boolean")
    return value


def _optional_string(
    raw: Mapping[str, Any],
    field_name: str,
    location: str,
    *,
    normalize: Callable[[str], str] | None = None,
) -> str:
    if field_name not in raw:
        return ""
    value = raw[field_name]
    if not isinstance(value, str) or not value.strip():
        raise CorpusError(f"{location}.{field_name} must be a non-empty string when provided")
    normalized = value.strip()
    return normalize(normalized) if normalize is not None else normalized


def _validate_string_key_mapping(value: Mapping[str, Any], location: str) -> None:
    if any(not isinstance(key, str) or not key.strip() for key in value):
        raise CorpusError(f"{location} keys must be non-empty strings")


def _split_metric_key(key: str, location: str) -> tuple[str, str, str]:
    category, separator, subtype_and_state = key.partition("/")
    if category not in SUPPORTED_CATEGORIES:
        raise CorpusError(f"{location}: unsupported metric category {category!r}")
    if not separator:
        return category, "", ""
    subtype, state_separator, state = subtype_and_state.partition("@")
    if not subtype or "/" in subtype or (state_separator and state not in {"confirmed", "probable"}):
        raise CorpusError(f"{location}: malformed metric key {key!r}")
    return category, subtype, state


def _reject_unknown_keys(
    raw: Mapping[str, Any],
    allowed: frozenset[str],
    location: str,
) -> None:
    unknown = sorted(str(key) for key in raw if key not in allowed)
    if unknown:
        raise CorpusError(f"{location}: unknown fields {unknown}")


def _parse_graph_expectation(raw: object, location: str) -> GraphExpectation:
    if not isinstance(raw, dict):
        raise CorpusError(f"{location}: graph must be an object")
    _reject_unknown_keys(raw, _GRAPH_FIELDS, location)

    must_not_truncate = _strict_bool(
        raw.get("must_not_truncate", False),
        f"{location}.must_not_truncate",
    )
    permutation_invariant = _strict_bool(
        raw.get("permutation_invariant", False),
        f"{location}.permutation_invariant",
    )
    min_edges = _non_negative_int(raw.get("min_edges", 0), f"{location}.min_edges")

    edge_types_raw = raw.get("required_edge_types", [])
    if not isinstance(edge_types_raw, list):
        raise CorpusError(f"{location}.required_edge_types must be an array")
    if any(not isinstance(value, str) or not value.strip() for value in edge_types_raw):
        raise CorpusError(f"{location}.required_edge_types entries must be non-empty strings")
    normalized_edge_types = [value.strip().lower() for value in edge_types_raw]
    if len(normalized_edge_types) != len(set(normalized_edge_types)):
        raise CorpusError(f"{location}.required_edge_types contains duplicate edge types")
    unsupported_edge_types = sorted(set(normalized_edge_types) - SUPPORTED_EDGE_TYPES)
    if unsupported_edge_types:
        raise CorpusError(
            f"{location}.required_edge_types contains unsupported edge types "
            f"{unsupported_edge_types}"
        )
    required_edge_types = tuple(EdgeType(value) for value in normalized_edge_types)

    if not (
        must_not_truncate
        or permutation_invariant
        or min_edges > 0
        or required_edge_types
    ):
        raise CorpusError(f"{location}: graph object must activate at least one gate")
    return GraphExpectation(
        must_not_truncate=must_not_truncate,
        required_edge_types=required_edge_types,
        min_edges=min_edges,
        permutation_invariant=permutation_invariant,
    )


def _parse_item(raw: object, location: str) -> ExpectedItem:
    if not isinstance(raw, dict):
        raise CorpusError(f"{location}: item must be an object")
    _reject_unknown_keys(raw, _ITEM_FIELDS, location)
    category = _required_string(raw, "category", location).lower()
    if category not in SUPPORTED_CATEGORIES:
        raise CorpusError(f"{location}: unsupported category {category!r}")
    value = _required_string(raw, "value", location)
    subtype = _optional_string(raw, "subtype", location, normalize=str.lower)
    method = _optional_string(raw, "method", location, normalize=str.upper)
    line_raw = raw.get("line")
    line = None if line_raw is None else _non_negative_int(line_raw, f"{location}.line")
    if line == 0:
        raise CorpusError(f"{location}.line must be 1-based")
    line_tolerance = _non_negative_int(raw.get("line_tolerance", 0), f"{location}.line_tolerance")
    contract_raw = raw.get("contract", {})
    metadata = raw.get("metadata", {})
    if not isinstance(contract_raw, dict) or not isinstance(metadata, dict):
        raise CorpusError(f"{location}: contract and metadata must be objects")
    contract = dict(contract_raw)
    _validate_string_key_mapping(contract, f"{location}.contract")
    _validate_string_key_mapping(metadata, f"{location}.metadata")
    _reject_unknown_keys(contract, _CONTRACT_FIELDS, f"{location}.contract")
    contract_method = contract.get("method")
    if contract_method is not None and (
        not isinstance(contract_method, str) or not contract_method.strip()
    ):
        raise CorpusError(f"{location}.contract.method must be a non-empty string")
    if method and contract_method and method != contract_method.strip().upper():
        raise CorpusError(f"{location}: method and contract.method disagree")
    if not method and isinstance(contract_method, str):
        method = contract_method.strip().upper()
    if isinstance(contract_method, str):
        contract["method"] = contract_method.strip().upper()
    for field_name in ("headers", "auth", "query_params", "body"):
        if field_name in contract and not isinstance(contract[field_name], dict):
            raise CorpusError(f"{location}.contract.{field_name} must be an object")
        if isinstance(contract.get(field_name), dict):
            _validate_string_key_mapping(
                contract[field_name],
                f"{location}.contract.{field_name}",
            )
    auth = contract.get("auth")
    if isinstance(auth, dict):
        _reject_unknown_keys(auth, _AUTH_FIELDS, f"{location}.contract.auth")
    body = contract.get("body")
    if isinstance(body, dict):
        _reject_unknown_keys(body, _BODY_FIELDS, f"{location}.contract.body")
    headers = contract.get("headers")
    if isinstance(headers, dict):
        normalized_header_names = [name.strip().lower() for name in headers]
        if len(normalized_header_names) != len(set(normalized_header_names)):
            raise CorpusError(
                f"{location}.contract.headers contains duplicate case-insensitive names"
            )
    expected_state = _optional_string(
        raw,
        "expected_state",
        location,
        normalize=str.lower,
    ) or "kept"
    if expected_state not in {"kept", "confirmed", "probable", "excluded"}:
        raise CorpusError(f"{location}: unsupported expected_state {expected_state!r}")
    return ExpectedItem(
        category=category,
        subtype=subtype,
        value=canonicalize_value(category, value),
        method=method,
        line=line,
        line_tolerance=line_tolerance,
        contract=contract,
        metadata=metadata,
        expected_state=expected_state,
    )


def _item_identity(item: ExpectedItem) -> str:
    return json.dumps(
        {
            "category": item.category,
            "value": item.value,
            "subtype": item.subtype,
            "method": item.method,
            "line": item.line,
            "line_tolerance": item.line_tolerance,
            "contract": item.contract,
            "metadata": item.metadata,
            "expected_state": item.expected_state,
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def _reject_duplicate_items(
    items: Sequence[ExpectedItem],
    location: str,
) -> None:
    identities = [_item_identity(item) for item in items]
    if len(identities) != len(set(identities)):
        raise CorpusError(f"{location}: duplicate ground-truth items are not allowed")


def _mapping_constraints_overlap(
    left: Mapping[str, Any],
    right: Mapping[str, Any],
) -> bool:
    for key in left.keys() & right.keys():
        left_value = left[key]
        right_value = right[key]
        if isinstance(left_value, dict) and isinstance(right_value, dict):
            if not _mapping_constraints_overlap(left_value, right_value):
                return False
        elif left_value != right_value:
            return False
    return True


def _items_can_match_same_prediction(left: ExpectedItem, right: ExpectedItem) -> bool:
    if left.category != right.category or left.value != right.value:
        return False
    if (
        left.subtype not in {"", "*"}
        and right.subtype not in {"", "*"}
        and left.subtype != right.subtype
    ):
        return False
    if left.method and right.method and left.method != right.method:
        return False
    if left.line is not None and right.line is not None:
        if abs(left.line - right.line) > left.line_tolerance + right.line_tolerance:
            return False
    left_state = left.expected_state if left.expected_state in {"confirmed", "probable"} else ""
    right_state = right.expected_state if right.expected_state in {"confirmed", "probable"} else ""
    if left_state and right_state and left_state != right_state:
        return False
    return _mapping_constraints_overlap(
        left.contract,
        right.contract,
    ) and _mapping_constraints_overlap(left.metadata, right.metadata)


def _reject_overlapping_items(
    items: Sequence[ExpectedItem],
    location: str,
) -> None:
    for left_index, left in enumerate(items):
        for right_index in range(left_index + 1, len(items)):
            if _items_can_match_same_prediction(left, items[right_index]):
                raise CorpusError(
                    f"{location}: items {left_index} and {right_index} are ambiguous overlapping "
                    "ground-truth occurrences"
                )


def load_manifest(corpus_root: Path, manifest_path: Path | None = None) -> list[CorpusCase]:
    """Load and strictly validate a JSONL corpus manifest."""
    root = corpus_root.resolve()
    manifest = (manifest_path or root / "manifest.jsonl").resolve()
    if not manifest.is_file():
        raise CorpusError(f"manifest not found: {manifest}")
    cases: list[CorpusCase] = []
    seen_ids: set[str] = set()
    for line_number, line in enumerate(manifest.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        location = f"{manifest}:{line_number}"
        raw = _load_strict_json(line, location)
        if not isinstance(raw, dict):
            raise CorpusError(f"{location}: case must be an object")
        _reject_unknown_keys(raw, _CASE_FIELDS, location)
        case_id = _required_string(raw, "case_id", location)
        if case_id in seen_ids:
            raise CorpusError(f"{location}: duplicate case_id {case_id!r}")
        seen_ids.add(case_id)
        asset_rel = _required_string(raw, "asset", location)
        asset = (root / asset_rel).resolve()
        if not asset.is_relative_to(root) or not asset.is_file():
            raise CorpusError(f"{location}: asset must be an existing file inside corpus root")
        asset_identity = asset.relative_to(root).as_posix()
        try:
            asset_bytes = asset.read_bytes()
        except OSError as exc:
            raise CorpusError(f"{location}: asset cannot be read ({type(exc).__name__})") from exc
        try:
            asset_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise CorpusError(f"{location}: asset must be valid UTF-8") from exc
        asset_fingerprint = hashlib.sha256(asset_bytes).hexdigest()
        labels_raw = raw.get("labels", [])
        forbidden_raw = raw.get("forbidden", [])
        if not isinstance(labels_raw, list) or not isinstance(forbidden_raw, list):
            raise CorpusError(f"{location}: labels and forbidden must be arrays")
        labels_all = tuple(
            _parse_item(item, f"{location}.labels[{index}]")
            for index, item in enumerate(labels_raw)
        )
        _reject_duplicate_items(labels_all, f"{location}.labels")
        _reject_overlapping_items(labels_all, f"{location}.labels")
        labels = tuple(item for item in labels_all if item.expected_state != "excluded")
        forbidden = (
            *_parse_items(forbidden_raw, f"{location}.forbidden"),
            *(item for item in labels_all if item.expected_state == "excluded"),
        )
        _reject_duplicate_items(forbidden, f"{location}.forbidden")
        _reject_overlapping_items(forbidden, f"{location}.forbidden")
        if any(
            _items_can_match_same_prediction(label, excluded)
            for label in labels
            for excluded in forbidden
        ):
            raise CorpusError(
                f"{location}: expected and forbidden constraints overlap on one prediction"
            )
        negative_raw = raw.get("negative_opportunities", {})
        if not isinstance(negative_raw, dict):
            raise CorpusError(f"{location}: negative_opportunities must be an object")
        negative: dict[str, int] = {}
        for key, value in negative_raw.items():
            if not isinstance(key, str) or not key.strip():
                raise CorpusError(
                    f"{location}.negative_opportunities keys must be non-empty strings"
                )
            normalized_key = key.strip().lower()
            if normalized_key in negative:
                raise CorpusError(
                    f"{location}.negative_opportunities contains duplicate normalized key "
                    f"{normalized_key!r}"
                )
            _split_metric_key(
                normalized_key,
                f"{location}.negative_opportunities.{key}",
            )
            negative[normalized_key] = _non_negative_int(
                value,
                f"{location}.negative_opportunities.{key}",
            )
        categories_raw = raw.get("evaluated_categories", [])
        if not isinstance(categories_raw, list):
            raise CorpusError(f"{location}: evaluated_categories must be an array")
        if any(not isinstance(value, str) or not value.strip() for value in categories_raw):
            raise CorpusError(f"{location}: evaluated_categories entries must be strings")
        normalized_categories = [value.strip().lower() for value in categories_raw]
        if len(normalized_categories) != len(set(normalized_categories)):
            raise CorpusError(f"{location}: evaluated_categories contains duplicate categories")
        categories = set(normalized_categories)
        categories.update(item.category for item in labels)
        categories.update(item.category for item in forbidden)
        categories.update(key.split("/", 1)[0] for key in negative)
        if not categories:
            raise CorpusError(f"{location}: case evaluates no categories")
        unsupported_categories = sorted(categories - SUPPORTED_CATEGORIES)
        if unsupported_categories:
            raise CorpusError(
                f"{location}: unsupported evaluated categories {unsupported_categories}"
            )
        subtypes_raw = raw.get("evaluated_subtypes", {})
        if not isinstance(subtypes_raw, dict):
            raise CorpusError(f"{location}: evaluated_subtypes must be an object")
        evaluated_subtypes: dict[str, tuple[str, ...]] = {}
        for category, values in subtypes_raw.items():
            if not isinstance(category, str) or not category.strip():
                raise CorpusError(
                    f"{location}.evaluated_subtypes keys must be non-empty strings"
                )
            normalized_category = category.strip().lower()
            if normalized_category in evaluated_subtypes:
                raise CorpusError(
                    f"{location}.evaluated_subtypes contains duplicate normalized category "
                    f"{normalized_category!r}"
                )
            if normalized_category not in categories or not isinstance(values, list):
                raise CorpusError(
                    f"{location}.evaluated_subtypes.{category}: category must be evaluated and value must be an array"
                )
            if any(not isinstance(value, str) or not value.strip() for value in values):
                raise CorpusError(
                    f"{location}.evaluated_subtypes.{category}: entries must be strings"
                )
            normalized_sequence = [value.strip().lower() for value in values]
            if len(normalized_sequence) != len(set(normalized_sequence)):
                raise CorpusError(
                    f"{location}.evaluated_subtypes.{category}: contains duplicate subtypes"
                )
            normalized_values = tuple(sorted(normalized_sequence))
            if not normalized_values:
                raise CorpusError(
                    f"{location}.evaluated_subtypes.{category}: subtype list cannot be empty"
                )
            evaluated_subtypes[normalized_category] = normalized_values
        for key in negative:
            category, subtype, _state = _split_metric_key(
                key,
                f"{location}.negative_opportunities.{key}",
            )
            if subtype and subtype not in evaluated_subtypes.get(category, ()):
                raise CorpusError(
                    f"{location}.negative_opportunities.{key}: subtype must be declared in "
                    f"evaluated_subtypes.{category}"
                )
        completeness = raw.get("completeness", {})
        if not isinstance(completeness, dict):
            raise CorpusError(f"{location}: completeness must be an object")
        _reject_unknown_keys(completeness, _COMPLETENESS_FIELDS, f"{location}.completeness")
        tags_raw = raw.get("tags", [])
        if not isinstance(tags_raw, list):
            raise CorpusError(f"{location}: tags must be an array")
        if any(not isinstance(tag, str) or not tag.strip() for tag in tags_raw):
            raise CorpusError(f"{location}: tags entries must be non-empty strings")
        normalized_tags = [tag.strip() for tag in tags_raw]
        if len(normalized_tags) != len(set(normalized_tags)):
            raise CorpusError(f"{location}: tags contains duplicate values")
        language_raw = raw.get("language", "javascript")
        if not isinstance(language_raw, str) or not language_raw.strip():
            raise CorpusError(f"{location}: language must be a non-empty string")
        language = language_raw.strip().lower()
        if language not in SUPPORTED_LANGUAGES:
            raise CorpusError(f"{location}: unsupported language {language!r}")
        must_not_be_partial = _strict_bool(
            completeness.get("must_not_be_partial", False),
            f"{location}.completeness.must_not_be_partial",
        )
        graph = (
            _parse_graph_expectation(raw["graph"], f"{location}.graph")
            if "graph" in raw
            else None
        )
        parser_expectation_raw = raw.get("parser_expectation", "full_or_recovered_ast")
        if not isinstance(parser_expectation_raw, str) or not parser_expectation_raw.strip():
            raise CorpusError(f"{location}: parser_expectation must be a non-empty string")
        semantic_group_raw = raw.get("semantic_group", "")
        if not isinstance(semantic_group_raw, str):
            raise CorpusError(f"{location}: semantic_group must be a string")
        cases.append(
            CorpusCase(
                case_id=case_id,
                asset=asset,
                asset_identity=asset_identity,
                asset_fingerprint=asset_fingerprint,
                language=language,
                labels=labels,
                forbidden=forbidden,
                evaluated_categories=tuple(sorted(categories)),
                evaluated_subtypes=evaluated_subtypes,
                negative_opportunities=negative,
                parser_expectation=parser_expectation_raw.strip().lower(),
                must_not_be_partial=must_not_be_partial,
                graph=graph,
                semantic_group=semantic_group_raw.strip(),
                tags=tuple(sorted(normalized_tags)),
            )
        )
    if not cases:
        raise CorpusError(f"manifest contains no cases: {manifest}")
    referenced_assets = {case.asset for case in cases}
    orphan_assets = sorted(
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file()
        and path.suffix.lower() in SUPPORTED_CORPUS_SUFFIXES
        and path.resolve() not in referenced_assets
    )
    if orphan_assets:
        raise CorpusError(f"unreferenced analyzable corpus assets: {orphan_assets}")
    return cases


def _parse_items(raw_items: Sequence[object], location: str) -> tuple[ExpectedItem, ...]:
    return tuple(_parse_item(item, f"{location}[{index}]") for index, item in enumerate(raw_items))


def load_gates(path: Path | None) -> list[GateSpec]:
    """Load gate definitions from JSON; no gates means metrics-only validation."""
    if path is None:
        return []
    try:
        gate_text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise CorpusError(f"invalid gate file {path}: {exc}") from exc
    raw = _load_strict_json(gate_text, str(path))
    if isinstance(raw, dict):
        _reject_unknown_keys(raw, frozenset({"gates"}), str(path))
    entries = raw.get("gates") if isinstance(raw, dict) else None
    if not isinstance(entries, list) or not entries:
        raise CorpusError(f"{path}: gates must be a non-empty array")
    gates: list[GateSpec] = []
    names: set[str] = set()
    keys: set[str] = set()
    for index, entry in enumerate(entries):
        location = f"{path}.gates[{index}]"
        if not isinstance(entry, dict):
            raise CorpusError(f"{location}: gate must be an object")
        _reject_unknown_keys(entry, _GATE_FIELDS, location)
        name = _required_string(entry, "name", location)
        if name in names:
            raise CorpusError(f"{location}: duplicate gate name {name!r}")
        names.add(name)
        key = _required_string(entry, "key", location).lower()
        if key in keys:
            raise CorpusError(f"{location}: duplicate gate key {key!r}")
        keys.add(key)
        if key.startswith("contract/"):
            contract_key = key.removeprefix("contract/")
            if contract_key not in {"method", "headers", "auth", "query_params", "body"}:
                raise CorpusError(f"{location}.key: unsupported contract metric {key!r}")
        elif key != "location" and not key.startswith("location/"):
            _split_metric_key(key, f"{location}.key")
        thresholds: dict[str, float | None] = {}
        for metric_name in ("precision", "recall", "f1"):
            value = entry.get(metric_name)
            if value is None:
                thresholds[metric_name] = None
            elif (
                isinstance(value, (int, float))
                and not isinstance(value, bool)
                and math.isfinite(float(value))
                and 0 <= float(value) <= 1
            ):
                thresholds[metric_name] = float(value)
            else:
                raise CorpusError(f"{location}.{metric_name}: threshold must be between 0 and 1")
        margin = entry.get("wilson_margin", 0.03)
        if (
            not isinstance(margin, (int, float))
            or isinstance(margin, bool)
            or not math.isfinite(float(margin))
            or not 0 <= float(margin) <= MAX_WILSON_MARGIN
        ):
            raise CorpusError(
                f"{location}.wilson_margin must be between 0 and {MAX_WILSON_MARGIN}"
            )
        hard_zero_fp = _strict_bool(entry.get("hard_zero_fp", False), f"{location}.hard_zero_fp")
        hard_zero_fn = _strict_bool(entry.get("hard_zero_fn", False), f"{location}.hard_zero_fn")
        if not any(threshold is not None for threshold in thresholds.values()) and not (
            hard_zero_fp or hard_zero_fn
        ):
            raise CorpusError(f"{location}: gate must enforce a metric threshold or hard-zero rule")
        min_positives = _non_negative_int(
            entry.get("min_positives", 0),
            f"{location}.min_positives",
        )
        min_negatives = _non_negative_int(
            entry.get("min_negatives", 0),
            f"{location}.min_negatives",
        )
        min_positive_cases = _non_negative_int(
            entry.get("min_positive_cases", 0),
            f"{location}.min_positive_cases",
        )
        min_negative_cases = _non_negative_int(
            entry.get("min_negative_cases", 0),
            f"{location}.min_negative_cases",
        )
        if hard_zero_fp and (min_negatives == 0 or min_negative_cases == 0):
            raise CorpusError(
                f"{location}: hard_zero_fp requires positive min_negatives and "
                "min_negative_cases"
            )
        if hard_zero_fn and (min_positives == 0 or min_positive_cases == 0):
            raise CorpusError(
                f"{location}: hard_zero_fn requires positive min_positives and "
                "min_positive_cases"
            )
        gates.append(
            GateSpec(
                name=name,
                key=key,
                precision=thresholds["precision"],
                recall=thresholds["recall"],
                f1=thresholds["f1"],
                min_positives=min_positives,
                min_negatives=min_negatives,
                min_positive_cases=min_positive_cases,
                min_negative_cases=min_negative_cases,
                hard_zero_fp=hard_zero_fp,
                hard_zero_fn=hard_zero_fn,
                wilson_margin=float(margin),
            )
        )
    return gates


def _semantic_sha256(value: object) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _corpus_fingerprint(cases: Sequence[CorpusCase]) -> str:
    payload: list[dict[str, Any]] = []
    for case in cases:
        graph = None
        if case.graph is not None:
            graph = {
                "must_not_truncate": case.graph.must_not_truncate,
                "required_edge_types": [
                    edge_type.value for edge_type in case.graph.required_edge_types
                ],
                "min_edges": case.graph.min_edges,
                "permutation_invariant": case.graph.permutation_invariant,
            }
        payload.append({
            "case_id": case.case_id,
            "asset": case.asset_identity,
            "asset_fingerprint": case.asset_fingerprint,
            "language": case.language,
            "labels": [_item_identity(item) for item in case.labels],
            "forbidden": [_item_identity(item) for item in case.forbidden],
            "evaluated_categories": list(case.evaluated_categories),
            "evaluated_subtypes": {
                key: list(value) for key, value in sorted(case.evaluated_subtypes.items())
            },
            "negative_opportunities": dict(sorted(case.negative_opportunities.items())),
            "parser_expectation": case.parser_expectation,
            "must_not_be_partial": case.must_not_be_partial,
            "graph": graph,
            "semantic_group": case.semantic_group,
            "tags": list(case.tags),
        })
    return _semantic_sha256(payload)


def _gate_profile_fingerprint(gates: Sequence[GateSpec]) -> str:
    return _semantic_sha256([
        {
            "name": gate.name,
            "key": gate.key,
            "precision": gate.precision,
            "recall": gate.recall,
            "f1": gate.f1,
            "min_positives": gate.min_positives,
            "min_negatives": gate.min_negatives,
            "min_positive_cases": gate.min_positive_cases,
            "min_negative_cases": gate.min_negative_cases,
            "hard_zero_fp": gate.hard_zero_fp,
            "hard_zero_fn": gate.hard_zero_fn,
            "wilson_margin": gate.wilson_margin,
        }
        for gate in sorted(gates, key=lambda item: (item.key, item.name))
    ])


def _mapping_contains(actual: Mapping[str, Any], expected: Mapping[str, Any]) -> bool:
    for key, expected_value in expected.items():
        if key not in actual:
            return False
        actual_value = actual[key]
        if isinstance(expected_value, dict):
            if not isinstance(actual_value, dict) or not _mapping_contains(actual_value, expected_value):
                return False
        elif actual_value != expected_value:
            return False
    return True


def _matches(expected: ExpectedItem, prediction: Prediction) -> bool:
    if expected.category != prediction.category:
        return False
    if expected.subtype not in {"", "*"} and expected.subtype != prediction.subtype:
        return False
    if expected.value != prediction.value:
        return False
    if expected.method and expected.method != prediction.method:
        return False
    if expected.line is not None and abs(expected.line - prediction.line) > expected.line_tolerance:
        return False
    if not _mapping_contains(prediction.contract, expected.contract):
        return False
    if not _mapping_contains(prediction.metadata, expected.metadata):
        return False
    if expected.expected_state == "confirmed" and prediction.metadata.get("confirmed") is not True:
        return False
    if expected.expected_state == "probable" and str(prediction.metadata.get("evidence") or "") != "probable":
        return False
    return True


def _matches_identity(expected: ExpectedItem, prediction: Prediction) -> bool:
    """Match an occurrence while deliberately ignoring request-contract fields."""
    if expected.category != prediction.category:
        return False
    if expected.subtype not in {"", "*"} and expected.subtype != prediction.subtype:
        return False
    if expected.value != prediction.value:
        return False
    return expected.line is None or abs(expected.line - prediction.line) <= expected.line_tolerance


def _matches_without_location(expected: ExpectedItem, prediction: Prediction) -> bool:
    if expected.category != prediction.category:
        return False
    if expected.subtype not in {"", "*"} and expected.subtype != prediction.subtype:
        return False
    if expected.value != prediction.value:
        return False
    if expected.method and expected.method != prediction.method:
        return False
    if not _mapping_contains(prediction.contract, expected.contract):
        return False
    if not _mapping_contains(prediction.metadata, expected.metadata):
        return False
    if expected.expected_state == "confirmed" and prediction.metadata.get("confirmed") is not True:
        return False
    if expected.expected_state == "probable" and (
        str(prediction.metadata.get("evidence") or "") != "probable"
    ):
        return False
    return True


def _maximum_matching(
    labels: Sequence[ExpectedItem],
    predictions: Sequence[Prediction],
    matcher: Callable[[ExpectedItem, Prediction], bool] = _matches,
) -> dict[int, int]:
    """Return label-index to prediction-index maximum bipartite matching."""
    adjacency = [
        [index for index, prediction in enumerate(predictions) if matcher(label, prediction)]
        for label in labels
    ]
    prediction_to_label: dict[int, int] = {}

    def augment(label_index: int, seen: set[int]) -> bool:
        for prediction_index in adjacency[label_index]:
            if prediction_index in seen:
                continue
            seen.add(prediction_index)
            current = prediction_to_label.get(prediction_index)
            if current is None or augment(current, seen):
                prediction_to_label[prediction_index] = label_index
                return True
        return False

    for label_index in sorted(range(len(labels)), key=lambda index: (len(adjacency[index]), index)):
        augment(label_index, set())
    return {label_index: prediction_index for prediction_index, label_index in prediction_to_label.items()}


def _metric(metrics: dict[str, DetectionMetric], key: str) -> DetectionMetric:
    if key not in metrics:
        metrics[key] = DetectionMetric(key=key)
    return metrics[key]


def _keys(category: str, subtype: str, evidence_state: str = "") -> tuple[str, ...]:
    subtype_key = f"{category}/{subtype or 'unspecified'}"
    keys = [category, subtype_key]
    if evidence_state in {"confirmed", "probable"}:
        keys.append(f"{subtype_key}@{evidence_state}")
    return tuple(keys)


def _record_tp(
    metrics: dict[str, DetectionMetric],
    label: ExpectedItem,
    prediction: Prediction,
) -> None:
    _metric(metrics, prediction.category).tp += 1
    if label.subtype in {"", "*"}:
        return
    subtype_key = f"{prediction.category}/{prediction.subtype or 'unspecified'}"
    _metric(metrics, subtype_key).tp += 1
    if label.expected_state in {"confirmed", "probable"}:
        _metric(metrics, f"{subtype_key}@{label.expected_state}").tp += 1


def _record_fp(metrics: dict[str, DetectionMetric], prediction: Prediction) -> None:
    evidence_state = str(prediction.metadata.get("evidence") or "").lower()
    for key in _keys(prediction.category, prediction.subtype, evidence_state):
        _metric(metrics, key).fp += 1


def _record_fn(metrics: dict[str, DetectionMetric], label: ExpectedItem) -> None:
    evidence_state = label.expected_state if label.expected_state in {"confirmed", "probable"} else ""
    for key in _keys(label.category, label.subtype, evidence_state):
        _metric(metrics, key).fn += 1


def _record_negative_opportunities(
    metrics: dict[str, DetectionMetric],
    opportunities: Mapping[str, int],
    fp_before_case: Mapping[str, int],
) -> None:
    for key, count in opportunities.items():
        metric = _metric(metrics, key)
        case_false_positives = metric.fp - fp_before_case.get(key, 0)
        metric.tn += max(0, count - case_false_positives)


def _record_contract_field(
    metrics: dict[str, DetectionMetric],
    key: str,
    *,
    expected: object,
    actual_present: bool,
    actual: object,
) -> None:
    metric = _metric(metrics, f"contract/{key}")
    matches = actual == expected
    if matches:
        metric.tp += 1
        return
    metric.fn += 1
    if actual_present:
        metric.fp += 1


def _contract_view(contract: Mapping[str, Any], method: str = "") -> dict[str, Any]:
    """Project volatile detector metadata into strictly comparable semantic fields."""
    view: dict[str, Any] = {}
    normalized_method = str(method or contract.get("method") or "").upper()
    if normalized_method:
        view["method"] = normalized_method

    headers = contract.get("headers")
    if isinstance(headers, dict):
        non_auth_headers = {
            str(name).lower(): value
            for name, value in headers.items()
            if str(name).lower() not in {"authorization", "proxy-authorization", "cookie"}
        }
        view["headers"] = dict(sorted(non_auth_headers.items()))

    auth = contract.get("auth")
    if isinstance(auth, dict):
        view["auth"] = {
            key: auth[key]
            for key in ("scheme", "in")
            if key in auth
        }

    query = contract.get("query_params")
    if isinstance(query, dict):
        view["query_params"] = dict(sorted(query.items()))

    body = contract.get("body")
    if isinstance(body, dict):
        view["body"] = {
            key: body[key]
            for key in ("kind", "shape")
            if key in body
        }
    return view


def _matches_contract_exact(expected: ExpectedItem, prediction: Prediction) -> bool:
    if not _matches_identity(expected, prediction):
        return False
    expected_view = _contract_view(expected.contract, expected.method)
    actual_view = _contract_view(prediction.contract, prediction.method)
    return all(actual_view.get(key) == value for key, value in expected_view.items())


def _prefer_exact_contract_matching(
    labels: Sequence[ExpectedItem],
    predictions: Sequence[Prediction],
) -> dict[int, int]:
    """Match exact repeated-call contracts first, then attribute remaining field errors."""
    exact = _maximum_matching(labels, predictions, matcher=_matches_contract_exact)
    matched_predictions = set(exact.values())
    remaining_label_indices = [index for index in range(len(labels)) if index not in exact]
    remaining_prediction_indices = [
        index for index in range(len(predictions)) if index not in matched_predictions
    ]
    fallback = _maximum_matching(
        [labels[index] for index in remaining_label_indices],
        [predictions[index] for index in remaining_prediction_indices],
        matcher=_matches_identity,
    )
    merged = dict(exact)
    for label_index, prediction_index in fallback.items():
        merged[remaining_label_indices[label_index]] = remaining_prediction_indices[prediction_index]
    return merged


def _record_contract_metrics(
    metrics: dict[str, DetectionMetric],
    labels: Sequence[ExpectedItem],
    predictions: Sequence[Prediction],
) -> None:
    contract_labels = [label for label in labels if label.method or label.contract]
    if not contract_labels:
        return
    matching = _prefer_exact_contract_matching(contract_labels, predictions)
    matched_predictions = set(matching.values())
    evaluated_fields = {
        key
        for label in contract_labels
        for key in label.contract
    }
    if any(label.method for label in contract_labels):
        evaluated_fields.add("method")

    for label_index, label in enumerate(contract_labels):
        prediction_index = matching.get(label_index)
        prediction = predictions[prediction_index] if prediction_index is not None else None
        expected_view = _contract_view(label.contract, label.method)
        actual_view = (
            _contract_view(prediction.contract, prediction.method)
            if prediction is not None
            else {}
        )
        if label.method:
            _record_contract_field(
                metrics,
                "method",
                expected=expected_view.get("method"),
                actual_present="method" in actual_view,
                actual=actual_view.get("method"),
            )
        for key in label.contract:
            if key == "method" and label.method:
                continue
            if key not in {"headers", "auth", "query_params", "body"}:
                continue
            actual_present = prediction is not None and key in prediction.contract
            _record_contract_field(
                metrics,
                key,
                expected=expected_view.get(key),
                actual_present=actual_present,
                actual=actual_view.get(key),
            )

    for prediction_index, prediction in enumerate(predictions):
        if prediction_index in matched_predictions:
            continue
        actual_view = _contract_view(prediction.contract, prediction.method)
        for key in evaluated_fields:
            if key == "method":
                if "method" in actual_view:
                    _metric(metrics, "contract/method").fp += 1
            elif key in actual_view:
                _metric(metrics, f"contract/{key}").fp += 1


def _record_location_metrics(
    metrics: dict[str, DetectionMetric],
    labels: Sequence[ExpectedItem],
    predictions: Sequence[Prediction],
) -> None:
    location_labels = [label for label in labels if label.line is not None]
    if not location_labels:
        return
    exact = _maximum_matching(location_labels, predictions, matcher=_matches)
    matched_predictions = set(exact.values())
    remaining_label_indices = [
        index for index in range(len(location_labels)) if index not in exact
    ]
    remaining_prediction_indices = [
        index for index in range(len(predictions)) if index not in matched_predictions
    ]
    fallback = _maximum_matching(
        [location_labels[index] for index in remaining_label_indices],
        [predictions[index] for index in remaining_prediction_indices],
        matcher=_matches_without_location,
    )
    matching = dict(exact)
    for label_index, prediction_index in fallback.items():
        matching[remaining_label_indices[label_index]] = remaining_prediction_indices[
            prediction_index
        ]

    for label_index, label in enumerate(location_labels):
        matched_index = matching.get(label_index)
        prediction = predictions[matched_index] if matched_index is not None else None
        keys = ("location", f"location/{label.category}/{label.subtype or 'unspecified'}")
        correct = bool(
            prediction is not None
            and label.line is not None
            and abs(label.line - prediction.line) <= label.line_tolerance
        )
        for key in keys:
            metric = _metric(metrics, key)
            if correct:
                metric.tp += 1
            else:
                metric.fn += 1
                if prediction is not None:
                    metric.fp += 1


def _evaluate_gate(spec: GateSpec, metrics: Mapping[str, DetectionMetric]) -> GateResult:
    metric = metrics.get(spec.key, DetectionMetric(key=spec.key))
    reasons: list[str] = []
    positives = metric.tp + metric.fn
    negatives = metric.fp + metric.tn
    if positives < spec.min_positives:
        reasons.append(f"positive samples {positives} < {spec.min_positives}")
    if negatives < spec.min_negatives:
        reasons.append(f"negative opportunities {negatives} < {spec.min_negatives}")
    if len(metric.positive_case_fingerprints) < spec.min_positive_cases:
        reasons.append(
            f"independent positive cases {len(metric.positive_case_fingerprints)} "
            f"< {spec.min_positive_cases}"
        )
    if len(metric.negative_case_fingerprints) < spec.min_negative_cases:
        reasons.append(
            f"independent negative cases {len(metric.negative_case_fingerprints)} "
            f"< {spec.min_negative_cases}"
        )
    for name, threshold, value, lower in (
        ("precision", spec.precision, metric.precision, metric.precision_wilson_lower),
        ("recall", spec.recall, metric.recall, metric.recall_wilson_lower),
    ):
        if threshold is None:
            continue
        if value is None or value < threshold:
            reasons.append(f"{name} {value!r} < {threshold}")
        minimum_lower = max(0.0, threshold - spec.wilson_margin)
        if lower is None or lower < minimum_lower:
            reasons.append(f"{name} Wilson lower {lower!r} < {minimum_lower}")
    if spec.f1 is not None:
        if metric.f1 is None or metric.f1 < spec.f1:
            reasons.append(f"f1 {metric.f1!r} < {spec.f1}")
        minimum_lower = max(0.0, spec.f1 - spec.wilson_margin)
        if metric.f1_wilson_lower is None or metric.f1_wilson_lower < minimum_lower:
            reasons.append(
                f"f1 conservative Wilson lower {metric.f1_wilson_lower!r} "
                f"< {minimum_lower}"
            )
    if spec.hard_zero_fp and metric.fp:
        reasons.append(f"hard-zero FP violated: {metric.fp}")
    if spec.hard_zero_fn and metric.fn:
        reasons.append(f"hard-zero FN violated: {metric.fn}")
    return GateResult(spec.name, spec.key, not reasons, tuple(reasons))


def _stable_graph_value(value: object) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=str,
    )


def _graph_signature(graph: CorrelationGraph) -> str:
    edges = sorted(
        (
            edge.edge_type.value,
            edge.source_id,
            edge.target_id,
            edge.confidence.value,
            edge.reasoning,
            _stable_graph_value(edge.metadata),
        )
        for edge in graph.edges
    )
    clusters = sorted(
        (
            cluster.id,
            cluster.name,
            cluster.description,
            tuple(sorted(cluster.finding_ids)),
            _stable_graph_value(cluster.common_traits),
        )
        for cluster in graph.clusters
    )
    return _stable_graph_value({
        "edges": edges,
        "clusters": clusters,
        "telemetry": graph.telemetry,
    })


def _graph_observation_edge(
    edge: Edge,
    finding_semantics: Mapping[str, str],
) -> tuple[str, str, str, str, str, str]:
    reasoning = edge.reasoning
    metadata = edge.metadata
    if edge.edge_type == EdgeType.SAME_FILE:
        # The same-file relation is already encoded by its edge type and endpoints. Its factory
        # repeats the host's absolute file URI in presentation text and metadata, which would make
        # an otherwise identical corpus baseline differ between Windows and POSIX workspaces.
        reasoning = "findings share one source file"
        metadata = {
            key: value
            for key, value in edge.metadata.items()
            if key != "file_url"
        }
    return (
        edge.edge_type.value,
        finding_semantics.get(edge.source_id, "<unknown>"),
        finding_semantics.get(edge.target_id, "<unknown>"),
        edge.confidence.value,
        reasoning,
        _stable_graph_value(metadata),
    )


def _graph_observation(
    graph: CorrelationGraph,
    findings: Sequence[Finding],
) -> dict[str, Any]:
    finding_semantics: dict[str, str] = {}
    for finding in findings:
        prediction = Prediction.from_finding(finding)
        finding_semantics[finding.id] = _stable_graph_value({
            "rule_id": finding.rule_id,
            "category": prediction.category,
            "subtype": prediction.subtype,
            "value": prediction.value,
            "method": prediction.method,
            "line": prediction.line,
            "column": max(0, finding.evidence.column),
            "contract": _contract_view(prediction.contract, prediction.method),
            "confirmed": prediction.metadata.get("confirmed") is True,
            "evidence": str(prediction.metadata.get("evidence") or ""),
        })
    edges = sorted(
        _graph_observation_edge(edge, finding_semantics)
        for edge in graph.edges
    )
    clusters = sorted(
        (
            cluster.name,
            cluster.description,
            tuple(sorted(finding_semantics.get(item, "<unknown>") for item in cluster.finding_ids)),
            _stable_graph_value(cluster.common_traits),
        )
        for cluster in graph.clusters
    )
    edge_types = Counter(edge.edge_type.value for edge in graph.edges)
    return {
        "edge_count": len(graph.edges),
        "cluster_count": len(graph.clusters),
        "edge_types": dict(sorted(edge_types.items())),
        "semantic_sha256": _semantic_sha256({
            "edges": edges,
            "clusters": clusters,
            "telemetry": graph.telemetry,
        }),
    }


def _graph_telemetry_reasons(graph: CorrelationGraph) -> tuple[list[str], list[str]]:
    telemetry = graph.telemetry
    if not isinstance(telemetry, Mapping):
        return ["telemetry must be an object"], []

    counter_names = (
        "candidates",
        "candidate_attempts",
        "emitted",
        "dropped",
        "duplicate_dropped",
        "cap_dropped",
        "truncated_candidates",
        "truncated_candidates_lower_bound",
        "truncated_candidates_unknown",
    )
    counters: dict[str, int] = {}
    malformed: list[str] = []
    for name in counter_names:
        value = telemetry.get(name)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            malformed.append(f"{name} must be a non-negative integer")
        else:
            counters[name] = value

    capped_passes = telemetry.get("capped_passes")
    if not isinstance(capped_passes, Mapping):
        malformed.append("capped_passes must be an object")
    elif any(
        not isinstance(name, str)
        or not name
        or isinstance(count, bool)
        or not isinstance(count, int)
        or count <= 0
        for name, count in capped_passes.items()
    ):
        malformed.append("capped_passes entries must have non-empty names and positive counts")

    passes = telemetry.get("passes")
    pass_counter_names = (
        "candidate_attempts",
        "emitted",
        "duplicate_dropped",
        "cap_dropped",
        "truncated_candidates",
        "truncated_candidates_lower_bound",
        "truncated_candidates_unknown",
    )
    normalized_passes: dict[str, dict[str, int]] = {}
    if not isinstance(passes, Mapping):
        malformed.append("passes must be an object")
    else:
        for pass_name, raw_stats in passes.items():
            if not isinstance(pass_name, str) or not pass_name or not isinstance(raw_stats, Mapping):
                malformed.append("passes entries must have non-empty names and object values")
                continue
            stats: dict[str, int] = {}
            for counter_name in pass_counter_names:
                value = raw_stats.get(counter_name)
                if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                    malformed.append(
                        f"passes.{pass_name}.{counter_name} must be a non-negative integer"
                    )
                else:
                    stats[counter_name] = value
            if len(stats) == len(pass_counter_names):
                normalized_passes[pass_name] = stats

    if counters.get("emitted") != len(graph.edges):
        malformed.append("emitted does not match graph edge count")
    if counters.get("candidates") != counters.get("candidate_attempts"):
        malformed.append("candidates does not match candidate_attempts")
    if counters.get("candidate_attempts") != (
        counters.get("emitted", 0) + counters.get("duplicate_dropped", 0)
    ):
        malformed.append("candidate_attempts does not equal emitted + duplicate_dropped")
    if counters.get("dropped") != counters.get("duplicate_dropped"):
        malformed.append("dropped does not match duplicate_dropped")
    if counters.get("cap_dropped") != counters.get("truncated_candidates_lower_bound"):
        malformed.append("cap_dropped does not match truncated_candidates_lower_bound")
    if counters.get("truncated_candidates_lower_bound") != (
        counters.get("truncated_candidates", 0)
        + counters.get("truncated_candidates_unknown", 0)
    ):
        malformed.append(
            "truncated_candidates_lower_bound does not equal exact + unknown lower bounds"
        )

    for counter_name in pass_counter_names:
        pass_total = sum(stats[counter_name] for stats in normalized_passes.values())
        if pass_total != counters.get(counter_name):
            malformed.append(
                f"passes {counter_name} total {pass_total} does not match global "
                f"{counters.get(counter_name)!r}"
            )
    if isinstance(capped_passes, Mapping):
        capped_names = {
            pass_name
            for pass_name, count in capped_passes.items()
            if isinstance(pass_name, str)
            and pass_name
            and isinstance(count, int)
            and not isinstance(count, bool)
            and count > 0
        }
        telemetry_capped_names = {
            pass_name
            for pass_name, stats in normalized_passes.items()
            if stats["cap_dropped"] > 0
        }
        if capped_names != telemetry_capped_names:
            malformed.append("capped_passes names do not match capped per-pass telemetry")
        for pass_name in capped_names & normalized_passes.keys():
            count = capped_passes[pass_name]
            if isinstance(count, int) and count > normalized_passes[pass_name]["cap_dropped"]:
                malformed.append(
                    f"capped_passes.{pass_name} exceeds its cap_dropped lower bound"
                )
    if malformed:
        return [f"malformed telemetry: {', '.join(malformed)}"], []

    truncation: list[str] = []
    if counters["cap_dropped"]:
        truncation.append(f"cap_dropped={counters['cap_dropped']}")
    if counters["truncated_candidates"]:
        truncation.append(f"truncated_candidates={counters['truncated_candidates']}")
    if counters["truncated_candidates_lower_bound"]:
        truncation.append(
            "truncated_candidates_lower_bound="
            f"{counters['truncated_candidates_lower_bound']}"
        )
    if counters["truncated_candidates_unknown"]:
        truncation.append(
            f"truncated_candidates_unknown={counters['truncated_candidates_unknown']}"
        )
    if capped_passes:
        truncation.append(f"capped_passes={_stable_graph_value(capped_passes)}")
    return [], truncation


def _graph_truncation_reasons(graph: CorrelationGraph) -> list[str]:
    malformed, truncation = _graph_telemetry_reasons(graph)
    return [*malformed, *truncation]


def _correlate_findings(findings: Sequence[Finding]) -> CorrelationGraph:
    copied_findings = [finding.model_copy(deep=True) for finding in findings]
    return Correlator().correlate(copied_findings)


def _graph_structure_reasons(
    graph: CorrelationGraph,
    findings: Sequence[Finding],
) -> list[str]:
    finding_ids = [finding.id for finding in findings]
    valid_ids = set(finding_ids)
    reasons: list[str] = []
    if len(finding_ids) != len(valid_ids):
        reasons.append("finding IDs are not unique")
    edge_signatures: set[tuple[str, str, EdgeType, str]] = set()
    for index, edge in enumerate(graph.edges):
        if edge.source_id not in valid_ids or edge.target_id not in valid_ids:
            reasons.append(f"edge[{index}] references an unknown finding")
        if edge.source_id == edge.target_id:
            reasons.append(f"edge[{index}] is a self-edge")
        signature = (edge.source_id, edge.target_id, edge.edge_type, edge.reasoning)
        if signature in edge_signatures:
            reasons.append(f"edge[{index}] duplicates an emitted edge")
        edge_signatures.add(signature)
    cluster_ids: set[str] = set()
    for index, cluster in enumerate(graph.clusters):
        if cluster.id in cluster_ids:
            reasons.append(f"cluster[{index}] duplicates a cluster ID")
        cluster_ids.add(cluster.id)
        if len(cluster.finding_ids) != len(set(cluster.finding_ids)):
            reasons.append(f"cluster[{index}] contains duplicate finding IDs")
        if any(finding_id not in valid_ids for finding_id in cluster.finding_ids):
            reasons.append(f"cluster[{index}] references an unknown finding")
    return reasons


def _finding_permutations(
    findings: Sequence[Finding],
) -> list[tuple[str, tuple[Finding, ...]]]:
    original = tuple(findings)
    candidates: list[tuple[str, tuple[Finding, ...]]] = [
        ("reversed", tuple(reversed(original))),
    ]
    if len(original) >= 3:
        candidates.extend(
            [
                ("rotated", (*original[1:], original[0])),
                ("interleaved", (*original[::2], *original[1::2])),
            ]
        )
    original_ids = tuple(finding.id for finding in original)
    seen = {original_ids}
    unique: list[tuple[str, tuple[Finding, ...]]] = []
    for name, permutation in candidates:
        signature = tuple(finding.id for finding in permutation)
        if signature in seen:
            continue
        seen.add(signature)
        unique.append((name, permutation))
    return unique


def _evaluate_graph_expectation(
    case_id: str,
    expectation: GraphExpectation,
    findings: Sequence[Finding],
) -> tuple[list[str], dict[str, Any] | None]:
    try:
        graph = _correlate_findings(findings)
        observed_edge_types = {edge.edge_type for edge in graph.edges}
    except Exception as exc:
        return [f"{case_id}: graph correlation failed ({type(exc).__name__})"], None

    failures: list[str] = []
    observation = _graph_observation(graph, findings)
    structure_reasons = _graph_structure_reasons(graph, findings)
    if structure_reasons:
        failures.append(f"{case_id}: graph integrity failed: {structure_reasons}")
    malformed_telemetry, truncation_reasons = _graph_telemetry_reasons(graph)
    if malformed_telemetry:
        failures.append(f"{case_id}: graph telemetry integrity failed: {malformed_telemetry}")
    if len(graph.edges) < expectation.min_edges:
        failures.append(
            f"{case_id}: graph edge count {len(graph.edges)} < min_edges "
            f"{expectation.min_edges}"
        )
    missing_edge_types = sorted(
        edge_type.value
        for edge_type in expectation.required_edge_types
        if edge_type not in observed_edge_types
    )
    if missing_edge_types:
        observed = sorted(edge_type.value for edge_type in observed_edge_types)
        failures.append(
            f"{case_id}: graph missing required edge types {missing_edge_types}; "
            f"observed={observed}"
        )
    if expectation.must_not_truncate:
        if truncation_reasons:
            failures.append(
                f"{case_id}: graph truncation/drop detected: {truncation_reasons}"
            )

    if expectation.permutation_invariant:
        forward_signature = _graph_signature(graph)
        forward_hash = hashlib.sha256(forward_signature.encode()).hexdigest()[:16]
        for permutation_name, permutation in _finding_permutations(findings):
            try:
                permuted_graph = _correlate_findings(permutation)
            except Exception as exc:
                failures.append(
                    f"{case_id}: {permutation_name} graph correlation failed "
                    f"({type(exc).__name__})"
                )
                continue
            permuted_structure = _graph_structure_reasons(permuted_graph, findings)
            if permuted_structure:
                failures.append(
                    f"{case_id}: {permutation_name} graph integrity failed: "
                    f"{permuted_structure}"
                )
            permuted_malformed, permuted_truncation = _graph_telemetry_reasons(permuted_graph)
            if permuted_malformed:
                failures.append(
                    f"{case_id}: {permutation_name} graph telemetry integrity failed: "
                    f"{permuted_malformed}"
                )
            permuted_signature = _graph_signature(permuted_graph)
            if forward_signature != permuted_signature:
                permuted_hash = hashlib.sha256(permuted_signature.encode()).hexdigest()[:16]
                failures.append(
                    f"{case_id}: graph signature changed for {permutation_name} findings; "
                    f"forward={forward_hash}, {permutation_name}={permuted_hash}"
                )
            if expectation.must_not_truncate and permuted_truncation:
                failures.append(
                    f"{case_id}: {permutation_name} graph truncation/drop detected: "
                    f"{permuted_truncation}"
                )
    return failures, observation


def _analyze_case(
    case: CorpusCase,
) -> tuple[
    list[Prediction],
    bool,
    list[str],
    list[Mapping[str, Any]],
    str,
    list[str],
    dict[str, Any] | None,
]:
    source = case.asset.read_text(encoding="utf-8")
    parsed = parse_js(source, language_hint=_LANGUAGE_HINTS[case.language])
    parser_errors = list(parsed.errors)
    if not parsed.success or parsed.ast is None:
        unavailable_graph_failures = (
            [f"{case.case_id}: graph unavailable because parsing failed"]
            if case.graph is not None
            else []
        )
        return [], False, parser_errors, [], parsed.parser_used, unavailable_graph_failures, None
    file_hash = hashlib.sha256(source.encode("utf-8")).hexdigest()
    ir = build_ir(parsed.ast, case.asset.as_uri(), file_hash)
    engine = RuleEngine(Config().rules)
    engine.register_defaults()
    context = AnalysisContext(
        file_url=case.asset.as_uri(),
        file_hash=file_hash,
        source_content=source,
    )
    findings = engine.analyze(ir, context)
    raw_incomplete = context.metadata.get("analysis_incomplete", [])
    detector_incomplete: list[Mapping[str, Any]] = []
    if isinstance(raw_incomplete, list):
        for event in raw_incomplete:
            if isinstance(event, Mapping):
                detector_incomplete.append(dict(event))
            else:
                detector_incomplete.append({
                    "component": "validation",
                    "reason": "malformed_analysis_incomplete_event",
                    "partial_results": True,
                    "value_type": type(event).__name__,
                })
    elif raw_incomplete:
        detector_incomplete.append({
            "component": "validation",
            "reason": "malformed_analysis_incomplete_collection",
            "partial_results": True,
            "value_type": type(raw_incomplete).__name__,
        })
    predictions = []
    for finding in findings:
        prediction = Prediction.from_finding(finding)
        if prediction.category not in case.evaluated_categories:
            continue
        # Subtype declarations scope subtype-specific expectations; they must never hide an
        # unexpected prediction from the parent category's false-positive accounting.
        predictions.append(prediction)
    partial = bool(parsed.partial or ir.partial)
    parser_errors.extend(ir.errors)
    graph_failures: list[str] = []
    graph_observation: dict[str, Any] | None = None
    if case.graph is not None:
        graph_failures, graph_observation = _evaluate_graph_expectation(
            case.case_id,
            case.graph,
            findings,
        )
    return (
        predictions,
        partial,
        parser_errors,
        detector_incomplete,
        parsed.parser_used,
        graph_failures,
        graph_observation,
    )


def run_corpus(
    corpus_root: Path,
    *,
    manifest_path: Path | None = None,
    gates_path: Path | None = None,
    required_gate_keys: frozenset[str] | None = None,
) -> ValidationResult:
    """Analyze all manifest cases and evaluate strict metrics and release gates."""
    cases = load_manifest(corpus_root, manifest_path)
    gate_specs = load_gates(gates_path)
    if required_gate_keys is not None:
        actual_gate_keys = {gate.key for gate in gate_specs}
        missing_gate_keys = sorted(required_gate_keys - actual_gate_keys)
        if missing_gate_keys:
            raise CorpusError(f"release gate file is missing required keys: {missing_gate_keys}")
        extra_gate_keys = sorted(actual_gate_keys - required_gate_keys)
        if extra_gate_keys:
            raise CorpusError(f"release gate file has unexpected keys: {extra_gate_keys}")
    metrics: dict[str, DetectionMetric] = {}
    forbidden_hits: list[str] = []
    completeness_failures: list[str] = []
    parser_failures: list[str] = []
    graph_failures: list[str] = []
    graph_observations: dict[str, Mapping[str, Any]] = {}
    predictions_by_group: dict[
        str,
        list[tuple[str, Counter[tuple[str, str, str, str, bool, str, str]]]],
    ] = defaultdict(list)
    total_predictions = 0
    total_labels = 0

    for case in cases:
        counts_before_case = {
            key: (metric.tp, metric.fp, metric.fn, metric.tn)
            for key, metric in metrics.items()
        }
        fp_before_case = {
            key: counts[1]
            for key, counts in counts_before_case.items()
        }
        (
            predictions,
            partial,
            errors,
            detector_incomplete,
            parser_used,
            case_graph_failures,
            case_graph_observation,
        ) = _analyze_case(case)
        graph_failures.extend(case_graph_failures)
        if case_graph_observation is not None:
            graph_observations[case.case_id] = case_graph_observation
        total_predictions += len(predictions)
        total_labels += len(case.labels)
        if case.parser_expectation in {"full_ast", "full"} and (partial or errors):
            parser_failures.append(f"{case.case_id}: expected full AST, got {parser_used} partial={partial} errors={errors}")
        elif case.parser_expectation == "full_or_recovered_ast" and parser_used == "regex":
            parser_failures.append(f"{case.case_id}: regex-only parser cannot satisfy full_or_recovered_ast")
        elif case.parser_expectation not in {"full_ast", "full", "full_or_recovered_ast", "partial_allowed"}:
            parser_failures.append(f"{case.case_id}: unsupported parser expectation {case.parser_expectation!r}")
        if case.must_not_be_partial and (partial or errors or detector_incomplete):
            completeness_failures.append(
                f"{case.case_id}: partial={partial}, errors={errors}, "
                f"analysis_incomplete={detector_incomplete}"
            )

        matching = _maximum_matching(case.labels, predictions)
        matched_predictions = set(matching.values())
        for label_index, label in enumerate(case.labels):
            prediction_index = matching.get(label_index)
            if prediction_index is None:
                _record_fn(metrics, label)
            else:
                _record_tp(metrics, label, predictions[prediction_index])
        for prediction_index, prediction in enumerate(predictions):
            if prediction_index not in matched_predictions:
                _record_fp(metrics, prediction)
        _record_contract_metrics(metrics, case.labels, predictions)
        _record_location_metrics(metrics, case.labels, predictions)
        for forbidden in case.forbidden:
            for prediction in predictions:
                if _matches(forbidden, prediction):
                    forbidden_hits.append(
                        f"{case.case_id}: forbidden {prediction.category}/{prediction.subtype} {prediction.value!r}"
                    )
        _record_negative_opportunities(metrics, case.negative_opportunities, fp_before_case)
        for key, metric in metrics.items():
            before_tp, before_fp, before_fn, before_tn = counts_before_case.get(
                key,
                (0, 0, 0, 0),
            )
            if metric.tp > before_tp or metric.fn > before_fn:
                metric.positive_case_ids.add(case.case_id)
                metric.positive_case_fingerprints.add(case.asset_fingerprint)
            if metric.fp > before_fp or metric.tn > before_tn:
                metric.negative_case_ids.add(case.case_id)
                metric.negative_case_fingerprints.add(case.asset_fingerprint)
        if case.semantic_group:
            signature = Counter(prediction.signature() for prediction in predictions)
            predictions_by_group[case.semantic_group].append((case.case_id, signature))

    invariance_failures: list[str] = []
    for group, members in sorted(predictions_by_group.items()):
        if len(members) < 2:
            invariance_failures.append(f"{group}: semantic_group requires at least two cases")
            continue
        reference_id, reference = members[0]
        for case_id, signature in members[1:]:
            if signature != reference:
                lost = list((reference - signature).elements())
                added = list((signature - reference).elements())
                invariance_failures.append(
                    f"{group}: {case_id} differs from {reference_id}; lost={lost}, added={added}"
                )

    gates = [_evaluate_gate(spec, metrics) for spec in gate_specs]
    return ValidationResult(
        metrics=metrics,
        gates=gates,
        case_count=len(cases),
        prediction_count=total_predictions,
        label_count=total_labels,
        forbidden_hits=forbidden_hits,
        completeness_failures=completeness_failures,
        parser_failures=parser_failures,
        invariance_failures=invariance_failures,
        graph_failures=graph_failures,
        corpus_fingerprint=_corpus_fingerprint(cases),
        gate_profile_fingerprint=_gate_profile_fingerprint(gate_specs),
        graph_observations=graph_observations,
    )


def _validate_sha256(value: object, location: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or value != value.lower()
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise CorpusError(f"{location} must be a lowercase SHA-256 hex digest")
    return value


def _validate_baseline_ratio(value: object, location: str) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or not 0 <= float(value) <= 1
    ):
        raise CorpusError(f"{location} must be a finite ratio between 0 and 1")
    return float(value)


def _validate_regression_baseline(raw: object, location: str) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise CorpusError(f"{location}: baseline root must be an object")
    _reject_unknown_keys(raw, _BASELINE_FIELDS, location)
    if set(raw) != set(_BASELINE_FIELDS):
        missing = sorted(_BASELINE_FIELDS - raw.keys())
        raise CorpusError(f"{location}: baseline is missing fields {missing}")
    schema_version = raw["schema_version"]
    if (
        isinstance(schema_version, bool)
        or not isinstance(schema_version, int)
        or schema_version != BASELINE_SCHEMA_VERSION
    ):
        raise CorpusError(
            f"{location}.schema_version must equal {BASELINE_SCHEMA_VERSION}"
        )
    if raw["profile"] != RELEASE_PROFILE:
        raise CorpusError(f"{location}.profile must equal {RELEASE_PROFILE!r}")
    canonicalizer_version = raw["canonicalizer_version"]
    if (
        isinstance(canonicalizer_version, bool)
        or not isinstance(canonicalizer_version, int)
        or canonicalizer_version != CANONICALIZER_VERSION
    ):
        raise CorpusError(
            f"{location}.canonicalizer_version must equal {CANONICALIZER_VERSION}"
        )
    _validate_sha256(raw["corpus_fingerprint"], f"{location}.corpus_fingerprint")
    _validate_sha256(
        raw["gate_profile_fingerprint"],
        f"{location}.gate_profile_fingerprint",
    )

    required_keys = raw["required_gate_keys"]
    if not isinstance(required_keys, list) or required_keys != sorted(RELEASE_GATE_KEYS):
        raise CorpusError(
            f"{location}.required_gate_keys must exactly match the release profile"
        )
    top_level_counts = {
        field_name: _non_negative_int(raw[field_name], f"{location}.{field_name}")
        for field_name in ("case_count", "label_count", "prediction_count")
    }

    metrics = raw["metrics"]
    if not isinstance(metrics, dict):
        raise CorpusError(f"{location}.metrics must be an object")
    metric_keys = set(metrics)
    if metric_keys != RELEASE_BASELINE_METRIC_KEYS:
        missing = sorted(RELEASE_BASELINE_METRIC_KEYS - metric_keys)
        extra = sorted(metric_keys - RELEASE_BASELINE_METRIC_KEYS)
        raise CorpusError(
            f"{location}.metrics must contain the exact release metric keys; "
            f"missing={missing}, extra={extra}"
        )
    for key, metric in metrics.items():
        metric_location = f"{location}.metrics.{key}"
        if not isinstance(metric, dict):
            raise CorpusError(f"{metric_location} must be an object")
        _reject_unknown_keys(metric, _BASELINE_METRIC_FIELDS, metric_location)
        if set(metric) != set(_BASELINE_METRIC_FIELDS):
            missing = sorted(_BASELINE_METRIC_FIELDS - metric.keys())
            raise CorpusError(f"{metric_location} is missing fields {missing}")
        metric_counts = {
            field_name: _non_negative_int(metric[field_name], f"{metric_location}.{field_name}")
            for field_name in (
                "tp",
                "fp",
                "fn",
                "tn",
                "positive_case_count",
                "negative_case_count",
            )
        }
        for field_name in ("positive_case_count", "negative_case_count"):
            if metric_counts[field_name] > top_level_counts["case_count"]:
                raise CorpusError(
                    f"{metric_location}.{field_name} exceeds baseline case_count"
                )
        positive_samples = metric_counts["tp"] + metric_counts["fn"]
        if metric_counts["positive_case_count"] > positive_samples:
            raise CorpusError(
                f"{metric_location}.positive_case_count exceeds positive samples"
            )
        negative_samples = metric_counts["fp"] + metric_counts["tn"]
        if metric_counts["negative_case_count"] > negative_samples:
            raise CorpusError(
                f"{metric_location}.negative_case_count exceeds negative samples"
            )
        metric_ratios = {
            field_name: _validate_baseline_ratio(
                metric[field_name],
                f"{metric_location}.{field_name}",
            )
            for field_name in (
                "precision",
                "recall",
                "f1",
                "precision_wilson_lower",
                "recall_wilson_lower",
                "f1_wilson_lower",
            )
        }
        derived = DetectionMetric(
            key=key,
            tp=metric_counts["tp"],
            fp=metric_counts["fp"],
            fn=metric_counts["fn"],
            tn=metric_counts["tn"],
        ).to_dict()
        for field_name in (
            "precision",
            "recall",
            "f1",
            "precision_wilson_lower",
            "recall_wilson_lower",
            "f1_wilson_lower",
        ):
            derived_value = derived[field_name]
            if not isinstance(derived_value, (int, float)) or not math.isclose(
                metric_ratios[field_name],
                float(derived_value),
                rel_tol=0.0,
                abs_tol=1e-15,
            ):
                raise CorpusError(
                    f"{metric_location}.{field_name} is inconsistent with metric counts"
                )

    category_prediction_count = sum(
        metrics[key]["tp"] + metrics[key]["fp"]
        for key in SUPPORTED_CATEGORIES
    )
    category_label_count = sum(
        metrics[key]["tp"] + metrics[key]["fn"]
        for key in SUPPORTED_CATEGORIES
    )
    if category_prediction_count != top_level_counts["prediction_count"]:
        raise CorpusError(
            f"{location}.prediction_count is inconsistent with category metrics"
        )
    if category_label_count != top_level_counts["label_count"]:
        raise CorpusError(f"{location}.label_count is inconsistent with category metrics")

    invariants = raw["invariants"]
    if not isinstance(invariants, dict):
        raise CorpusError(f"{location}.invariants must be an object")
    _reject_unknown_keys(invariants, _BASELINE_INVARIANT_FIELDS, f"{location}.invariants")
    if set(invariants) != set(_BASELINE_INVARIANT_FIELDS):
        missing = sorted(_BASELINE_INVARIANT_FIELDS - invariants.keys())
        raise CorpusError(f"{location}.invariants is missing fields {missing}")
    for field_name, value in invariants.items():
        count = _non_negative_int(value, f"{location}.invariants.{field_name}")
        if count != 0:
            raise CorpusError(
                f"{location}.invariants.{field_name} must be zero in a release baseline"
            )

    graph_observations = raw["graph_observations"]
    if not isinstance(graph_observations, dict) or not graph_observations:
        raise CorpusError(f"{location}.graph_observations must be a non-empty object")
    for case_id, observation in graph_observations.items():
        graph_location = f"{location}.graph_observations.{case_id}"
        if not isinstance(case_id, str) or not case_id or not isinstance(observation, dict):
            raise CorpusError(f"{graph_location} must be an object with a non-empty case ID")
        _reject_unknown_keys(observation, _BASELINE_GRAPH_FIELDS, graph_location)
        if set(observation) != set(_BASELINE_GRAPH_FIELDS):
            missing = sorted(_BASELINE_GRAPH_FIELDS - observation.keys())
            raise CorpusError(f"{graph_location} is missing fields {missing}")
        edge_count = _non_negative_int(
            observation["edge_count"],
            f"{graph_location}.edge_count",
        )
        _non_negative_int(
            observation["cluster_count"],
            f"{graph_location}.cluster_count",
        )
        _validate_sha256(
            observation["semantic_sha256"],
            f"{graph_location}.semantic_sha256",
        )
        edge_types = observation["edge_types"]
        if not isinstance(edge_types, dict):
            raise CorpusError(f"{graph_location}.edge_types must be an object")
        unsupported = sorted(set(edge_types) - SUPPORTED_EDGE_TYPES)
        if unsupported:
            raise CorpusError(
                f"{graph_location}.edge_types has unsupported keys {unsupported}"
            )
        for edge_type, count in edge_types.items():
            _non_negative_int(count, f"{graph_location}.edge_types.{edge_type}")
        if sum(edge_types.values()) != edge_count:
            raise CorpusError(f"{graph_location}.edge_types does not sum to edge_count")
    return raw


def load_regression_baseline(path: Path) -> dict[str, Any]:
    """Load a strict committed detection-regression baseline."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise CorpusError(f"invalid regression baseline {path}: {exc}") from exc
    raw = _load_strict_json(text, str(path))
    return _validate_regression_baseline(raw, str(path))


def build_regression_baseline(result: ValidationResult) -> dict[str, Any]:
    """Create a release baseline payload from one fully passing corpus result."""
    if not result.passed:
        raise CorpusError("cannot baseline a failing corpus result")
    if {gate.key for gate in result.gates} != RELEASE_GATE_KEYS:
        raise CorpusError("cannot baseline an incomplete or extended release gate profile")
    if set(result.graph_observations) == set():
        raise CorpusError("cannot baseline a corpus without graph observations")
    missing_metrics = sorted(RELEASE_BASELINE_METRIC_KEYS - result.metrics.keys())
    if missing_metrics:
        raise CorpusError(f"cannot baseline missing release metrics: {missing_metrics}")

    metrics: dict[str, dict[str, Any]] = {}
    for key in sorted(RELEASE_BASELINE_METRIC_KEYS):
        metric = result.metrics[key].to_dict()
        metrics[key] = {
            field_name: metric[field_name]
            for field_name in sorted(_BASELINE_METRIC_FIELDS)
        }
    payload: dict[str, Any] = {
        "schema_version": BASELINE_SCHEMA_VERSION,
        "profile": RELEASE_PROFILE,
        "canonicalizer_version": result.canonicalizer_version,
        "corpus_fingerprint": result.corpus_fingerprint,
        "gate_profile_fingerprint": result.gate_profile_fingerprint,
        "required_gate_keys": sorted(RELEASE_GATE_KEYS),
        "case_count": result.case_count,
        "label_count": result.label_count,
        "prediction_count": result.prediction_count,
        "metrics": metrics,
        "invariants": {
            "failed_gate_count": sum(not gate.passed for gate in result.gates),
            "forbidden_hit_count": len(result.forbidden_hits),
            "completeness_failure_count": len(result.completeness_failures),
            "parser_failure_count": len(result.parser_failures),
            "invariance_failure_count": len(result.invariance_failures),
            "graph_failure_count": len(result.graph_failures),
        },
        "graph_observations": {
            key: dict(value)
            for key, value in sorted(result.graph_observations.items())
        },
    }
    return _validate_regression_baseline(payload, "generated baseline")


def _validate_current_metric_projection(
    key: str,
    metric: DetectionMetric,
) -> tuple[dict[str, Any] | None, list[str]]:
    failures: list[str] = []
    for field_name in ("tp", "fp", "fn", "tn"):
        value = getattr(metric, field_name, None)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            failures.append(
                f"metric {key}.{field_name} has invalid current count {value!r}; "
                "expected a non-negative integer"
            )
    if failures:
        return None, failures

    try:
        projection = metric.to_dict()
    except Exception as exc:
        failures.append(
            f"metric {key} current projection failed ({type(exc).__name__})"
        )
        return None, failures
    if not isinstance(projection, dict):
        return None, [f"metric {key} current projection is not an object"]

    for field_name in (
        "tp",
        "fp",
        "fn",
        "tn",
        "positive_case_count",
        "negative_case_count",
    ):
        value = projection.get(field_name)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            failures.append(
                f"metric {key}.{field_name} has invalid current count {value!r}; "
                "expected a non-negative integer"
            )
    for field_name in (
        "precision",
        "recall",
        "f1",
        "precision_wilson_lower",
        "recall_wilson_lower",
        "f1_wilson_lower",
    ):
        value = projection.get(field_name)
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(float(value))
            or not 0 <= float(value) <= 1
        ):
            failures.append(
                f"metric {key}.{field_name} has invalid current ratio {value!r}; "
                "expected a finite value between 0 and 1"
            )
    return (None if failures else projection), failures


def evaluate_regression_baseline(
    result: ValidationResult,
    baseline: Mapping[str, Any],
) -> list[str]:
    """Return every metric, identity or invariant regression from a strict baseline."""
    validated = _validate_regression_baseline(dict(baseline), "baseline")
    failures: list[str] = []
    identity_fields = (
        "canonicalizer_version",
        "corpus_fingerprint",
        "gate_profile_fingerprint",
        "case_count",
        "label_count",
        "prediction_count",
    )
    current_identity = {
        "canonicalizer_version": result.canonicalizer_version,
        "corpus_fingerprint": result.corpus_fingerprint,
        "gate_profile_fingerprint": result.gate_profile_fingerprint,
        "case_count": result.case_count,
        "label_count": result.label_count,
        "prediction_count": result.prediction_count,
    }
    for field_name in identity_fields:
        if current_identity[field_name] != validated[field_name]:
            failures.append(
                f"identity.{field_name} changed: current={current_identity[field_name]!r}, "
                f"baseline={validated[field_name]!r}"
            )
    current_gate_keys = sorted(gate.key for gate in result.gates)
    if current_gate_keys != validated["required_gate_keys"]:
        failures.append("release gate keys differ from the committed baseline profile")

    baseline_metrics = validated["metrics"]
    for key in sorted(RELEASE_BASELINE_METRIC_KEYS):
        metric = result.metrics.get(key)
        if metric is None:
            failures.append(f"metric {key!r} is missing from the current result")
            continue
        current, projection_failures = _validate_current_metric_projection(key, metric)
        failures.extend(projection_failures)
        if current is None:
            continue
        previous = baseline_metrics[key]
        for field_name in ("tp", "tn", "positive_case_count", "negative_case_count"):
            if current[field_name] < previous[field_name]:
                failures.append(
                    f"metric {key}.{field_name} regressed: "
                    f"current={current[field_name]}, baseline={previous[field_name]}"
                )
        for field_name in ("fp", "fn"):
            if current[field_name] > previous[field_name]:
                failures.append(
                    f"metric {key}.{field_name} regressed: "
                    f"current={current[field_name]}, baseline={previous[field_name]}"
                )
        for field_name in (
            "precision",
            "recall",
            "f1",
            "precision_wilson_lower",
            "recall_wilson_lower",
            "f1_wilson_lower",
        ):
            current_value = current[field_name]
            if float(current_value) + 1e-15 < previous[field_name]:
                failures.append(
                    f"metric {key}.{field_name} regressed: "
                    f"current={current_value!r}, baseline={previous[field_name]}"
                )

    current_invariants = {
        "failed_gate_count": sum(not gate.passed for gate in result.gates),
        "forbidden_hit_count": len(result.forbidden_hits),
        "completeness_failure_count": len(result.completeness_failures),
        "parser_failure_count": len(result.parser_failures),
        "invariance_failure_count": len(result.invariance_failures),
        "graph_failure_count": len(result.graph_failures),
    }
    for field_name, previous in validated["invariants"].items():
        if current_invariants[field_name] > previous:
            failures.append(
                f"invariant {field_name} regressed: "
                f"current={current_invariants[field_name]}, baseline={previous}"
            )
    current_graph = {
        key: dict(value)
        for key, value in sorted(result.graph_observations.items())
    }
    if current_graph != validated["graph_observations"]:
        failures.append("graph observations differ from the committed semantic baseline")
    return failures
