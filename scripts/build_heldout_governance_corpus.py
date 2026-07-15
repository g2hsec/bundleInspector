"""Build the deterministic 11-case frozen governance detection corpus."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.build_detection_corpus import _case, _write_asset  # noqa: E402

DEFAULT_ROOT = REPO_ROOT / "tests" / "heldout" / "source" / "corpus"
PUBLIC_GATES = REPO_ROOT / "tests" / "corpus" / "gates.json"


@dataclass
class _CaseBuilder:
    case_id: str
    filename: str
    lines: list[str] = field(default_factory=list)
    labels: list[dict[str, object]] = field(default_factory=list)
    categories: set[str] = field(default_factory=set)
    subtypes: dict[str, set[str]] = field(default_factory=dict)
    negatives: dict[str, int] = field(default_factory=dict)
    tags: set[str] = field(default_factory=lambda: {"frozen-governance", "synthetic"})
    graph: dict[str, object] | None = None

    def line(self, source: str) -> int:
        self.lines.append(source)
        return len(self.lines)

    def label(self, category: str, *, line: int, **values: object) -> None:
        label: dict[str, object] = {"category": category, "line": line, **values}
        self.labels.append(label)
        self.categories.add(category)
        subtype = values.get("subtype")
        if isinstance(subtype, str):
            self.subtypes.setdefault(category, set()).add(subtype)

    def evaluate(self, category: str, *subtypes: str) -> None:
        self.categories.add(category)
        self.subtypes.setdefault(category, set()).update(subtypes)

    def add_negative(self, key: str, count: int) -> None:
        self.negatives[key] = self.negatives.get(key, 0) + count

    def manifest_entry(self, root: Path) -> dict[str, object]:
        asset = _write_asset(root, f"generated/{self.filename}", self.lines)
        evaluated_subtypes = {
            category: sorted(values)
            for category, values in sorted(self.subtypes.items())
            if values
        }
        return _case(
            self.case_id,
            asset,
            labels=self.labels,
            evaluated_categories=sorted(self.categories),
            evaluated_subtypes=evaluated_subtypes,
            negative_opportunities=dict(sorted(self.negatives.items())),
            tags=sorted(self.tags),
            graph=self.graph,
        )


def _add_safe_dom(builder: _CaseBuilder, count: int, prefix: str, variant: int) -> None:
    builder.evaluate("sink", "dom_html_sink", "taint_flow")
    for index in range(count):
        value = f"<span>frozen {prefix} {index:03d}</span>"
        if variant % 5 == 0:
            source = (
                f'let cleanMarkup{prefix}{index:03d}="{value}";'
                f"governancePane.innerHTML=cleanMarkup{prefix}{index:03d};"
            )
        elif variant % 5 == 1:
            source = (
                f'const cleanBox{prefix}{index:03d}={{markup:"{value}"}};'
                f"governancePane.innerHTML=cleanBox{prefix}{index:03d}.markup;"
            )
        elif variant % 5 == 2:
            source = (
                f'const cleanParts{prefix}{index:03d}=["{value}"];'
                f"governancePane.innerHTML=cleanParts{prefix}{index:03d}[0];"
            )
        elif variant % 5 == 3:
            source = (
                f'function cleanMarkup{prefix}{index:03d}(){{return "{value}";}}'
                f"governancePane.innerHTML=cleanMarkup{prefix}{index:03d}();"
            )
        else:
            source = (
                f'const cleanMap{prefix}{index:03d}=new Map([["markup","{value}"]]);'
                f'governancePane.innerHTML=cleanMap{prefix}{index:03d}.get("markup");'
            )
        line = builder.line(source)
        builder.label(
            "sink",
            subtype="dom_html_sink",
            value="innerHTML=",
            line=line,
        )


def _add_secret_positive(builder: _CaseBuilder, offset: int, *, row_style: bool = False) -> None:
    builder.evaluate("secret", "aws_access_key", "potential_secret")
    builder.line("const frozenCredentialRegistry = [" if row_style else "const frozenCredentialRegistry = {")
    for index in range(75):
        value = f"AKIA9{offset + index:015d}"
        line = builder.line(
            f'  [{index}, "{value}"],'
            if row_style
            else f'  cloudCredential{index:03d}: "{value}",'
        )
        builder.label(
            "secret",
            subtype="aws_access_key",
            value=value,
            line=line,
        )
    for index in range(63):
        value = f"Qv7N{offset + index:05d}Zx4P8mK2rT6wY9cH3sJ5dF1a"
        line = builder.line(
            f'  [{index + 75}, "{value}"],'
            if row_style
            else f'  sessionToken{index:03d}: "{value}",'
        )
        builder.label(
            "secret",
            subtype="potential_secret",
            value=value,
            line=line,
        )
    builder.line("];" if row_style else "};")


def _add_endpoint_negatives(builder: _CaseBuilder, count: int, prefix: str) -> None:
    builder.evaluate("endpoint", "api_endpoint", "client_route")
    for index in range(count):
        builder.line(f'const staticIllustration{prefix}{index:03d}="/media/{prefix}/icon-{index:03d}.svg";')
    for index in range(200):
        builder.line(f'const breadcrumb{prefix}{index:03d}="workspace section {prefix} {index:03d}";')
    builder.add_negative("endpoint", count)
    builder.add_negative("endpoint/client_route", 200)


def _add_contracts(builder: _CaseBuilder, start: int, count: int, variant: int) -> None:
    builder.evaluate("endpoint", "api_endpoint", "client_route")
    for index in range(start, start + count):
        value = f"/svc/governance/accounts/{index:03d}?cursor={index}"
        request = (
            f'fetch("{value}",{{body:JSON.stringify({{account:"frozen-{index:03d}"}}),'
            f'headers:{{Authorization:"Bearer synthetic","X-Governance":"batch-{index:03d}"}},'
            'method:"PATCH"})'
        )
        if variant == 0:
            source = f"void {request};"
        elif variant == 1:
            source = f"Promise.resolve({request});"
        else:
            source = f"{request}.catch(handleFrozenRequestError);"
        line = builder.line(source)
        builder.label(
            "endpoint",
            subtype="api_endpoint",
            value=value,
            method="PATCH",
            line=line,
            contract={
                "method": "PATCH",
                "headers": {"X-Governance": f"batch-{index:03d}"},
                "auth": {"scheme": "bearer", "in": "header"},
                "query_params": {"cursor": str(index)},
                "body": {"kind": "json", "shape": {"account": "string"}},
            },
        )


def _add_routes(builder: _CaseBuilder, start: int, count: int) -> None:
    builder.evaluate("endpoint", "api_endpoint", "client_route")
    for index in range(start, start + count):
        value = f"/workspace/frozen/review/{index:03d}"
        line = builder.line(
            f'const routes{index:03d}=[{{path:"{value}",component:Review{index:03d}}}];'
        )
        builder.label(
            "endpoint",
            subtype="client_route",
            value=value,
            line=line,
        )


def _add_direct_endpoints(builder: _CaseBuilder, count: int) -> None:
    builder.evaluate("endpoint", "api_endpoint")
    for index in range(count):
        value = f"/svc/frozen/catalog/{index:03d}"
        line = builder.line(f'queueMicrotask(()=>fetch("{value}",{{method:"GET"}}));')
        builder.label("endpoint", value=value, method="GET", line=line)


def _add_confirmed_flows(builder: _CaseBuilder, start: int, count: int) -> None:
    builder.evaluate("sink", "dom_html_sink", "taint_flow")
    for index in range(start, start + count):
        line = builder.line(
            f"function paintFrozen{index:03d}(){{governancePane.innerHTML=window.location.hash;}}"
        )
        builder.label(
            "sink",
            subtype="taint_flow",
            value="URL/location -> innerhtml=",
            expected_state="confirmed",
            line=line,
        )
        builder.label(
            "sink",
            subtype="dom_html_sink",
            value="innerHTML=",
            line=line,
        )


def _add_probable_flows(builder: _CaseBuilder, start: int, count: int) -> None:
    builder.evaluate("sink", "dom_html_sink", "taint_flow")
    for index in range(start, start + count):
        line = builder.line(
            f"function stageFrozen{index:03d}(enabled){{let fragment;if(enabled)"
            f"{{fragment=location.search;}}governancePane.innerHTML=fragment;}}"
        )
        builder.label(
            "sink",
            subtype="taint_flow",
            value="URL/location -> innerhtml=",
            expected_state="probable",
            line=line,
        )
        builder.label(
            "sink",
            subtype="dom_html_sink",
            value="innerHTML=",
            line=line,
        )


def _add_positive_families(builder: _CaseBuilder, variant: int) -> None:
    builder.evaluate("domain", "link_local_ip", "internal_domain")
    builder.evaluate("flag", "feature_flag", "flag_sdk")
    builder.evaluate("debug", "debugger_statement", "source_map_reference")
    builder.evaluate("upload", "file_upload", "client_side_file_validation")
    builder.evaluate("endpoint", "webpack_named_chunk")
    if variant == 0:
        for index in range(25):
            value = f"169.254.{index + 30}.{index + 80}"
            line = builder.line(f'const governanceProbe{index:03d}="http://{value}/ready";')
            builder.label("domain", subtype="link_local_ip", value=value, line=line)
        for index in range(25):
            value = f"feature_flag_governance_review_{index:03d}"
            line = builder.line(f'const governanceFlag{index:03d}="{value}";')
            builder.label("flag", subtype="feature_flag", value=value, line=line)
        for index in range(25):
            line = builder.line(f"function frozenInspect{index:03d}(){{void 0;debugger;}}")
            builder.label("debug", subtype="debugger_statement", value="debugger", line=line)
        for index in range(25):
            line = builder.line(
                f'const frozenForm{index:03d}=new FormData();frozenForm{index:03d}.append("file",blob{index:03d});'
            )
            builder.label("upload", subtype="file_upload", value="new FormData()", line=line)
        quote = '"'
        chunk_prefix = "governance-a"
    else:
        for index in range(25):
            value = f"review-{index:03d}.governance.internal"
            line = builder.line(f'const governanceService{index:03d}="https://{value}/ready";')
            builder.label("domain", subtype="internal_domain", value=value, line=line)
        builder.line('import LDClient from "launchdarkly-js-client-sdk";')
        builder.line('const governanceFlags=LDClient.initialize("synthetic-governance");')
        for index in range(25):
            value = f"frozen-review-{index:03d}"
            line = builder.line(f'governanceFlags.variation("{value}",false);')
            builder.label("flag", subtype="flag_sdk", value=value, line=line)
        for index in range(25):
            value = f"frozen-governance-{index:03d}.js.map"
            line = builder.line(f"//# sourceMappingURL={value}")
            builder.label("debug", subtype="source_map_reference", value=value, line=line)
        for index in range(25):
            line = builder.line(
                f'const frozenPolicy{index:03d}={{allowedExt:["webp","avif"],maxSize:{index + 2}000}};'
            )
            builder.label(
                "upload",
                subtype="client_side_file_validation",
                value="allowedExt",
                line=line,
            )
        quote = "'"
        chunk_prefix = "governance-b"
    for index in range(25):
        value = f"{chunk_prefix}-{index:03d} -> ./FrozenPanel{variant}{index:03d}"
        line = builder.line(
            f"void import(/* webpackChunkName: {quote}{chunk_prefix}-{index:03d}{quote} */ "
            f"{quote}./FrozenPanel{variant}{index:03d}{quote});"
        )
        builder.label(
            "endpoint",
            subtype="webpack_named_chunk",
            value=value,
            line=line,
        )


def _add_family_negatives(builder: _CaseBuilder, count: int, prefix: str) -> None:
    for category in ("domain", "flag", "debug", "upload"):
        builder.evaluate(category)
        builder.add_negative(category, count)
    builder.evaluate("endpoint", "webpack_named_chunk")
    builder.add_negative("endpoint/webpack_named_chunk", count)
    for index in range(count):
        builder.line(
            f'const governanceControl{prefix}{index:03d}={{label:"review control {prefix} {index:03d}",enabled:false}};'
        )


def _add_secret_negatives(builder: _CaseBuilder, count: int, prefix: str) -> None:
    builder.evaluate("secret", "aws_access_key", "potential_secret")
    builder.add_negative("secret", count)
    builder.add_negative("secret/aws_access_key", count)
    builder.add_negative("secret/potential_secret", count)
    for index in range(count):
        builder.line(f'const helpText{prefix}{index:03d}="review guidance item {index:03d}";')


def _add_dom_negatives(builder: _CaseBuilder, count: int, prefix: str) -> None:
    builder.evaluate("sink", "dom_html_sink")
    builder.add_negative("sink", count)
    builder.add_negative("sink/dom_html_sink", count)
    for index in range(count):
        builder.line(f'governancePane.textContent="safe review text {prefix} {index:03d}";')


def _load_heldout_gates() -> dict[str, Any]:
    raw = json.loads(PUBLIC_GATES.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or not isinstance(raw.get("gates"), list):
        raise ValueError("public release gate profile is invalid")
    public_gates = raw["gates"]
    if not all(isinstance(gate, dict) for gate in public_gates):
        raise ValueError("public release gate profile is invalid")
    result: dict[str, Any] = {
        "gates": [dict(gate) for gate in public_gates],
    }
    location_gate = next(
        (gate for gate in result["gates"] if gate.get("key") == "location"),
        None,
    )
    if not isinstance(location_gate, dict) or location_gate.get("min_positive_cases") != 20:
        raise ValueError("unexpected public location diversity contract")
    location_gate["min_positive_cases"] = 11
    return result


def build_corpus(root: Path) -> tuple[int, int]:
    root = root.resolve()
    cases = [
        _CaseBuilder("governance-credential-object-a", "credential_object_a.js"),
        _CaseBuilder("governance-credential-object-b", "credential_object_b.js"),
        _CaseBuilder("governance-contract-batch-a", "contract_batch_a.js"),
        _CaseBuilder("governance-contract-batch-b", "contract_batch_b.js"),
        _CaseBuilder("governance-contract-batch-c", "contract_batch_c.js"),
        _CaseBuilder("governance-endpoint-batch", "endpoint_batch.js"),
        _CaseBuilder("governance-surface-a", "surface_a.js"),
        _CaseBuilder("governance-surface-b", "surface_b.js"),
        _CaseBuilder("governance-confirmed-boundary", "confirmed_boundary.js"),
        _CaseBuilder("governance-probable-a", "probable_a.js"),
        _CaseBuilder("governance-probable-b", "probable_b.js"),
    ]

    for index, builder in enumerate(cases):
        _add_safe_dom(
            builder,
            102 if index < 5 else 46,
            chr(ord("a") + index),
            index,
        )
    _add_secret_positive(cases[0], 10_000)
    _add_secret_positive(cases[1], 20_000, row_style=True)
    _add_endpoint_negatives(cases[0], 200, "a")
    _add_endpoint_negatives(cases[1], 200, "b")
    for builder in cases[:5]:
        builder.add_negative("sink/taint_flow", 102)
        builder.add_negative("sink/taint_flow@confirmed", 102)
        builder.add_negative("sink/taint_flow@probable", 102)

    for variant, (builder, start, count) in enumerate(
        zip(cases[2:5], (0, 42, 84), (42, 42, 41), strict=True)
    ):
        _add_contracts(builder, start, count, variant)
    for builder, start in zip(cases[2:5], (0, 50, 100), strict=True):
        _add_routes(builder, start, 50)
    _add_direct_endpoints(cases[5], 100)
    _add_confirmed_flows(cases[6], 0, 43)
    _add_confirmed_flows(cases[7], 43, 42)
    _add_confirmed_flows(cases[8], 85, 42)
    _add_probable_flows(cases[9], 0, 63)
    _add_probable_flows(cases[10], 63, 63)
    _add_positive_families(cases[6], 0)
    _add_positive_families(cases[7], 1)
    cases[6].graph = {
        "required_edge_types": ["same_file"],
        "min_edges": 1,
        "permutation_invariant": True,
    }

    _add_secret_negatives(cases[8], 300, "a")
    _add_secret_negatives(cases[9], 300, "b")
    _add_endpoint_negatives(cases[8], 500, "c")
    cases[8].add_negative("endpoint/api_endpoint", 500)
    _add_family_negatives(cases[8], 250, "a")
    _add_family_negatives(cases[9], 250, "b")
    _add_dom_negatives(cases[8], 300, "a")
    _add_dom_negatives(cases[9], 300, "b")

    root.mkdir(parents=True, exist_ok=True)
    manifest_entries = [builder.manifest_entry(root) for builder in cases]
    referenced = {str(entry["asset"]) for entry in manifest_entries}
    for path in (root / "generated").glob("*"):
        if path.is_file() and path.relative_to(root).as_posix() not in referenced:
            path.unlink()
    (root / "manifest.jsonl").write_text(
        "\n".join(
            json.dumps(entry, allow_nan=False, sort_keys=True)
            for entry in manifest_entries
        ) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    (root / "gates.json").write_text(
        json.dumps(_load_heldout_gates(), allow_nan=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    label_count = sum(len(builder.labels) for builder in cases)
    return len(cases), label_count


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    args = parser.parse_args(argv)
    case_count, label_count = build_corpus(args.root)
    print(json.dumps({"case_count": case_count, "label_count": label_count}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
