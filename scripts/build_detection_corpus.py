"""Build the deterministic synthetic release-gate corpus.

All credential-shaped values are nonfunctional synthetic fixtures. The generated assets are kept
under ``tests/corpus/generated`` and are safe to rebuild in place.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ROOT = REPO_ROOT / "tests" / "corpus"
CORPUS_SOURCE_SUFFIXES = frozenset({".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"})


def _base36(value: int, width: int) -> str:
    alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    encoded = ""
    current = value
    while current:
        current, remainder = divmod(current, len(alphabet))
        encoded = alphabet[remainder] + encoded
    return (encoded or "0").rjust(width, "0")[-width:]


def _write_asset(root: Path, relative: str, lines: list[str]) -> str:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    return relative.replace("\\", "/")


def _case(
    case_id: str,
    asset: str,
    *,
    labels: list[dict[str, object]],
    evaluated_categories: list[str],
    negative_opportunities: dict[str, int] | None = None,
    forbidden: list[dict[str, object]] | None = None,
    evaluated_subtypes: dict[str, list[str]] | None = None,
    semantic_group: str = "",
    tags: list[str] | None = None,
    language: str = "javascript",
    parser_expectation: str = "full_ast",
    graph: dict[str, object] | None = None,
) -> dict[str, object]:
    result: dict[str, object] = {
        "case_id": case_id,
        "asset": asset,
        "language": language,
        "parser_expectation": parser_expectation,
        "labels": labels,
        "forbidden": forbidden or [],
        "evaluated_categories": evaluated_categories,
        "negative_opportunities": negative_opportunities or {},
        "completeness": {"must_not_be_partial": True},
        "tags": tags or [],
    }
    if evaluated_subtypes:
        result["evaluated_subtypes"] = evaluated_subtypes
    if semantic_group:
        result["semantic_group"] = semantic_group
    if graph:
        result["graph"] = graph
    return result


def build_corpus(root: Path) -> tuple[int, int]:
    root = root.resolve()
    generated = root / "generated"
    generated.mkdir(parents=True, exist_ok=True)
    cases: list[dict[str, object]] = []

    known_secret_lines: list[str] = []
    known_secret_labels: list[dict[str, object]] = []
    for index in range(125):
        value = f"AKIA{index:016d}"
        known_secret_lines.append(f'const syntheticAwsKey{index:03d} = "{value}";')
        known_secret_labels.append(
            {
                "category": "secret",
                "subtype": "aws_access_key",
                "value": value,
                "line": index + 1,
            }
        )
    known_asset = _write_asset(root, "generated/secret_known_positive.js", known_secret_lines)
    cases.append(
        _case(
            "secret-known-provider-positive",
            known_asset,
            labels=known_secret_labels,
            evaluated_categories=["secret"],
            evaluated_subtypes={"secret": ["aws_access_key"]},
            tags=["known-provider", "synthetic-invalid-credentials"],
        )
    )

    generic_secret_lines: list[str] = []
    generic_secret_labels: list[dict[str, object]] = []
    for index in range(125):
        value = f"aX9bY2cZmN4pQ7rT8sV1wU3x{_base36(index, 5)}"
        generic_secret_lines.append(f'const syntheticOpaqueToken{index:03d} = "{value}";')
        generic_secret_labels.append(
            {
                "category": "secret",
                "subtype": "potential_secret",
                "value": value,
                "line": index + 1,
            }
        )
    generic_asset = _write_asset(root, "generated/secret_generic_positive.js", generic_secret_lines)
    cases.append(
        _case(
            "secret-generic-positive",
            generic_asset,
            labels=generic_secret_labels,
            evaluated_categories=["secret"],
            evaluated_subtypes={"secret": ["potential_secret"]},
            tags=["generic-entropy", "synthetic-invalid-credentials"],
        )
    )

    secret_negative_lines = [
        f'const componentLabel{index:03d} = "checkout button label number {index:03d}";'
        for index in range(500)
    ]
    secret_negative_asset = _write_asset(root, "generated/secret_negative.js", secret_negative_lines)
    cases.append(
        _case(
            "secret-category-negative",
            secret_negative_asset,
            labels=[],
            evaluated_categories=["secret"],
            evaluated_subtypes={"secret": ["aws_access_key", "potential_secret"]},
            negative_opportunities={
                "secret": 500,
                "secret/aws_access_key": 500,
                "secret/potential_secret": 500,
            },
            tags=["category-negative", "finite-opportunities"],
        )
    )

    endpoint_lines: list[str] = []
    endpoint_labels: list[dict[str, object]] = []
    for index in range(100):
        value = f"/api/corpus/items/{index:03d}"
        endpoint_lines.append(f'fetch("{value}", {{method: "GET"}});')
        endpoint_labels.append(
            {
                "category": "endpoint",
                "value": value,
                "method": "GET",
                "line": index + 1,
            }
        )
    endpoint_asset = _write_asset(root, "generated/endpoint_positive.js", endpoint_lines)
    cases.append(
        _case(
            "endpoint-http-positive",
            endpoint_asset,
            labels=endpoint_labels,
            evaluated_categories=["endpoint"],
            tags=["fetch", "request-contract"],
        )
    )

    contract_lines: list[str] = []
    contract_labels: list[dict[str, object]] = []
    for index in range(125):
        value = f"/api/contracts/{index:03d}?page={index}"
        contract_lines.append(
            f'fetch("{value}", {{method:"DELETE",headers:{{Authorization:"Bearer synthetic",'
            f'"X-Corpus":"case-{index:03d}"}},body:JSON.stringify({{item:"value-{index:03d}"}})}});'
        )
        contract_labels.append(
            {
                "category": "endpoint",
                "subtype": "api_endpoint",
                "value": value,
                "method": "DELETE",
                "line": index + 1,
                "contract": {
                    "method": "DELETE",
                    "headers": {"X-Corpus": f"case-{index:03d}"},
                    "auth": {"scheme": "bearer", "in": "header"},
                    "query_params": {"page": str(index)},
                    "body": {"kind": "json", "shape": {"item": "string"}},
                },
            }
        )
    contract_asset = _write_asset(root, "generated/endpoint_contract_positive.js", contract_lines)
    cases.append(
        _case(
            "endpoint-request-contract-positive",
            contract_asset,
            labels=contract_labels,
            evaluated_categories=["endpoint"],
            evaluated_subtypes={"endpoint": ["api_endpoint"]},
            tags=["method", "headers", "auth", "query", "body"],
        )
    )

    route_lines: list[str] = []
    route_labels: list[dict[str, object]] = []
    for index in range(125):
        value = f"/app/routes/{index:03d}"
        route_lines.append(f'const routes{index:03d}=[{{path:"{value}",component:Page{index:03d}}}];')
        route_labels.append(
            {
                "category": "endpoint",
                "subtype": "client_route",
                "value": value,
                "line": index + 1,
            }
        )
    route_asset = _write_asset(root, "generated/route_positive.js", route_lines)
    cases.append(
        _case(
            "route-positive",
            route_asset,
            labels=route_labels,
            evaluated_categories=["endpoint"],
            evaluated_subtypes={"endpoint": ["client_route"]},
            tags=["generic-router", "route-template"],
        )
    )

    endpoint_negative_lines = [
        f'const staticAsset{index:03d} = "/assets/icons/icon-{index:03d}.svg";'
        for index in range(500)
    ]
    endpoint_negative_asset = _write_asset(root, "generated/endpoint_negative.js", endpoint_negative_lines)
    cases.append(
        _case(
            "endpoint-category-negative",
            endpoint_negative_asset,
            labels=[],
            evaluated_categories=["endpoint"],
            evaluated_subtypes={"endpoint": ["api_endpoint"]},
            negative_opportunities={"endpoint": 500, "endpoint/api_endpoint": 500},
            tags=["category-negative", "static-assets", "finite-opportunities"],
        )
    )

    route_negative_lines = [
        f'const navigationLabel{index:03d}="settings breadcrumb {index:03d}";'
        for index in range(500)
    ]
    route_negative_asset = _write_asset(root, "generated/route_negative.js", route_negative_lines)
    cases.append(
        _case(
            "route-category-negative",
            route_negative_asset,
            labels=[],
            evaluated_categories=["endpoint"],
            evaluated_subtypes={"endpoint": ["client_route"]},
            negative_opportunities={"endpoint/client_route": 500},
            tags=["category-negative", "finite-opportunities"],
        )
    )

    flow_lines: list[str] = []
    flow_labels: list[dict[str, object]] = []
    for index in range(125):
        flow_lines.append(
            f"function render{index:03d}(){{const value{index:03d}=location.hash;target.innerHTML=value{index:03d};}}"
        )
        flow_labels.append(
            {
                "category": "sink",
                "subtype": "taint_flow",
                "value": "URL/location -> innerhtml=",
                "line": index + 1,
                "expected_state": "confirmed",
            }
        )
        flow_labels.append(
            {
                "category": "sink",
                "subtype": "dom_html_sink",
                "value": "innerHTML=",
                "line": index + 1,
            }
        )
    flow_asset = _write_asset(root, "generated/flow_confirmed_positive.js", flow_lines)
    cases.append(
        _case(
            "flow-confirmed-positive",
            flow_asset,
            labels=flow_labels,
            evaluated_categories=["sink"],
            evaluated_subtypes={"sink": ["taint_flow", "dom_html_sink"]},
            tags=["confirmed-flow", "straight-line"],
        )
    )

    probable_flow_lines: list[str] = []
    probable_flow_labels: list[dict[str, object]] = []
    for index in range(125):
        probable_flow_lines.append(
            f"function renderMaybe{index:03d}(n){{let value{index:03d};for(let i=0;i<n;i++)"
            f"{{value{index:03d}=location.hash;}}target.innerHTML=value{index:03d};}}"
        )
        probable_flow_labels.append(
            {
                "category": "sink",
                "subtype": "taint_flow",
                "value": "URL/location -> innerhtml=",
                "line": index + 1,
                "expected_state": "probable",
            }
        )
        probable_flow_labels.append(
            {
                "category": "sink",
                "subtype": "dom_html_sink",
                "value": "innerHTML=",
                "line": index + 1,
            }
        )
    probable_flow_asset = _write_asset(root, "generated/flow_probable_positive.js", probable_flow_lines)
    cases.append(
        _case(
            "flow-probable-positive",
            probable_flow_asset,
            labels=probable_flow_labels,
            evaluated_categories=["sink"],
            evaluated_subtypes={"sink": ["taint_flow", "dom_html_sink"]},
            tags=["probable-flow", "loop-may-not-execute"],
        )
    )

    flow_negative_lines = [
        f'function renderSafe{index:03d}(){{const value{index:03d}="safe";target.innerHTML=value{index:03d};}}'
        for index in range(500)
    ]
    flow_negative_asset = _write_asset(root, "generated/flow_negative.js", flow_negative_lines)
    flow_negative_labels = [
        {
            "category": "sink",
            "subtype": "dom_html_sink",
            "value": "innerHTML=",
            "line": index + 1,
        }
        for index in range(500)
    ]
    cases.append(
        _case(
            "flow-category-negative",
            flow_negative_asset,
            labels=flow_negative_labels,
            evaluated_categories=["sink"],
            evaluated_subtypes={"sink": ["taint_flow", "dom_html_sink"]},
            negative_opportunities={
                "sink/taint_flow": 500,
                "sink/taint_flow@confirmed": 500,
                "sink/taint_flow@probable": 500,
            },
            tags=["category-negative", "finite-opportunities"],
        )
    )

    unreachable_shapes = {
        "return": "function unreachableReturn(){const x=location.hash;return;target.innerHTML=x;}",
        "false-branch": "if(false){target.innerHTML=location.hash;}",
        "short-circuit": "true || (target.innerHTML=location.hash);",
        "switch-break": "switch(1){case 1:break;target.innerHTML=location.hash;}",
    }
    for name, source in unreachable_shapes.items():
        asset = _write_asset(root, f"generated/flow_unreachable_{name}.js", [source])
        cases.append(
            _case(
                f"flow-unreachable-{name}",
                asset,
                labels=[
                    {
                        "category": "sink",
                        "subtype": "dom_html_sink",
                        "value": "innerHTML=",
                        "line": 1,
                    }
                ],
                forbidden=[
                    {
                        "category": "sink",
                        "subtype": "taint_flow",
                        "value": "URL/location -> innerhtml=",
                        "metadata": {"confirmed": True},
                    }
                ],
                evaluated_categories=["sink"],
                evaluated_subtypes={"sink": ["taint_flow", "dom_html_sink"]},
                negative_opportunities={
                    "sink/taint_flow@confirmed": 1,
                    "sink/taint_flow@probable": 1,
                },
                tags=["hard-zero", "unreachable-confirmed"],
            )
        )

    sink_negative_lines = [
        f'target.textContent="safe sink control {index:03d}";'
        for index in range(500)
    ]
    sink_negative_asset = _write_asset(
        root,
        "generated/sink_negative.js",
        sink_negative_lines,
    )
    cases.append(
        _case(
            "dom-sink-category-negative",
            sink_negative_asset,
            labels=[],
            evaluated_categories=["sink"],
            evaluated_subtypes={"sink": ["dom_html_sink"]},
            negative_opportunities={
                "sink": 500,
                "sink/dom_html_sink": 500,
            },
            tags=["category-negative", "safe-text-sink", "finite-opportunities"],
        )
    )

    # Independently templated detector-family cases prevent a single large generated file from
    # satisfying both Wilson sample counts and case-diversity release gates.
    aws_variant_lines = [
        f'const syntheticAwsVariant{index:03d}="ABIA{index:016d}";'
        for index in range(25)
    ]
    aws_variant_labels = [
        {
            "category": "secret",
            "subtype": "aws_access_key",
            "value": f"ABIA{index:016d}",
            "line": index + 1,
        }
        for index in range(25)
    ]
    cases.append(
        _case(
            "secret-known-provider-prefix-variant",
            _write_asset(root, "manual/secret_known_prefix_variant.js", aws_variant_lines),
            labels=aws_variant_labels,
            evaluated_categories=["secret"],
            evaluated_subtypes={"secret": ["aws_access_key"]},
            tags=["manual-adjudication", "provider-prefix-variant", "synthetic-invalid-credentials"],
        )
    )
    secret_manual_negative_lines = [
        f'const placeholder{index:03d}="replace-with-secret-{index:03d}";'
        for index in range(100)
    ]
    cases.append(
        _case(
            "secret-manual-negative",
            _write_asset(root, "manual/secret_negative_placeholders.js", secret_manual_negative_lines),
            labels=[],
            evaluated_categories=["secret"],
            evaluated_subtypes={"secret": ["aws_access_key", "potential_secret"]},
            negative_opportunities={
                "secret": 100,
                "secret/aws_access_key": 100,
                "secret/potential_secret": 100,
            },
            tags=["manual-adjudication", "placeholder-negative", "finite-opportunities"],
        )
    )

    domain_link_lines = [
        f'const linkLocal{index:03d}="http://169.254.{index + 1}.{index + 10}/health";'
        for index in range(25)
    ]
    domain_link_labels = [
        {
            "category": "domain",
            "subtype": "link_local_ip",
            "value": f"169.254.{index + 1}.{index + 10}",
            "line": index + 1,
        }
        for index in range(25)
    ]
    cases.append(
        _case(
            "domain-link-local-positive",
            _write_asset(root, "manual/domain_link_local_positive.js", domain_link_lines),
            labels=domain_link_labels,
            evaluated_categories=["domain"],
            evaluated_subtypes={"domain": ["link_local_ip"]},
            tags=["manual-adjudication", "link-local", "ssrf-surface"],
        )
    )
    domain_internal_lines = [
        f'const internalService{index:03d}="https://service-{index:03d}.corp.internal/api";'
        for index in range(25)
    ]
    domain_internal_labels = [
        {
            "category": "domain",
            "subtype": "internal_domain",
            "value": f"service-{index:03d}.corp.internal",
            "line": index + 1,
        }
        for index in range(25)
    ]
    cases.append(
        _case(
            "domain-internal-positive",
            _write_asset(root, "manual/domain_internal_positive.js", domain_internal_lines),
            labels=domain_internal_labels,
            evaluated_categories=["domain"],
            evaluated_subtypes={"domain": ["internal_domain"]},
            tags=["manual-adjudication", "internal-host", "url-context"],
        )
    )
    for suffix, lines in (
        (
            "public-range",
            [f'const publicRange{index:03d}="172.32.{index // 250}.{index % 250 + 1}";' for index in range(250)],
        ),
        (
            "invalid-range",
            [f'const invalidRange{index:03d}="999.999.{index:03d}.999";' for index in range(250)],
        ),
    ):
        cases.append(
            _case(
                f"domain-{suffix}-negative",
                _write_asset(root, f"manual/domain_negative_{suffix}.js", lines),
                labels=[],
                evaluated_categories=["domain"],
                negative_opportunities={"domain": 250},
                tags=["manual-adjudication", "ip-boundary-negative", "finite-opportunities"],
            )
        )

    flag_literal_lines = [
        f'const flagKey{index:03d}="feature_flag_checkout_{index:03d}";'
        for index in range(25)
    ]
    flag_literal_labels = [
        {
            "category": "flag",
            "subtype": "feature_flag",
            "value": f"feature_flag_checkout_{index:03d}",
            "line": index + 1,
        }
        for index in range(25)
    ]
    cases.append(
        _case(
            "flag-literal-positive",
            _write_asset(root, "manual/flag_literal_positive.js", flag_literal_lines),
            labels=flag_literal_labels,
            evaluated_categories=["flag"],
            evaluated_subtypes={"flag": ["feature_flag"]},
            tags=["manual-adjudication", "literal-key", "word-boundary"],
        )
    )
    flag_sdk_lines = [
        'import LD from "launchdarkly-js-client-sdk";',
        'const client = LD.initialize("synthetic-fixture");',
        *[
            f'client.variation("checkout-redesign-{index:03d}", false);'
            for index in range(25)
        ],
    ]
    flag_sdk_labels = [
        {
            "category": "flag",
            "subtype": "flag_sdk",
            "value": f"checkout-redesign-{index:03d}",
            "line": index + 3,
        }
        for index in range(25)
    ]
    cases.append(
        _case(
            "flag-sdk-positive",
            _write_asset(root, "manual/flag_sdk_positive.js", flag_sdk_lines),
            labels=flag_sdk_labels,
            evaluated_categories=["flag"],
            evaluated_subtypes={"flag": ["flag_sdk"]},
            tags=["manual-adjudication", "sdk-provenance", "launchdarkly"],
        )
    )
    for suffix, lines in (
        (
            "prose",
            [f'const message{index:03d}="Run experiment {index:03d} and toggle it";' for index in range(250)],
        ),
        (
            "generic-method",
            [f'calculator{index:03d}.variation("display-{index:03d}");' for index in range(250)],
        ),
    ):
        cases.append(
            _case(
                f"flag-{suffix}-negative",
                _write_asset(root, f"manual/flag_negative_{suffix}.js", lines),
                labels=[],
                evaluated_categories=["flag"],
                negative_opportunities={"flag": 250},
                tags=["manual-adjudication", "provenance-negative", "finite-opportunities"],
            )
        )

    debugger_lines = [f"function inspect{index:03d}(){{debugger;}}" for index in range(25)]
    debugger_labels = [
        {
            "category": "debug",
            "subtype": "debugger_statement",
            "value": "debugger",
            "line": index + 1,
        }
        for index in range(25)
    ]
    cases.append(
        _case(
            "debugger-statement-positive",
            _write_asset(root, "manual/debugger_statement_positive.js", debugger_lines),
            labels=debugger_labels,
            evaluated_categories=["debug"],
            evaluated_subtypes={"debug": ["debugger_statement"]},
            tags=["manual-adjudication", "ast-statement", "comment-exclusion"],
        )
    )
    source_map_lines = [
        f"//# sourceMappingURL=debug-{index:03d}.js.map"
        for index in range(25)
    ]
    source_map_labels = [
        {
            "category": "debug",
            "subtype": "source_map_reference",
            "value": f"debug-{index:03d}.js.map",
            "line": index + 1,
        }
        for index in range(25)
    ]
    cases.append(
        _case(
            "debug-source-map-positive",
            _write_asset(root, "manual/debug_source_map_positive.js", source_map_lines),
            labels=source_map_labels,
            evaluated_categories=["debug"],
            evaluated_subtypes={"debug": ["source_map_reference"]},
            tags=["manual-adjudication", "line-directive", "source-disclosure"],
        )
    )
    for suffix, lines in (
        (
            "string",
            [f'const debugText{index:03d}="debugger sourceMappingURL {index:03d}";' for index in range(250)],
        ),
        (
            "comment",
            [f"// debugger sourceMappingURL mention {index:03d}" for index in range(250)],
        ),
    ):
        cases.append(
            _case(
                f"debug-{suffix}-negative",
                _write_asset(root, f"manual/debug_negative_{suffix}.js", lines),
                labels=[],
                evaluated_categories=["debug"],
                negative_opportunities={"debug": 250},
                tags=["manual-adjudication", "lexical-context-negative", "finite-opportunities"],
            )
        )

    upload_form_lines = [
        f'const form{index:03d}=new FormData(); form{index:03d}.append("file",file{index:03d});'
        for index in range(25)
    ]
    upload_form_labels = [
        {
            "category": "upload",
            "subtype": "file_upload",
            "value": "new FormData()",
            "line": index + 1,
        }
        for index in range(25)
    ]
    cases.append(
        _case(
            "upload-formdata-positive",
            _write_asset(root, "manual/upload_formdata_positive.js", upload_form_lines),
            labels=upload_form_labels,
            evaluated_categories=["upload"],
            evaluated_subtypes={"upload": ["file_upload"]},
            tags=["manual-adjudication", "formdata", "file-object"],
        )
    )
    upload_validation_lines = [
        f'const uploadOptions{index:03d}={{allowedExt:["jpg","png"],maxSize:{index + 1}000}};'
        for index in range(25)
    ]
    upload_validation_labels = [
        {
            "category": "upload",
            "subtype": "client_side_file_validation",
            "value": "allowedExt",
            "line": index + 1,
        }
        for index in range(25)
    ]
    cases.append(
        _case(
            "upload-client-validation-positive",
            _write_asset(root, "manual/upload_validation_positive.js", upload_validation_lines),
            labels=upload_validation_labels,
            evaluated_categories=["upload"],
            evaluated_subtypes={"upload": ["client_side_file_validation"]},
            tags=["manual-adjudication", "extension-allowlist", "client-only-validation"],
        )
    )
    for suffix, lines in (
        (
            "format-enum",
            [f'const formats{index:03d}=["json","xml","yaml","toml"];' for index in range(250)],
        ),
        (
            "profile-types",
            [f'const profileTypes{index:03d}=["zip","home","work"];' for index in range(250)],
        ),
    ):
        cases.append(
            _case(
                f"upload-{suffix}-negative",
                _write_asset(root, f"manual/upload_negative_{suffix}.js", lines),
                labels=[],
                evaluated_categories=["upload"],
                negative_opportunities={"upload": 250},
                tags=["manual-adjudication", "enum-negative", "finite-opportunities"],
            )
        )

    for variant, quote in (("double", '"'), ("single", "'")):
        chunk_lines = [
            f"import(/* webpackChunkName: {quote}admin-{index:03d}{quote} */ "
            f"{quote}./AdminPage{index:03d}{quote});"
            for index in range(25)
        ]
        chunk_labels = [
            {
                "category": "endpoint",
                "subtype": "webpack_named_chunk",
                "value": f"admin-{index:03d} -> ./AdminPage{index:03d}",
                "line": index + 1,
            }
            for index in range(25)
        ]
        cases.append(
            _case(
                f"chunk-webpack-{variant}-positive",
                _write_asset(root, f"manual/chunk_webpack_{variant}_positive.js", chunk_lines),
                labels=chunk_labels,
                evaluated_categories=["endpoint"],
                evaluated_subtypes={"endpoint": ["webpack_named_chunk"]},
                tags=["manual-adjudication", "webpack-magic-comment", f"{variant}-quote"],
            )
        )
    chunk_negative_cases = {
        "comment": [f'// import(/* webpackChunkName: "hidden-{index:03d}" */ "./Hidden");' for index in range(250)],
        "file-path": [f'const file{index:03d}={{path:"src/page-{index:03d}.js"}};' for index in range(250)],
    }
    for suffix, lines in chunk_negative_cases.items():
        cases.append(
            _case(
                f"chunk-{suffix}-negative",
                _write_asset(root, f"manual/chunk_negative_{suffix}.js", lines),
                labels=[],
                evaluated_categories=["endpoint"],
                evaluated_subtypes={"endpoint": ["client_route", "webpack_named_chunk"]},
                negative_opportunities={
                    "endpoint": 250,
                    "endpoint/webpack_named_chunk": 250,
                    "endpoint/client_route": 250,
                },
                tags=["manual-adjudication", "chunk-context-negative", "finite-opportunities"],
            )
        )

    modern_route_lines = [
        f'const router{index:03d}=createBrowserRouter([{{path:"/modern/routes/{index:03d}",element:Page{index:03d}}}]);'
        for index in range(25)
    ]
    modern_route_labels = [
        {
            "category": "endpoint",
            "subtype": "client_route",
            "value": f"/modern/routes/{index:03d}",
            "line": index + 1,
        }
        for index in range(25)
    ]
    cases.append(
        _case(
            "route-browser-router-positive",
            _write_asset(root, "manual/route_browser_router_positive.js", modern_route_lines),
            labels=modern_route_labels,
            evaluated_categories=["endpoint"],
            evaluated_subtypes={"endpoint": ["client_route"]},
            tags=["manual-adjudication", "react-router", "structural-route"],
        )
    )

    tsx_source = (
        'const input: string = location.hash; const view=<div dangerouslySetInnerHTML={{__html: input}}/>; '
        'fetch("/api/tsx-modern?page=1",{method:"POST",headers:{Authorization:"Bearer synthetic",'
        '"X-Mode":"tsx"},body:JSON.stringify({name:"value"})});'
    )
    cases.append(
        _case(
            "modern-tsx-multidetector-positive",
            _write_asset(root, "manual/modern_security.tsx", [tsx_source]),
            labels=[
                {
                    "category": "endpoint",
                    "subtype": "api_endpoint",
                    "value": "/api/tsx-modern?page=1",
                    "method": "POST",
                    "line": 1,
                    "contract": {
                        "method": "POST",
                        "headers": {"X-Mode": "tsx"},
                        "auth": {"scheme": "bearer", "in": "header"},
                        "query_params": {"page": "1"},
                        "body": {"kind": "json", "shape": {"name": "string"}},
                    },
                },
                {
                    "category": "sink",
                    "subtype": "dom_html_sink",
                    "value": "innerHTML=",
                    "line": 1,
                },
                {
                    "category": "sink",
                    "subtype": "taint_flow",
                    "value": "URL/location -> innerhtml=",
                    "line": 1,
                    "expected_state": "confirmed",
                },
            ],
            evaluated_categories=["endpoint", "sink"],
            evaluated_subtypes={
                "endpoint": ["api_endpoint"],
                "sink": ["dom_html_sink", "taint_flow"],
            },
            language="tsx",
            graph={
                "must_not_truncate": True,
                "required_edge_types": ["same_file"],
                "min_edges": 1,
                "permutation_invariant": True,
            },
            tags=["manual-adjudication", "tsx", "request-contract", "confirmed-flow"],
        )
    )

    minified_source = (
        'const k="feature_flag_minified_checkout";fetch("/api/minified");'
        "function r(){const x=location.hash;target.innerHTML=x}"
    )
    cases.append(
        _case(
            "minified-multidetector-positive",
            _write_asset(root, "manual/minified_security.js", [minified_source]),
            labels=[
                {
                    "category": "endpoint",
                    "subtype": "api_endpoint",
                    "value": "/api/minified",
                    "method": "GET",
                    "line": 1,
                },
                {
                    "category": "secret",
                    "subtype": "potential_secret",
                    "value": "feature_flag_minified_checkout",
                    "line": 1,
                },
                {
                    "category": "flag",
                    "subtype": "feature_flag",
                    "value": "feature_flag_minified_checkout",
                    "line": 1,
                },
                {
                    "category": "sink",
                    "subtype": "dom_html_sink",
                    "value": "innerHTML=",
                    "line": 1,
                },
                {
                    "category": "sink",
                    "subtype": "taint_flow",
                    "value": "URL/location -> innerhtml=",
                    "line": 1,
                    "expected_state": "confirmed",
                },
            ],
            evaluated_categories=["endpoint", "secret", "flag", "sink"],
            evaluated_subtypes={
                "endpoint": ["api_endpoint"],
                "secret": ["potential_secret"],
                "flag": ["feature_flag"],
                "sink": ["dom_html_sink", "taint_flow"],
            },
            language="minified",
            tags=["manual-adjudication", "minified", "multi-detector", "confirmed-flow"],
        )
    )

    probable_variant = (
        "function renderConditional(ok){let value;if(ok){value=location.search;}"
        "target.innerHTML=value;}"
    )
    cases.append(
        _case(
            "flow-probable-conditional-positive",
            _write_asset(root, "manual/flow_probable_conditional.js", [probable_variant]),
            labels=[
                {
                    "category": "sink",
                    "subtype": "dom_html_sink",
                    "value": "innerHTML=",
                    "line": 1,
                },
                {
                    "category": "sink",
                    "subtype": "taint_flow",
                    "value": "URL/location -> innerhtml=",
                    "line": 1,
                    "expected_state": "probable",
                },
            ],
            evaluated_categories=["sink"],
            evaluated_subtypes={"sink": ["dom_html_sink", "taint_flow"]},
            tags=["manual-adjudication", "probable-flow", "conditional-definition"],
        )
    )
    safe_sink_variant_lines = [
        f'target.setAttribute("aria-label","safe-{index:03d}");'
        for index in range(100)
    ]
    cases.append(
        _case(
            "dom-sink-safe-attribute-negative",
            _write_asset(root, "manual/sink_negative_safe_attribute.js", safe_sink_variant_lines),
            labels=[],
            evaluated_categories=["sink"],
            evaluated_subtypes={"sink": ["dom_html_sink"]},
            negative_opportunities={"sink": 100, "sink/dom_html_sink": 100},
            tags=["manual-adjudication", "safe-attribute", "finite-opportunities"],
        )
    )

    for quote_name, quote in (("double", '"'), ("single", "'")):
        value = "/api/invariant/profile"
        asset = _write_asset(root, f"generated/endpoint_quote_{quote_name}.js", [f"fetch({quote}{value}{quote});"])
        cases.append(
            _case(
                f"endpoint-quote-{quote_name}",
                asset,
                labels=[{"category": "endpoint", "value": value, "method": "GET", "line": 1}],
                evaluated_categories=["endpoint"],
                semantic_group="endpoint-quote-invariance",
                tags=["quote-invariant", "order-invariant"],
            )
        )

    referenced_assets = {
        str(case["asset"]).replace("\\", "/")
        for case in cases
    }
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in CORPUS_SOURCE_SUFFIXES:
            continue
        if path.relative_to(root).as_posix() not in referenced_assets:
            path.unlink()

    manifest = root / "manifest.jsonl"
    manifest.write_text(
        "\n".join(json.dumps(case, sort_keys=True, allow_nan=False) for case in cases) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    gates = {
        "gates": [
            {
                "name": "known provider secret",
                "key": "secret/aws_access_key",
                "precision": 0.99,
                "recall": 1.0,
                "min_positives": 150,
                "min_negatives": 600,
                "min_positive_cases": 2,
                "min_negative_cases": 2,
                "hard_zero_fn": True,
            },
            {
                "name": "generic secret precision",
                "key": "secret/potential_secret",
                "precision": 0.95,
                "min_positives": 126,
                "min_negatives": 600,
                "min_positive_cases": 2,
                "min_negative_cases": 2,
            },
            {
                "name": "HTTP endpoint",
                "key": "endpoint",
                "precision": 0.97,
                "recall": 0.95,
                "min_positives": 100,
                "min_negatives": 600,
                "min_positive_cases": 6,
                "min_negative_cases": 3,
            },
            {
                "name": "request contract",
                "key": "endpoint/api_endpoint",
                "f1": 0.95,
                "min_positives": 125,
                "min_negatives": 500,
                "min_positive_cases": 3,
                "min_negative_cases": 1,
            },
            {
                "name": "request method accuracy",
                "key": "contract/method",
                "f1": 0.99,
                "min_positives": 125,
                "min_positive_cases": 3,
            },
            {
                "name": "request header accuracy",
                "key": "contract/headers",
                "f1": 0.95,
                "min_positives": 125,
                "min_positive_cases": 2,
            },
            {
                "name": "request auth accuracy",
                "key": "contract/auth",
                "f1": 0.95,
                "min_positives": 125,
                "min_positive_cases": 2,
            },
            {
                "name": "request query accuracy",
                "key": "contract/query_params",
                "f1": 0.95,
                "min_positives": 125,
                "min_positive_cases": 2,
            },
            {
                "name": "request body accuracy",
                "key": "contract/body",
                "f1": 0.95,
                "min_positives": 125,
                "min_positive_cases": 2,
            },
            {
                "name": "client route",
                "key": "endpoint/client_route",
                "precision": 0.95,
                "recall": 0.93,
                "min_positives": 150,
                "min_negatives": 600,
                "min_positive_cases": 2,
                "min_negative_cases": 3,
            },
            {
                "name": "confirmed flow",
                "key": "sink/taint_flow@confirmed",
                "precision": 0.99,
                "recall": 0.9,
                "min_positives": 127,
                "min_negatives": 504,
                "min_positive_cases": 3,
                "min_negative_cases": 5,
                "hard_zero_fp": True,
            },
            {
                "name": "probable flow",
                "key": "sink/taint_flow@probable",
                "f1": 0.9,
                "min_positives": 126,
                "min_negatives": 504,
                "min_positive_cases": 2,
                "min_negative_cases": 5,
            },
            {
                "name": "DOM HTML sink",
                "key": "sink/dom_html_sink",
                "precision": 0.97,
                "recall": 0.95,
                "min_positives": 757,
                "min_negatives": 600,
                "min_positive_cases": 10,
                "min_negative_cases": 2,
            },
            {
                "name": "evidence location",
                "key": "location",
                "f1": 0.99,
                "min_positives": 1_900,
                "min_positive_cases": 20,
            },
            {
                "name": "domain family",
                "key": "domain",
                "precision": 0.95,
                "recall": 0.95,
                "min_positives": 50,
                "min_negatives": 500,
                "min_positive_cases": 2,
                "min_negative_cases": 2,
            },
            {
                "name": "feature flag family",
                "key": "flag",
                "precision": 0.95,
                "recall": 0.95,
                "min_positives": 50,
                "min_negatives": 500,
                "min_positive_cases": 2,
                "min_negative_cases": 2,
            },
            {
                "name": "debug family",
                "key": "debug",
                "precision": 0.95,
                "recall": 0.95,
                "min_positives": 50,
                "min_negatives": 500,
                "min_positive_cases": 2,
                "min_negative_cases": 2,
            },
            {
                "name": "upload family",
                "key": "upload",
                "precision": 0.95,
                "recall": 0.95,
                "min_positives": 50,
                "min_negatives": 500,
                "min_positive_cases": 2,
                "min_negative_cases": 2,
            },
            {
                "name": "chunk analyzer",
                "key": "endpoint/webpack_named_chunk",
                "precision": 0.95,
                "recall": 0.95,
                "min_positives": 50,
                "min_negatives": 500,
                "min_positive_cases": 2,
                "min_negative_cases": 2,
            },
        ]
    }
    (root / "gates.json").write_text(
        json.dumps(gates, indent=2, sort_keys=True, allow_nan=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    (root / "README.md").write_text(
        "# Detection release corpus\n\n"
        "Generated by `scripts/build_detection_corpus.py`. All credential-shaped values are "
        "deterministic, nonfunctional synthetic fixtures. `manifest.jsonl` is the ground truth and "
        "`gates.json` is enforced by `scripts/run_detection_metrics.py`. The committed "
        "`baseline.json` is enforced with `--fail-on-regression` and is updated only through "
        "`scripts/update_detection_baseline.py --output <reviewed-path>`.\n",
        encoding="utf-8",
        newline="\n",
    )
    label_count = 0
    for case in cases:
        labels = case.get("labels")
        if isinstance(labels, list):
            label_count += len(labels)
    return len(cases), label_count


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    args = parser.parse_args(argv)
    case_count, label_count = build_corpus(args.root)
    print(
        json.dumps(
            {"corpus": str(args.root.resolve()), "cases": case_count, "labels": label_count},
            allow_nan=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
