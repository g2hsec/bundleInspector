"""
Feature flag detector.

Detects feature flags, A/B tests, and hidden functionality.
"""

from __future__ import annotations

import re
from collections.abc import Iterator, Set
from typing import Any

from bundleInspector.core.url_utils import safe_urlsplit as urlsplit
from bundleInspector.rules.base import AnalysisContext, BaseRule, RuleResult
from bundleInspector.storage.models import (
    Category,
    Confidence,
    FunctionCall,
    IntermediateRepresentation,
    Severity,
    StringLiteral,
)


class FlagDetector(BaseRule):
    """
    Detect feature flags and hidden functionality.

    Looks for:
    - Feature flag patterns
    - A/B test configurations
    - Remote config fetches
    - Conditional feature enablement
    """

    id = "flag-detector"
    name = "Feature Flag Detector"
    description = "Detects feature flags and hidden functionality"
    category = Category.FLAG
    severity = Severity.LOW

    # Flag-related keywords in variable/function names
    FLAG_KEYWORDS = [
        "feature_flag",
        "feature-flag",
        "featureflag",
        "feature_toggle",
        "feature-toggle",
        "toggle",
        "experiment",
        "variant",
        "ab_test",
        "abtest",
        "a_b_test",
        "rollout",
        "canary",
        "beta_feature",
        "alpha_feature",
        "preview_feature",
        "hidden_feature",
        "internal_only",
        "admin_only",
        "debug_mode",
        "dev_mode",
        "dev_only",
    ]

    # Common feature flag SDKs
    FLAG_SDKS = [
        "launchdarkly",
        "optimizely",
        "splitio",
        "configcat",
        "unleash",
        "flipper",
        "growthbook",
        "flagsmith",
        "featureflag",
    ]

    # Config endpoint patterns
    CONFIG_ENDPOINTS = [
        r"/(?:api/)?(?:feature[-_]?)?flags?",
        r"/(?:api/)?config(?:uration)?s?",
        r"/(?:api/)?experiments?",
        r"/(?:api/)?settings",
        r"/(?:api/)?toggles?",
        r"/(?:api/)?variants?",
    ]

    # DQ-D05: a flag key is a single token (identifier / snake / kebab / dotted), never prose. This
    # shape gate drops sentences like "This experiment shows..." that merely contain a keyword.
    _FLAG_KEY_SHAPE = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$", re.IGNORECASE)
    _CONFIG_SEGMENTS = frozenset(
        {
            "flag",
            "flags",
            "featureflag",
            "featureflags",
            "feature-flag",
            "feature-flags",
            "config",
            "configs",
            "configuration",
            "configurations",
            "experiment",
            "experiments",
            "setting",
            "settings",
            "toggle",
            "toggles",
            "variant",
            "variants",
        }
    )
    _STATIC_EXTENSIONS = (".js", ".mjs", ".cjs", ".css", ".map", ".json", ".png", ".svg")

    @staticmethod
    def _tokens(value: str) -> list[str]:
        expanded = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", value or "")
        return [part.lower() for part in re.split(r"[._-]+", expanded) if part]

    def _keyword_in_key(self, value: str, keyword: str) -> bool:
        value_tokens = self._tokens(value)
        keyword_tokens = self._tokens(keyword)
        if not keyword_tokens:
            return False
        width = len(keyword_tokens)
        return any(
            value_tokens[i : i + width] == keyword_tokens
            for i in range(len(value_tokens) - width + 1)
        )

    def _looks_like_config_endpoint(self, value: str) -> bool:
        parsed = urlsplit(
            value if value.startswith(("http://", "https://")) else f"https://host{value}"
        )
        path = (parsed.path or "").lower().rstrip("/")
        if not path or path.endswith(self._STATIC_EXTENSIONS):
            return False
        for segment in path.split("/"):
            base = re.sub(r"\.(?:do|action|jsp|php|aspx?)$", "", segment)
            if base in self._CONFIG_SEGMENTS:
                return True
        return False

    # DQ-D05: import-source substrings -> SDK name, so a flag read via an imported client
    # (`client.variation('key')`) is attributed even though the vendor name is not in the call chain.
    _SDK_MODULE_HINTS = {
        "launchdarkly": "launchdarkly",
        "optimizely": "optimizely",
        "@splitsoftware/splitio": "splitio",
        "splitio": "splitio",
        "configcat": "configcat",
        "unleash": "unleash",
        "flagsmith": "flagsmith",
        "growthbook": "growthbook",
    }
    # Canonical, vendor-DISTINCT flag-read methods (lowercased) -- attributed on ANY receiver when an
    # SDK is imported, since these names are flag-specific.
    _SDK_READ_METHODS = {
        "variation",
        "variationdetail",
        "gettreatment",
        "gettreatments",
        "isfeatureenabled",
        "getfeatureflag",
        "boolvariation",
        "stringvariation",
    }
    # DQ-D05: GENERIC read methods (ConfigCat getValue/getValueAsync, OpenFeature getBooleanValue/
    # getStringValue) collide with ubiquitous non-flag APIs (RxJS BehaviorSubject.getValue()), so they
    # are attributed ONLY when the receiver is a variable bound to an SDK client (see
    # _detect_sdk_clients) -- not on an arbitrary receiver.
    _SDK_GENERIC_READ_METHODS = {
        "getvalue",
        "getvalueasync",
        "getbooleanvalue",
        "getbooleanvalueasync",
        "getstringvalue",
        "getnumbervalue",
        "getobjectvalue",
        "isenabled",
        "getflag",
    }
    # Generic init/singleton method names -> only qualify a variable as an SDK client when the call
    # is also SDK-hinted (see _detect_sdk_clients).
    _SDK_INIT_METHODS = {"initialize", "init", "getinstance", "createinstance", "setup"}
    # Client-FACTORY method names that qualify on their own (exact match, NOT a bare "client"
    # substring -- else createHttpClient()/apolloClient()/createAnalyticsClient() would wrongly count).
    _SDK_CLIENT_METHODS = {
        "getclient",
        "newclient",
        "createclient",
        "makeclient",
        "buildclient",
        "initclient",
        "client",
    }

    def match(
        self,
        ir: IntermediateRepresentation,
        context: AnalysisContext,
    ) -> Iterator[RuleResult]:
        """Match feature flags in IR."""
        imported_sdks = self._detect_sdk_imports(ir)
        sdk_clients = self._detect_sdk_clients(ir, imported_sdks)

        # Check string literals
        for literal in ir.string_literals:
            yield from self._check_literal(literal)

        # Check function calls
        for call in ir.function_calls:
            yield from self._check_call(call, imported_sdks, sdk_clients)

        # Check identifiers
        for name, identifiers in ir.identifiers.items():
            yield from self._check_identifier(name, identifiers)

    def _check_literal(self, literal: StringLiteral) -> Iterator[RuleResult]:
        """Check string literals for flag patterns."""
        value = literal.value.lower()

        # Skip short strings
        if len(value) < 3:
            return

        # DQ-D05: only a flag-key-SHAPED literal (a single identifier/snake/kebab/dotted token) can
        # be a flag key. This drops prose that merely contains a keyword ("run the experiment now"),
        # while keeping real keys like feature_flag_new_checkout / new-checkout-flow.
        key_shaped = bool(self._FLAG_KEY_SHAPE.match(value))

        # Check for flag keywords
        matched_keyword = False
        if key_shaped:
            for keyword in self.FLAG_KEYWORDS:
                if self._keyword_in_key(literal.value, keyword):
                    yield RuleResult(
                        rule_id=self.id,
                        category=self.category,
                        severity=Severity.LOW,
                        confidence=Confidence.MEDIUM,
                        title=f"Feature Flag: {literal.value[:50]}",
                        description=f"Found potential feature flag reference: {literal.value}",
                        extracted_value=literal.value,
                        value_type="feature_flag",
                        line=literal.line,
                        column=literal.column,
                        ast_node_type="Literal",
                        tags=["flag", keyword],
                    )
                    matched_keyword = True
                    break

        # Check for config endpoints (skip if already matched as keyword). DQ-D05: the value must
        # look like a path/URL (no spaces), not arbitrary prose; a bare /settings or /config path is
        # only weak evidence, so it is reported at LOW.
        if matched_keyword:
            return
        stripped = value.strip()
        # DQ-D05: the value must be an ABSOLUTE path/URL (no spaces; leads with '/' or http). A
        # relative form like "dashboard/settings" or "./config" is a route / require specifier /
        # asset path, not an API config endpoint -- those false-positived when the gate merely
        # required a '/'. A genuine relative API endpoint is still surfaced by the endpoint detector.
        if " " in stripped or not (stripped.startswith("/") or stripped.startswith("http")):
            return
        if self._looks_like_config_endpoint(stripped):
            bare = (
                urlsplit(stripped if stripped.startswith("http") else f"https://host{stripped}")
                .path.rstrip("/")
                .rsplit("/", 1)[-1]
            )
            sev = (
                Severity.LOW if bare in ("settings", "config", "configuration") else Severity.MEDIUM
            )
            yield RuleResult(
                rule_id=self.id,
                category=self.category,
                severity=sev,
                confidence=Confidence.MEDIUM,
                title=f"Config Endpoint: {literal.value[:50]}",
                description=f"Found feature/config endpoint: {literal.value}",
                extracted_value=literal.value,
                value_type="config_endpoint",
                line=literal.line,
                column=literal.column,
                ast_node_type="Literal",
                tags=["flag", "endpoint"],
            )

    @staticmethod
    def _callee_method_name(callee: Any) -> str:
        """Last method/identifier name of a raw-AST callee node, lowercased."""
        if not isinstance(callee, dict):
            return ""
        if callee.get("type") == "Identifier":
            return (callee.get("name") or "").lower()
        if callee.get("type") == "MemberExpression":
            prop = callee.get("property") or {}
            return (prop.get("name") or "").lower()
        return ""

    @staticmethod
    def _member_root(callee: Any) -> str:
        """Root/object identifier of a callee (LDClient.initialize -> 'ldclient'), lowercased."""
        cur = callee
        for _ in range(10):
            if not isinstance(cur, dict):
                return ""
            t = cur.get("type")
            if t == "Identifier":
                return (cur.get("name") or "").lower()
            if t == "MemberExpression":
                cur = cur.get("object")
            elif t == "CallExpression":
                cur = cur.get("callee")
            else:
                return ""
        return ""

    def _detect_sdk_clients(
        self,
        ir: IntermediateRepresentation,
        imported_sdks: Set[str],
    ) -> set[str]:
        """DQ-D05: names (lowercased) of variables bound to a flag-SDK client -- `const c =
        getClient(...)` / `initialize(...)` / `new ConfigCatClient(...)`. A GENERIC read method
        (c.getValue('flag')) is attributed only on such a client, not on an unrelated receiver."""
        if not imported_sdks:
            return set()
        clients: set[str] = set()
        raw = getattr(ir, "raw_ast", None)
        stack = [raw] if isinstance(raw, dict) else []
        seen = 0
        while stack:
            node = stack.pop()
            seen += 1
            if seen > 500000 or not isinstance(node, dict):
                continue
            if node.get("type") == "VariableDeclarator":
                idn = node.get("id") or {}
                init = node.get("init") or {}
                if (
                    isinstance(idn, dict)
                    and idn.get("type") == "Identifier"
                    and isinstance(init, dict)
                ):
                    name = (idn.get("name") or "").lower()
                    itype = init.get("type")
                    if itype == "CallExpression":
                        m = self._callee_method_name(init.get("callee"))
                        root = self._member_root(init.get("callee"))
                        # DQ-D05: a client-specific method name (getClient/newClient) qualifies on its
                        # own; a generic init (initialize/init/setup/getInstance) only when SDK-hinted
                        # (LDClient.initialize / configcat.getClient) -- NOT a bare initialize(reducer).
                        obj_hint = "client" in root or any(s in root for s in imported_sdks)
                        if m in self._SDK_CLIENT_METHODS or (
                            m in self._SDK_INIT_METHODS and obj_hint
                        ):
                            clients.add(name)
                    elif itype == "NewExpression":
                        cn = ((init.get("callee") or {}).get("name") or "").lower()
                        if "client" in cn or any(s in cn for s in imported_sdks):
                            clients.add(name)
            for v in node.values():
                if isinstance(v, dict):
                    stack.append(v)
                elif isinstance(v, list):
                    stack.extend(it for it in v if isinstance(it, dict))
        return clients

    def _detect_sdk_imports(self, ir: IntermediateRepresentation) -> set[str]:
        """DQ-D05: map imported module sources (launchdarkly-js-client-sdk, @splitsoftware/splitio,
        ...) to SDK names, so a flag read via the imported client is attributed to its vendor."""
        found: set[str] = set()
        for imp in getattr(ir, "imports", None) or []:
            src = (getattr(imp, "source", "") or "").lower()
            if not src:
                continue
            for hint, name in self._SDK_MODULE_HINTS.items():
                if hint in src:
                    found.add(name)
        return found

    def _check_call(
        self,
        call: FunctionCall,
        imported_sdks: Set[str] = frozenset(),
        sdk_clients: Set[str] = frozenset(),
    ) -> Iterator[RuleResult]:
        """Check function calls for flag SDKs."""
        full_name = call.full_name.lower()
        name = call.name.lower()

        # Common function names that contain flag keywords but aren't flags
        EXCLUDE_NAMES = {"invariant", "environment", "development", "navigator"}
        if name in EXCLUDE_NAMES:
            return
        # Exclude calls on browser APIs (e.g., window.navigator.vibrate)
        # Only check the caller object names, not the entire chain, to avoid
        # false exclusions like "config.environment.getFlag()"
        EXCLUDE_OBJECTS = {"navigator"}
        parts = full_name.split(".")
        if any(part in EXCLUDE_OBJECTS for part in parts[:-1]):
            return

        # Check for flag SDK usage
        sdk_matched = False
        for sdk in self.FLAG_SDKS:
            if sdk in full_name:
                # Try to extract flag name
                flag_name = self._extract_flag_from_args(call.arguments)

                yield RuleResult(
                    rule_id=self.id,
                    category=self.category,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    title=f"Feature Flag SDK: {sdk.title()}",
                    description=f"Found {sdk} SDK usage"
                    + (f" for flag: {flag_name}" if flag_name else ""),
                    extracted_value=flag_name or call.full_name,
                    value_type="flag_sdk",
                    line=call.line,
                    column=call.column,
                    ast_node_type="CallExpression",
                    tags=["flag", "sdk", sdk],
                    metadata={"sdk": sdk, "flag": flag_name},
                )
                sdk_matched = True
                break

        # Skip function pattern check if already matched as SDK call
        if sdk_matched:
            return

        # DQ-D05: with a flag SDK imported, its canonical read methods are flag reads even when the
        # vendor name is not in the call chain (const client = LDClient.initialize(...); ...
        # client.variation('key', false)). Attribute the SDK and capture the flag key.
        # A vendor-distinct read fires on any receiver; a GENERIC read (getValue/isEnabled) fires
        # only when the receiver is a tracked SDK client (DQ-D05).
        receiver = full_name.split(".", 1)[0] if "." in full_name else ""
        is_sdk_read = name in self._SDK_READ_METHODS or (
            name in self._SDK_GENERIC_READ_METHODS and receiver in sdk_clients
        )
        if imported_sdks and is_sdk_read:
            flag_name = self._extract_flag_from_args(call.arguments)
            sdk = sorted(imported_sdks)[0]
            yield RuleResult(
                rule_id=self.id,
                category=self.category,
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                title=f"Feature Flag SDK: {sdk.title()}",
                description=f"Found {sdk} flag read via {call.name}"
                + (f" for flag: {flag_name}" if flag_name else ""),
                extracted_value=flag_name or call.full_name,
                value_type="flag_sdk",
                line=call.line,
                column=call.column,
                ast_node_type="CallExpression",
                tags=["flag", "sdk", sdk],
                metadata={"sdk": sdk, "flag": flag_name},
            )
            return

        # Check for common flag function patterns
        flag_functions = [
            "isfeatureenabled",
            "isflagon",
            "hasfeature",
            "getvariant",
            "getexperiment",
        ]
        if name in flag_functions or any(
            re.search(rf"(?<![a-z]){f}(?![a-z])", name) for f in ["flag", "feature", "variant"]
        ):
            flag_name = self._extract_flag_from_args(call.arguments)

            yield RuleResult(
                rule_id=self.id,
                category=self.category,
                severity=Severity.LOW,
                confidence=Confidence.MEDIUM,
                title=f"Feature Flag Check: {call.name}",
                description="Found feature flag check"
                + (f" for: {flag_name}" if flag_name else ""),
                extracted_value=flag_name or call.full_name,
                value_type="flag_check",
                line=call.line,
                column=call.column,
                ast_node_type="CallExpression",
                tags=["flag"],
                metadata={"flag": flag_name},
            )

    def _check_identifier(self, name: str, identifiers: list) -> Iterator[RuleResult]:
        """Check identifier names for flag patterns."""
        # Skip common names
        if len(name) < 5:
            return

        # Check for admin/internal patterns
        token_sequences = {
            ("is", "admin"),
            ("admin", "mode"),
            ("admin", "only"),
            ("internal", "only"),
            ("dev", "mode"),
            ("debug", "mode"),
        }
        tokens = self._tokens(name)
        for pattern in token_sequences:
            width = len(pattern)
            if any(tuple(tokens[i : i + width]) == pattern for i in range(len(tokens) - width + 1)):
                first = identifiers[0] if identifiers else None
                yield RuleResult(
                    rule_id=self.id,
                    category=self.category,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    title=f"Admin/Debug Flag: {name}",
                    description=f"Found potential admin/debug flag: {name}",
                    extracted_value=name,
                    value_type="admin_flag",
                    line=first.line if first else 0,
                    column=first.column if first else 0,
                    ast_node_type="Identifier",
                    tags=["flag", "admin"],
                )
                break

    def _extract_flag_from_args(self, arguments: list) -> str:
        """Extract flag name from function arguments."""
        if not arguments:
            return ""

        first_arg = arguments[0]

        if first_arg.get("type") == "Literal":
            return str(first_arg.get("value", ""))

        return ""
