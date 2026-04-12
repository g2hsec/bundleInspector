"""Tests for endpoint detector."""

import pytest

from bundleInspector.parser.js_parser import parse_js
from bundleInspector.parser.ir_builder import build_ir
from bundleInspector.rules.base import AnalysisContext
from bundleInspector.rules.detectors.endpoints import EndpointDetector
from bundleInspector.storage.models import Confidence


class TestEndpointDetector:
    """Tests for EndpointDetector."""

    @pytest.fixture
    def detector(self):
        return EndpointDetector()

    @pytest.fixture
    def context(self):
        return AnalysisContext(
            file_url="https://example.com/app.js",
            file_hash="abc123",
            source_content="",
        )

    def _analyze(self, source: str, detector: EndpointDetector, context: AnalysisContext):
        """Helper to analyze source code."""
        result = parse_js(source)
        assert result.success

        ir = build_ir(result.ast, context.file_url, context.file_hash)
        context.source_content = source

        return list(detector.match(ir, context))

    def test_detect_fetch(self, detector, context):
        """Test detection of fetch calls."""
        source = '''
        fetch("/api/users");
        '''
        findings = self._analyze(source, detector, context)

        assert len(findings) >= 1
        assert any("/api/users" in f.extracted_value for f in findings)

    def test_detect_axios(self, detector, context):
        """Test detection of axios calls."""
        source = '''
        axios.get("/api/products");
        axios.post("/api/orders", { item: 1 });
        '''
        findings = self._analyze(source, detector, context)

        assert len(findings) >= 2
        assert any("/api/products" in f.extracted_value for f in findings)
        assert any("/api/orders" in f.extracted_value for f in findings)

    def test_detect_xmlhttprequest_open(self, detector, context):
        """Detect practical XMLHttpRequest `.open(method, url)` calls."""
        source = '''
        const xhr = new XMLHttpRequest();
        xhr.open("POST", "/api/orders");
        '''
        findings = self._analyze(source, detector, context)

        assert any(
            f.extracted_value == "/api/orders" and f.metadata.get("method") == "POST"
            for f in findings
        )

    def test_detect_window_xmlhttprequest_open(self, detector, context):
        """Detect practical `window.XMLHttpRequest` instance calls."""
        source = '''
        const xhr = new window.XMLHttpRequest();
        xhr.open("GET", "/api/users");
        '''
        findings = self._analyze(source, detector, context)

        assert any(
            f.extracted_value == "/api/users" and f.metadata.get("method") == "GET"
            for f in findings
        )

    def test_detect_assigned_xmlhttprequest_open(self, detector, context):
        """Detect XHR instances introduced via assignment before `.open()`."""
        source = '''
        let xhr;
        xhr = new XMLHttpRequest();
        xhr.open("PATCH", "/api/users");
        '''
        findings = self._analyze(source, detector, context)

        assert any(
            f.extracted_value == "/api/users" and f.metadata.get("method") == "PATCH"
            for f in findings
        )

    def test_detect_xmlhttprequest_open_with_standard_url_patterns(self, detector, context):
        """Resolve URL/Request-derived arguments passed into XMLHttpRequest.open.""" 
        source = '''
        const API_BASE = "https://api.example.com";
        const xhr = new XMLHttpRequest();
        xhr.open("GET", new Request(new URL("/users", API_BASE)).clone().url);
        '''
        findings = self._analyze(source, detector, context)

        assert any(
            f.extracted_value == "https://api.example.com/users" and f.metadata.get("method") == "GET"
            for f in findings
        )

    def test_skip_non_xhr_open_false_positive(self, detector, context):
        """Do not classify unrelated `.open()` calls as HTTP requests."""
        source = '''
        const dialog = {
            open(method, url) {
                return `${method}:${url}`;
            }
        };
        dialog.open("GET", "/static/app.js");
        '''
        findings = self._analyze(source, detector, context)

        assert not findings

    def test_detect_full_url(self, detector, context):
        """Test detection of full URLs."""
        source = '''
        const apiUrl = "https://api.example.com/v1/users";
        '''
        findings = self._analyze(source, detector, context)

        assert len(findings) >= 1
        assert any("api.example.com" in f.extracted_value for f in findings)

    def test_detect_graphql(self, detector, context):
        """Test detection of GraphQL endpoints."""
        source = '''
        fetch("/graphql", {
            method: "POST",
            body: JSON.stringify({ query: "{ users { id } }" })
        });
        '''
        findings = self._analyze(source, detector, context)

        assert len(findings) >= 1
        assert any("/graphql" in f.extracted_value for f in findings)

    def test_detect_websocket_constructor(self, detector, context):
        """Detect direct WebSocket constructor endpoints."""
        source = '''
        new WebSocket("wss://api.example.com/socket");
        '''
        findings = self._analyze(source, detector, context)

        assert any(
            f.extracted_value == "wss://api.example.com/socket" and "websocket" in f.tags
            for f in findings
        )

    def test_detect_window_websocket_constructor(self, detector, context):
        """Detect `window.WebSocket` constructor calls with resolved constants."""
        source = '''
        const SOCKET_BASE = "wss://api.example.com";
        new window.WebSocket(`${SOCKET_BASE}/socket`);
        '''
        findings = self._analyze(source, detector, context)

        assert any(
            f.extracted_value == "wss://api.example.com/socket" and "websocket" in f.tags
            for f in findings
        )

    def test_detect_websocket_constructor_from_url_object(self, detector, context):
        """Resolve `new URL(..., \"wss://...\")` inputs passed into WebSocket constructors."""
        source = '''
        const SOCKET_BASE = "wss://api.example.com";
        new WebSocket(new URL("/socket", SOCKET_BASE));
        '''
        findings = self._analyze(source, detector, context)

        assert any(
            f.extracted_value == "wss://api.example.com/socket" and "websocket" in f.tags
            for f in findings
        )

    def test_detect_websocket_full_url_literal(self, detector, context):
        """Detect standalone WebSocket full URL literals that look API-like."""
        source = '''
        const socketUrl = "wss://api.example.com/socket";
        '''
        findings = self._analyze(source, detector, context)

        assert any(
            f.extracted_value == "wss://api.example.com/socket"
            for f in findings
        )

    def test_detect_template_literal(self, detector, context):
        """Test detection in template literals."""
        source = '''
        fetch(`/api/users/${userId}`);
        '''
        findings = self._analyze(source, detector, context)

        assert len(findings) >= 1
        # Template literal should have medium confidence
        assert any(f.confidence == Confidence.MEDIUM for f in findings)

    def test_detect_rest_pattern(self, detector, context):
        """Test detection of REST API patterns."""
        source = '''
        const endpoints = {
            users: "/api/v1/users",
            products: "/api/v1/products",
            orders: "/rest/orders"
        };
        '''
        findings = self._analyze(source, detector, context)

        assert len(findings) >= 3

    def test_resolve_constant_base_url_concat(self, detector, context):
        """Resolve simple string constants to reduce endpoint false negatives."""
        source = '''
        const API_BASE = "https://api.example.com";
        fetch(API_BASE + "/users");
        '''
        findings = self._analyze(source, detector, context)

        assert any(
            f.extracted_value == "https://api.example.com/users"
            for f in findings
        )

    def test_resolve_axios_client_base_url(self, detector, context):
        """Resolve axios.create({ baseURL }) client instances."""
        source = '''
        const API_BASE = "https://api.example.com";
        const api = axios.create({ baseURL: API_BASE });
        api.get("/users");
        '''
        findings = self._analyze(source, detector, context)

        assert any(
            f.extracted_value == "https://api.example.com/users"
            for f in findings
        )

    def test_detect_object_config_url(self, detector, context):
        """Detect axios-style object config requests."""
        source = '''
        axios({
            method: "POST",
            url: "/api/orders"
        });
        '''
        findings = self._analyze(source, detector, context)

        assert any("/api/orders" == f.extracted_value for f in findings)

    def test_detect_object_config_url_with_spread_override(self, detector, context):
        """Resolve spread-based object config requests with later url/method overrides."""
        source = '''
        const baseConfig = {
            method: "GET",
            url: "/docs/orders"
        };
        axios({
            ...baseConfig,
            method: "POST",
            url: "/api/orders"
        });
        '''
        findings = self._analyze(source, detector, context)

        assert any(
            f.extracted_value == "/api/orders" and f.metadata.get("method") == "POST"
            for f in findings
        )

    def test_detect_object_config_helper_call(self, detector, context):
        """Resolve helper calls that directly return object-style request configs."""
        source = '''
        const requestConfig = () => ({
            method: "POST",
            url: "/api/orders"
        });
        axios(requestConfig());
        '''
        findings = self._analyze(source, detector, context)

        assert any(
            f.extracted_value == "/api/orders" and f.metadata.get("method") == "POST"
            for f in findings
        )

    def test_detect_object_config_helper_call_with_spread_return(self, detector, context):
        """Resolve helper calls that return spread-based object configs."""
        source = '''
        function requestConfig() {
            const baseConfig = {
                method: "GET",
                baseURL: "https://api.example.com",
                url: "/docs/orders"
            };
            return {
                ...baseConfig,
                method: "PUT",
                url: "/users"
            };
        }
        axios(requestConfig());
        '''
        findings = self._analyze(source, detector, context)

        assert any(
            f.extracted_value == "https://api.example.com/users"
            and f.metadata.get("method") == "PUT"
            for f in findings
        )

    def test_detect_block_helper_returning_object_config(self, detector, context):
        """Resolve block-bodied helpers that return direct object configs."""
        source = '''
        function requestConfig() {
            return {
                method: "PUT",
                baseURL: "https://api.example.com",
                url: "/users"
            };
        }
        axios(requestConfig());
        '''
        findings = self._analyze(source, detector, context)

        assert any(
            f.extracted_value == "https://api.example.com/users"
            and f.metadata.get("method") == "PUT"
            for f in findings
        )

    def test_detect_object_method_returning_object_config(self, detector, context):
        """Resolve object-literal helper methods that return direct request configs."""
        source = '''
        const helpers = {
            requestConfig() {
                return {
                    method: "POST",
                    url: "/api/orders"
                };
            }
        };
        axios(helpers.requestConfig());
        '''
        findings = self._analyze(source, detector, context)

        assert any(
            f.extracted_value == "/api/orders" and f.metadata.get("method") == "POST"
            for f in findings
        )

    def test_detect_block_object_config_helper_returning_local_array_selected_config(self, detector, context):
        """Resolve block-bodied helpers that return local array-selected request configs."""
        source = '''
        function requestConfig(index) {
            const configs = [
                { method: "GET", url: "/api/users" },
                { method: "POST", url: "/api/orders" }
            ];
            return configs[index];
        }
        axios(requestConfig(1));
        '''
        findings = self._analyze(source, detector, context)

        assert any(
            f.extracted_value == "/api/orders" and f.metadata.get("method") == "POST"
            for f in findings
        )

    def test_detect_block_object_method_returning_local_array_selected_config(self, detector, context):
        """Resolve block-bodied object methods that return local array-selected request configs."""
        source = '''
        const helpers = {
            requestConfig(index) {
                const configs = [
                    { method: "GET", url: "/api/users" },
                    { method: "POST", url: "/api/orders" }
                ];
                return configs[index];
            }
        };
        axios(helpers.requestConfig(0));
        '''
        findings = self._analyze(source, detector, context)

        assert any(
            f.extracted_value == "/api/users" and f.metadata.get("method") == "GET"
            for f in findings
        )

    def test_detect_block_object_config_helper_returning_local_alias_of_selected_config(self, detector, context):
        """Resolve block-bodied helpers that alias a selected local config before returning it."""
        source = '''
        function requestConfig(index) {
            const configs = [
                { method: "GET", url: "/api/users" },
                { method: "POST", url: "/api/orders" }
            ];
            const cfg = configs[index];
            return cfg;
        }
        axios(requestConfig(1));
        '''
        findings = self._analyze(source, detector, context)

        assert any(
            f.extracted_value == "/api/orders" and f.metadata.get("method") == "POST"
            for f in findings
        )

    def test_skip_block_object_config_helper_returning_local_asset_config_false_positive(self, detector, context):
        """Do not classify block-bodied helpers that return local asset configs."""
        source = '''
        function requestConfig(index) {
            const configs = [
                { method: "GET", url: "/static/app.js" }
            ];
            return configs[index];
        }
        axios(requestConfig(0));
        '''
        findings = self._analyze(source, detector, context)

        assert not findings

    def test_detect_identifier_bound_object_config_helper_result(self, detector, context):
        """Resolve helper-returned request configs that are stored in an identifier first."""
        source = '''
        const requestConfig = () => ({
            method: "POST",
            url: "/api/orders"
        });
        const cfg = requestConfig();
        axios(cfg);
        '''
        findings = self._analyze(source, detector, context)

        assert any(
            f.extracted_value == "/api/orders" and f.metadata.get("method") == "POST"
            for f in findings
        )

    def test_detect_array_indexed_object_config_request(self, detector, context):
        """Resolve request config objects selected from static arrays."""
        source = '''
        const configs = [
            { method: "GET", url: "/api/users" },
            { method: "POST", url: "/api/orders" }
        ];
        axios(configs[1]);
        '''
        findings = self._analyze(source, detector, context)

        assert any(
            f.extracted_value == "/api/orders" and f.metadata.get("method") == "POST"
            for f in findings
        )

    def test_detect_computed_array_indexed_object_config_request(self, detector, context):
        """Resolve request config objects selected from arrays by static indexes."""
        source = '''
        const configs = [
            { method: "GET", url: "/api/users" },
            { method: "POST", url: "/api/orders" }
        ];
        const configIndex = 0;
        axios(configs[configIndex]);
        '''
        findings = self._analyze(source, detector, context)

        assert any(
            f.extracted_value == "/api/users" and f.metadata.get("method") == "GET"
            for f in findings
        )

    def test_skip_object_config_helper_returning_static_asset(self, detector, context):
        """Do not classify helper-returned static asset configs as endpoints."""
        source = '''
        function assetConfig() {
            return {
                method: "GET",
                url: "/static/app.js"
            };
        }
        axios(assetConfig());
        '''
        findings = self._analyze(source, detector, context)

        assert not findings

    def test_skip_array_indexed_static_asset_config_false_positive(self, detector, context):
        """Do not classify array-selected static asset configs as endpoints."""
        source = '''
        const configs = [
            { method: "GET", url: "/static/app.js" },
            { method: "GET", url: "/static/vendor.js" }
        ];
        const configIndex = 1;
        axios(configs[configIndex]);
        '''
        findings = self._analyze(source, detector, context)

        assert not findings

    def test_skip_identifier_bound_static_asset_config_helper_false_positive(self, detector, context):
        """Do not classify identifier-bound helper-returned static asset configs as endpoints."""
        source = '''
        const assetConfig = () => ({
            method: "GET",
            url: "/static/app.js"
        });
        const cfg = assetConfig();
        axios(cfg);
        '''
        findings = self._analyze(source, detector, context)

        assert not findings

    def test_skip_static_asset_urls(self, detector, context):
        """Do not classify obvious static assets as endpoints."""
        source = '''
        fetch("/static/app.js");
        const cdn = "https://cdn.example.com/assets/app.css";
        '''
        findings = self._analyze(source, detector, context)

        assert not findings

    def test_resolve_zero_arg_function_return_in_fetch_url(self, detector, context):
        """Resolve simple zero-argument function returns to reduce cross-function misses."""
        source = '''
        function getBaseUrl() {
            return "https://api.example.com";
        }
        fetch(getBaseUrl() + "/users");
        '''
        findings = self._analyze(source, detector, context)

        assert any(
            f.extracted_value == "https://api.example.com/users"
            for f in findings
        )

    def test_resolve_zero_arg_arrow_function_return_in_http_call(self, detector, context):
        """Resolve simple arrow-function string returns used as endpoint helpers."""
        source = '''
        const getOrdersUrl = () => "/api/orders";
        axios.get(getOrdersUrl());
        '''
        findings = self._analyze(source, detector, context)

        assert any(
            f.extracted_value == "/api/orders"
            for f in findings
        )

    def test_resolve_object_pattern_parameter_helper_endpoint(self, detector, context):
        """Resolve helper parameters introduced via shallow object destructuring."""
        source = '''
        function route({ users }) {
            return users;
        }
        fetch(route({ users: "/api/users" }));
        '''
        findings = self._analyze(source, detector, context)

        assert any(
            f.extracted_value == "/api/users"
            for f in findings
        )

    def test_resolve_object_pattern_parameter_helper_endpoint_from_spread_arg(self, detector, context):
        """Resolve object-pattern helper parameters when the argument object uses spread overrides."""
        source = '''
        function route({ users }) {
            return users;
        }
        const base = { users: "/docs/users" };
        fetch(route({ ...base, users: "/api/users" }));
        '''
        findings = self._analyze(source, detector, context)

        assert any(
            f.extracted_value == "/api/users"
            for f in findings
        )

    def test_resolve_object_pattern_parameter_helper_config(self, detector, context):
        """Resolve request-config helpers that destructure object parameters."""
        source = '''
        function requestConfig({ method, url }) {
            return { method, url };
        }
        axios(requestConfig({ method: "POST", url: "/api/orders" }));
        '''
        findings = self._analyze(source, detector, context)

        assert any(
            f.extracted_value == "/api/orders" and f.metadata.get("method") == "POST"
            for f in findings
        )

    def test_resolve_nested_object_pattern_parameter_helper_endpoint(self, detector, context):
        """Resolve helper parameters introduced via nested object destructuring."""
        source = '''
        function route({ api: { users } }) {
            return users;
        }
        fetch(route({ api: { users: "/api/users" } }));
        '''
        findings = self._analyze(source, detector, context)

        assert any(
            f.extracted_value == "/api/users"
            for f in findings
        )

    def test_resolve_nested_object_pattern_parameter_helper_config(self, detector, context):
        """Resolve request-config helpers that use nested object-pattern parameters."""
        source = '''
        function requestConfig({ request: { method, url } }) {
            return { method, url };
        }
        axios(requestConfig({ request: { method: "POST", url: "/api/orders" } }));
        '''
        findings = self._analyze(source, detector, context)

        assert any(
            f.extracted_value == "/api/orders" and f.metadata.get("method") == "POST"
            for f in findings
        )

    def test_resolve_object_pattern_parameter_default_helper_endpoint(self, detector, context):
        """Resolve helper params that rely on object-pattern default values."""
        source = '''
        function route({ users = "/api/users" }) {
            return users;
        }
        fetch(route({}));
        '''
        findings = self._analyze(source, detector, context)

        assert any(
            f.extracted_value == "/api/users"
            for f in findings
        )

    def test_resolve_array_pattern_parameter_default_helper_endpoint(self, detector, context):
        """Resolve helper params that rely on array-pattern default values."""
        source = '''
        function route([users = "/api/users"]) {
            return users;
        }
        fetch(route([]));
        '''
        findings = self._analyze(source, detector, context)

        assert any(
            f.extracted_value == "/api/users"
            for f in findings
        )

    def test_resolve_array_pattern_parameter_helper_endpoint(self, detector, context):
        """Resolve helper parameters introduced via array destructuring."""
        source = '''
        function route([users]) {
            return users;
        }
        fetch(route(["/api/users"]));
        '''
        findings = self._analyze(source, detector, context)

        assert any(
            f.extracted_value == "/api/users"
            for f in findings
        )

    def test_resolve_array_pattern_parameter_helper_config(self, detector, context):
        """Resolve request-config helpers that use array-pattern parameters."""
        source = '''
        function requestConfig([method, url]) {
            return { method, url };
        }
        axios(requestConfig(["POST", "/api/orders"]));
        '''
        findings = self._analyze(source, detector, context)

        assert any(
            f.extracted_value == "/api/orders" and f.metadata.get("method") == "POST"
            for f in findings
        )

    def test_resolve_object_member_concat_in_http_call(self, detector, context):
        """Resolve object-member string constants used to assemble endpoints."""
        source = '''
        const API = {
            host: "https://api.example.com",
            routes: {
                users: "/users"
            }
        };
        fetch(API.host + API.routes.users);
        '''
        findings = self._analyze(source, detector, context)

        assert any(
            f.extracted_value == "https://api.example.com/users"
            for f in findings
        )

    def test_resolve_object_destructured_endpoint_alias(self, detector, context):
        """Resolve top-level destructured endpoint aliases from static route objects."""
        source = '''
        const ROUTES = {
            users: "/api/users"
        };
        const { users: endpoint } = ROUTES;
        fetch(endpoint);
        '''
        findings = self._analyze(source, detector, context)

        assert any(
            f.extracted_value == "/api/users"
            for f in findings
        )

    def test_resolve_object_destructured_endpoint_alias_default(self, detector, context):
        """Resolve destructured aliases that rely on object-pattern defaults."""
        source = '''
        const ROUTES = {};
        const { users: endpoint = "/api/users" } = ROUTES;
        fetch(endpoint);
        '''
        findings = self._analyze(source, detector, context)

        assert any(
            f.extracted_value == "/api/users"
            for f in findings
        )

    def test_resolve_destructured_nested_object_alias_endpoint(self, detector, context):
        """Resolve destructured object aliases that carry nested endpoint members."""
        source = '''
        const GROUPS = {
            api: {
                users: "/api/users"
            }
        };
        const { api: routes } = GROUPS;
        fetch(routes.users);
        '''
        findings = self._analyze(source, detector, context)

        assert any(
            f.extracted_value == "/api/users"
            for f in findings
        )

    def test_resolve_nested_object_destructured_endpoint_alias(self, detector, context):
        """Resolve nested object-pattern aliases from static route objects."""
        source = '''
        const GROUPS = {
            api: {
                users: "/api/users"
            }
        };
        const { api: { users: endpoint } } = GROUPS;
        fetch(endpoint);
        '''
        findings = self._analyze(source, detector, context)

        assert any(
            f.extracted_value == "/api/users"
            for f in findings
        )

    def test_resolve_array_destructured_endpoint_alias(self, detector, context):
        """Resolve array-destructured endpoint aliases from static route arrays."""
        source = '''
        const ROUTES = ["/api/users"];
        const [endpoint] = ROUTES;
        fetch(endpoint);
        '''
        findings = self._analyze(source, detector, context)

        assert any(
            f.extracted_value == "/api/users"
            for f in findings
        )

    def test_detect_identifier_bound_object_config_request(self, detector, context):
        """Resolve axios config identifiers backed by static object literals."""
        source = '''
        const requestConfig = {
            method: "POST",
            url: "/api/orders"
        };
        axios(requestConfig);
        '''
        findings = self._analyze(source, detector, context)

        assert any(
            f.extracted_value == "/api/orders"
            for f in findings
        )

    def test_resolve_helper_returning_object_member_endpoint(self, detector, context):
        """Resolve zero-arg helpers that return object-member endpoints."""
        source = '''
        const ROUTES = { orders: "/api/orders" };
        const getOrdersUrl = () => ROUTES.orders;
        axios.get(getOrdersUrl());
        '''
        findings = self._analyze(source, detector, context)

        assert any(
            f.extracted_value == "/api/orders"
            for f in findings
        )

    def test_resolve_object_method_endpoint_helper(self, detector, context):
        """Resolve object-literal helper methods that assemble endpoints."""
        source = '''
        const api = {
            build(path) {
                return "https://api.example.com" + path;
            }
        };
        fetch(api.build("/users"));
        '''
        findings = self._analyze(source, detector, context)

        assert any(
            f.extracted_value == "https://api.example.com/users"
            for f in findings
        )

    def test_skip_static_asset_member_expression_endpoint_false_positive(self, detector, context):
        """Do not promote object-member static assets into endpoint findings."""
        source = '''
        const assets = { app: "/static/app.js" };
        fetch(assets.app);
        '''
        findings = self._analyze(source, detector, context)

        assert not findings

    def test_skip_static_asset_object_method_false_positive(self, detector, context):
        """Do not classify object-literal helper methods that return assets as endpoints."""
        source = '''
        const assets = {
            app() {
                return "/static/app.js";
            }
        };
        fetch(assets.app());
        '''
        findings = self._analyze(source, detector, context)

        assert not findings

    def test_resolve_single_argument_helper_function_endpoint(self, detector, context):
        """Resolve helper functions that compose endpoints from constant base URLs and arguments."""
        source = '''
        const API_BASE = "https://api.example.com";
        function endpoint(path) {
            return API_BASE + path;
        }
        fetch(endpoint("/users"));
        '''
        findings = self._analyze(source, detector, context)

        assert any(
            f.extracted_value == "https://api.example.com/users"
            for f in findings
        )

    def test_resolve_multi_step_helper_chain_endpoint(self, detector, context):
        """Resolve simple helper chains without executing code."""
        source = '''
        const API_BASE = "https://api.example.com";
        const normalizePath = (path) => path;
        const buildUrl = (path) => API_BASE + normalizePath(path);
        fetch(buildUrl("/orders"));
        '''
        findings = self._analyze(source, detector, context)

        assert any(
            f.extracted_value == "https://api.example.com/orders"
            for f in findings
        )

    def test_resolve_parameterized_helper_with_placeholder_segment(self, detector, context):
        """Preserve endpoint signal when a helper receives an unknown runtime path segment."""
        source = '''
        const API_BASE = "/api/users/";
        const userUrl = (userId) => API_BASE + userId;
        fetch(userUrl(currentUserId));
        '''
        findings = self._analyze(source, detector, context)

        assert any(
            f.extracted_value == "/api/users/${userId}"
            and f.confidence == Confidence.MEDIUM
            for f in findings
        )

    def test_skip_static_asset_parameterized_helper_false_positive(self, detector, context):
        """Do not classify helper-composed static assets as endpoints."""
        source = '''
        const ASSET_BASE = "/static";
        const assetUrl = (name) => ASSET_BASE + "/" + name + ".js";
        fetch(assetUrl("app"));
        '''
        findings = self._analyze(source, detector, context)

        assert not findings

    def test_resolve_conditional_helper_with_boolean_constant(self, detector, context):
        """Resolve conditional helper returns when the branch is statically decidable."""
        source = '''
        const USE_ADMIN = true;
        function route(useAdmin) {
            return useAdmin ? "/api/admin" : "/api/users";
        }
        fetch(route(USE_ADMIN));
        '''
        findings = self._analyze(source, detector, context)

        assert any(
            f.extracted_value == "/api/admin"
            for f in findings
        )

    def test_resolve_conditional_helper_with_computed_boolean_constant(self, detector, context):
        """Resolve branchy helpers when the boolean input is derived from a static comparison."""
        source = '''
        const MODE = "orders";
        const USE_ORDERS = MODE === "orders";
        const route = (useOrders) => useOrders ? "/api/orders" : "/api/users";
        fetch(route(USE_ORDERS));
        '''
        findings = self._analyze(source, detector, context)

        assert any(
            f.extracted_value == "/api/orders"
            for f in findings
        )

    def test_resolve_conditional_helper_chain_with_string_comparison(self, detector, context):
        """Resolve branchy helper chains that compare static string parameters."""
        source = '''
        const MODE = "admin";
        const route = (mode) => mode === "admin" ? "/admin/api/users" : "/public/api/users";
        const buildUrl = (mode) => "https://api.example.com" + route(mode);
        fetch(buildUrl(MODE));
        '''
        findings = self._analyze(source, detector, context)

        assert any(
            f.extracted_value == "https://api.example.com/admin/api/users"
            for f in findings
        )

    def test_resolve_default_parameter_branch_helper_when_argument_omitted(self, detector, context):
        """Resolve branchy helpers that rely on statically known default parameters."""
        source = '''
        const DEFAULT_MODE = "admin";
        function route(mode = DEFAULT_MODE) {
            return mode === "admin" ? "/api/admin" : "/api/users";
        }
        fetch(route());
        '''
        findings = self._analyze(source, detector, context)

        assert any(
            f.extracted_value == "/api/admin"
            for f in findings
        )

    def test_resolve_block_helper_with_default_parameter_alias(self, detector, context):
        """Resolve block-bodied helpers that use default parameters plus local aliases."""
        source = '''
        const DEFAULT_MODE = "orders";
        function buildUrl(mode = DEFAULT_MODE) {
            const base = "https://api.example.com";
            const route = mode === "orders" ? "/orders" : "/users";
            return base + route;
        }
        fetch(buildUrl());
        '''
        findings = self._analyze(source, detector, context)

        assert any(
            f.extracted_value == "https://api.example.com/orders"
            for f in findings
        )

    def test_resolve_nullish_fallback_helper_when_default_is_null(self, detector, context):
        """Resolve nullish-coalescing helpers when a default parameter is statically null."""
        source = '''
        function route(path = null) {
            return path ?? "/api/users";
        }
        fetch(route());
        '''
        findings = self._analyze(source, detector, context)

        assert any(
            f.extracted_value == "/api/users"
            for f in findings
        )

    def test_resolve_block_helper_with_nullish_fallback_chain(self, detector, context):
        """Resolve block-bodied helpers that use nullish fallback before URL assembly."""
        source = '''
        const API_BASE = "https://api.example.com";
        function buildUrl(path = null) {
            const selectedPath = path ?? "/orders";
            return API_BASE + selectedPath;
        }
        fetch(buildUrl());
        '''
        findings = self._analyze(source, detector, context)

        assert any(
            f.extracted_value == "https://api.example.com/orders"
            for f in findings
        )

    def test_skip_nullish_static_asset_fallback_false_positive(self, detector, context):
        """Do not classify nullish-fallback asset helpers as endpoints."""
        source = '''
        function asset(path = null) {
            return path ?? "/static/app.js";
        }
        fetch(asset());
        '''
        findings = self._analyze(source, detector, context)

        assert not findings

    def test_skip_static_asset_conditional_helper_false_positive(self, detector, context):
        """Do not classify statically resolved conditional asset helpers as endpoints."""
        source = '''
        const USE_LEGACY = true;
        const assetPath = (useLegacy) => useLegacy ? "/static/app.legacy.js" : "/static/app.js";
        fetch(assetPath(USE_LEGACY));
        '''
        findings = self._analyze(source, detector, context)

        assert not findings

    def test_resolve_block_helper_with_local_aliases(self, detector, context):
        """Resolve block-bodied helpers that build endpoints through local aliases."""
        source = '''
        function buildUrl(mode) {
            const base = "https://api.example.com";
            const route = mode === "admin" ? "/admin/users" : "/users";
            return base + route;
        }
        fetch(buildUrl("admin"));
        '''
        findings = self._analyze(source, detector, context)

        assert any(
            f.extracted_value == "https://api.example.com/admin/users"
            for f in findings
        )

    def test_resolve_block_helper_if_else_returns(self, detector, context):
        """Resolve block-bodied helpers with explicit if/else return statements."""
        source = '''
        function route(useAdmin) {
            if (useAdmin) {
                return "/api/admin";
            } else {
                return "/api/users";
            }
        }
        fetch(route(true));
        '''
        findings = self._analyze(source, detector, context)

        assert any(
            f.extracted_value == "/api/admin"
            for f in findings
        )

    def test_resolve_block_helper_assignment_before_return(self, detector, context):
        """Resolve block-bodied helpers that assign a local path before returning it."""
        source = '''
        function route(mode) {
            let path;
            if (mode === "admin") {
                path = "/api/admin";
            } else {
                path = "/api/users";
            }
            return path;
        }
        fetch(route("admin"));
        '''
        findings = self._analyze(source, detector, context)

        assert any(
            f.extracted_value == "/api/admin"
            for f in findings
        )

    def test_resolve_block_helper_local_array_lookup(self, detector, context):
        """Resolve block-bodied helpers that return local array-selected endpoints."""
        source = '''
        function route(index) {
            const routes = ["/api/users", "/api/orders"];
            return routes[index];
        }
        fetch(route(1));
        '''
        findings = self._analyze(source, detector, context)

        assert any(
            f.extracted_value == "/api/orders"
            for f in findings
        )

    def test_resolve_block_helper_local_nested_object_array_lookup(self, detector, context):
        """Resolve block-bodied helpers that return nested object-array lookups."""
        source = '''
        function route(index) {
            const groups = {
                api: ["/api/users", "/api/orders"]
            };
            return groups.api[index];
        }
        fetch(route(0));
        '''
        findings = self._analyze(source, detector, context)

        assert any(
            f.extracted_value == "/api/users"
            for f in findings
        )

    def test_resolve_block_helper_local_nested_object_array_lookup_over_global_shadow(self, detector, context):
        """Local helper-scope object-array bindings should override conflicting global constants."""
        source = '''
        const groups = {
            api: ["/static/app.js"]
        };
        function route(index) {
            const groups = {
                api: ["/api/users"]
            };
            return groups.api[index];
        }
        fetch(route(0));
        '''
        findings = self._analyze(source, detector, context)

        assert any(
            f.extracted_value == "/api/users"
            for f in findings
        )
        assert not any(
            f.extracted_value == "/static/app.js"
            for f in findings
        )

    def test_skip_unknown_branch_with_return_to_avoid_endpoint_false_positive(self, detector, context):
        """Do not guess a default branch when an unresolved branch can return a different value."""
        source = '''
        const API_BASE = "https://api.example.com";
        function route(flag) {
            if (flag) {
                return "/admin";
            }
            return "/users";
        }
        fetch(API_BASE + route(runtimeFlag));
        '''
        findings = self._analyze(source, detector, context)

        assert not any(
            f.extracted_value == "https://api.example.com/users"
            for f in findings
        )

    def test_skip_block_helper_local_array_asset_false_positive(self, detector, context):
        """Do not classify block-bodied helpers that select local array assets."""
        source = '''
        function asset(index) {
            const assets = ["/static/app.js", "/static/vendor.js"];
            return assets[index];
        }
        fetch(asset(0));
        '''
        findings = self._analyze(source, detector, context)

        assert not findings

    def test_skip_block_helper_local_nested_object_array_asset_over_global_api(self, detector, context):
        """Local helper-scope asset arrays should override conflicting global API constants."""
        source = '''
        const API_BASE = "/api";
        const groups = {
            api: [API_BASE + "/users"]
        };
        function asset(index) {
            const groups = {
                api: ["/static/app.js"]
            };
            return groups.api[index];
        }
        fetch(asset(0));
        '''
        findings = self._analyze(source, detector, context)

        assert not findings

    def test_skip_block_helper_static_asset_false_positive(self, detector, context):
        """Do not classify block-bodied helper asset paths as endpoints."""
        source = '''
        function asset(useLegacy) {
            const base = "/static";
            if (useLegacy) {
                return base + "/app.legacy.js";
            }
            return base + "/app.js";
        }
        fetch(asset(true));
        '''
        findings = self._analyze(source, detector, context)

        assert not findings

    def test_resolve_switch_helper_return_case(self, detector, context):
        """Resolve switch-based helpers when the discriminant is statically known."""
        source = '''
        function route(mode) {
            switch (mode) {
                case "admin":
                    return "/api/admin";
                case "users":
                    return "/api/users";
                default:
                    return "/api/health";
            }
        }
        fetch(route("admin"));
        '''
        findings = self._analyze(source, detector, context)

        assert any(
            f.extracted_value == "/api/admin"
            for f in findings
        )

    def test_resolve_switch_helper_assignment_then_return(self, detector, context):
        """Resolve switch-based helpers that assign a local path before returning it."""
        source = '''
        function route(mode) {
            let path = "/api/health";
            switch (mode) {
                case "orders":
                    path = "/api/orders";
                    break;
                case "users":
                    path = "/api/users";
                    break;
            }
            return path;
        }
        fetch(route("orders"));
        '''
        findings = self._analyze(source, detector, context)

        assert any(
            f.extracted_value == "/api/orders"
            for f in findings
        )

    def test_skip_unknown_switch_with_return_to_avoid_endpoint_false_positive(self, detector, context):
        """Do not guess a switch case when the discriminant is unresolved."""
        source = '''
        const API_BASE = "https://api.example.com";
        function route(mode) {
            switch (mode) {
                case "admin":
                    return "/admin";
                case "users":
                    return "/users";
                default:
                    return "/health";
            }
        }
        fetch(API_BASE + route(runtimeMode));
        '''
        findings = self._analyze(source, detector, context)

        assert not any(
            f.extracted_value == "https://api.example.com/health"
            for f in findings
        )

    def test_skip_switch_static_asset_false_positive(self, detector, context):
        """Do not classify switch-selected static assets as endpoints."""
        source = '''
        function asset(kind) {
            switch (kind) {
                case "legacy":
                    return "/static/app.legacy.js";
                default:
                    return "/static/app.js";
            }
        }
        fetch(asset("legacy"));
        '''
        findings = self._analyze(source, detector, context)

        assert not findings

    def test_resolve_computed_route_map_lookup_helper(self, detector, context):
        """Resolve computed member lookups when helper parameters select a static route map key."""
        source = '''
        const ROUTES = {
            admin: "/api/admin",
            users: "/api/users"
        };
        function route(kind) {
            return ROUTES[kind];
        }
        fetch(route("admin"));
        '''
        findings = self._analyze(source, detector, context)

        assert any(
            f.extracted_value == "/api/admin"
            for f in findings
        )

    def test_resolve_computed_route_map_lookup_with_logical_key_fallback(self, detector, context):
        """Resolve computed route maps when the selected key is chosen by a logical-expression fallback."""
        source = '''
        const ROUTES = {
            admin: "/api/admin",
            users: "/api/users"
        };
        function route(useAdmin) {
            return ROUTES[useAdmin && "admin" || "users"];
        }
        fetch(route(false));
        '''
        findings = self._analyze(source, detector, context)

        assert any(
            f.extracted_value == "/api/users"
            for f in findings
        )

    def test_resolve_computed_route_map_lookup_with_nullish_key_fallback(self, detector, context):
        """Resolve computed route maps when the selected key uses a nullish-coalescing fallback."""
        source = '''
        const ROUTES = {
            users: "/api/users",
            orders: "/api/orders"
        };
        function route(kind = null) {
            return ROUTES[kind ?? "orders"];
        }
        fetch(route());
        '''
        findings = self._analyze(source, detector, context)

        assert any(
            f.extracted_value == "/api/orders"
            for f in findings
        )

    def test_resolve_computed_route_map_lookup_with_conditional_key(self, detector, context):
        """Resolve computed route maps when the selected key comes from a statically decidable branch."""
        source = '''
        const USE_ADMIN = true;
        const ROUTES = {
            admin: "/api/admin",
            users: "/api/users"
        };
        function route() {
            return ROUTES[USE_ADMIN ? "admin" : "users"];
        }
        fetch(route());
        '''
        findings = self._analyze(source, detector, context)

        assert any(
            f.extracted_value == "/api/admin"
            for f in findings
        )

    def test_skip_unresolved_computed_route_map_branch_to_avoid_endpoint_false_positive(self, detector, context):
        """Do not guess a computed route-map branch when the selected key is unresolved."""
        source = '''
        const API_BASE = "https://api.example.com";
        const ROUTES = {
            admin: "/admin",
            users: "/users"
        };
        function route(useAdmin) {
            return API_BASE + ROUTES[useAdmin ? "admin" : "users"];
        }
        fetch(route(runtimeFlag));
        '''
        findings = self._analyze(source, detector, context)

        assert not any(
            f.extracted_value in {
                "https://api.example.com/admin",
                "https://api.example.com/users",
            }
            for f in findings
        )

    def test_skip_computed_asset_map_lookup_with_nullish_key_false_positive(self, detector, context):
        """Do not classify computed map lookups with nullish key fallback when they still resolve to assets."""
        source = '''
        const ASSETS = {
            app: "/static/app.js",
            vendor: "/static/vendor.js"
        };
        function asset(kind = null) {
            return ASSETS[kind ?? "vendor"];
        }
        fetch(asset());
        '''
        findings = self._analyze(source, detector, context)

        assert not findings

    def test_resolve_array_index_lookup_endpoint(self, detector, context):
        """Resolve direct array index lookups of endpoint strings."""
        source = '''
        const ROUTES = ["/api/users", "/api/orders"];
        fetch(ROUTES[1]);
        '''
        findings = self._analyze(source, detector, context)

        assert any(
            f.extracted_value == "/api/orders"
            for f in findings
        )

    def test_resolve_computed_array_index_lookup_endpoint(self, detector, context):
        """Resolve computed array index lookups when the index is statically known."""
        source = '''
        const ROUTES = ["/api/users", "/api/orders"];
        const routeIndex = 1;
        fetch(ROUTES[routeIndex]);
        '''
        findings = self._analyze(source, detector, context)

        assert any(
            f.extracted_value == "/api/orders"
            for f in findings
        )

    def test_resolve_nested_object_array_lookup_endpoint(self, detector, context):
        """Resolve nested object-array endpoint lookups through computed indexes."""
        source = '''
        const GROUPS = {
            api: ["/api/users", "/api/orders"]
        };
        const routeIndex = 0;
        fetch(GROUPS.api[routeIndex]);
        '''
        findings = self._analyze(source, detector, context)

        assert any(
            f.extracted_value == "/api/users"
            for f in findings
        )

    def test_resolve_logical_fallback_helper_branch(self, detector, context):
        """Resolve logical-expression helper fallbacks when the branch is statically decidable."""
        source = '''
        const USE_ADMIN = false;
        const route = () => USE_ADMIN && "/api/admin" || "/api/users";
        fetch(route());
        '''
        findings = self._analyze(source, detector, context)

        assert any(
            f.extracted_value == "/api/users"
            for f in findings
        )

    def test_skip_computed_asset_map_lookup_false_positive(self, detector, context):
        """Do not classify computed map lookups that resolve to static assets."""
        source = '''
        const ASSETS = { app: "/static/app.js" };
        const asset = (name) => ASSETS[name];
        fetch(asset("app"));
        '''
        findings = self._analyze(source, detector, context)

        assert not findings

    def test_skip_static_asset_array_lookup_false_positive(self, detector, context):
        """Do not classify array-indexed static assets as endpoints."""
        source = '''
        const ASSETS = ["/static/app.js", "/static/vendor.js"];
        const assetIndex = 1;
        fetch(ASSETS[assetIndex]);
        '''
        findings = self._analyze(source, detector, context)

        assert not findings

    def test_skip_logical_asset_fallback_false_positive(self, detector, context):
        """Do not classify statically resolved logical asset fallbacks as endpoints."""
        source = '''
        const USE_LEGACY = false;
        const asset = () => USE_LEGACY && "/static/app.legacy.js" || "/static/app.js";
        fetch(asset());
        '''
        findings = self._analyze(source, detector, context)

        assert not findings

    def test_skip_standalone_docs_and_marketing_full_url_false_positive(self, detector, context):
        """Standalone docs/marketing URLs should not be classified as API endpoints."""
        source = '''
        const docsUrl = "https://example.com/docs/getting-started";
        const pricingUrl = "https://www.example.com/pricing";
        '''
        findings = self._analyze(source, detector, context)

        assert not findings

    def test_skip_standalone_docs_example_api_url_false_positive(self, detector, context):
        """Docs/example lines should suppress standalone API-looking full URLs."""
        source = '''
        const readmeExampleUrl = "https://api.example.com/v1/users";
        '''
        findings = self._analyze(source, detector, context)

        assert not findings

    def test_skip_standalone_docs_object_key_api_url_false_positive(self, detector, context):
        """Docs/example-labeled object keys should suppress standalone API-looking full URLs."""
        source = '''
        const docsLinks = {
            exampleApiUrl: "https://api.example.com/v1/users",
            docsGraphqlUrl: "https://api.example.com/graphql",
        };
        '''
        findings = self._analyze(source, detector, context)

        assert not findings

    def test_resolve_new_url_constructor_in_fetch_call(self, detector, context):
        """Resolve standard URL constructor patterns used directly in fetch calls."""
        source = '''
        const API_BASE = "https://api.example.com";
        fetch(new URL("/users", API_BASE));
        '''
        findings = self._analyze(source, detector, context)

        assert any(
            f.extracted_value == "https://api.example.com/users"
            for f in findings
        )

    def test_resolve_new_url_tostring_in_http_call(self, detector, context):
        """Resolve URL-object `.toString()` calls used as endpoint arguments."""
        source = '''
        const API_BASE = "https://api.example.com/v1/";
        axios.get(new URL("orders", API_BASE).toString());
        '''
        findings = self._analyze(source, detector, context)

        assert any(
            f.extracted_value == "https://api.example.com/v1/orders"
            for f in findings
        )

    def test_resolve_bound_url_object_href_in_fetch_call(self, detector, context):
        """Resolve `URL` instances read back through `.href` properties."""
        source = '''
        const API_BASE = "https://api.example.com";
        const userUrl = new URL("/users", API_BASE);
        fetch(userUrl.href);
        '''
        findings = self._analyze(source, detector, context)

        assert any(
            f.extracted_value == "https://api.example.com/users"
            for f in findings
        )

    def test_resolve_new_request_in_fetch_call(self, detector, context):
        """Resolve standard Request objects passed directly to fetch."""
        source = '''
        fetch(new Request("/api/users", { method: "POST" }));
        '''
        findings = self._analyze(source, detector, context)

        assert any(
            f.extracted_value == "/api/users"
            for f in findings
        )

    def test_resolve_new_request_wrapping_new_url(self, detector, context):
        """Resolve Request objects constructed from URL instances."""
        source = '''
        const API_BASE = "https://api.example.com";
        fetch(new Request(new URL("/users", API_BASE)));
        '''
        findings = self._analyze(source, detector, context)

        assert any(
            f.extracted_value == "https://api.example.com/users"
            for f in findings
        )

    def test_resolve_bound_request_object_in_fetch_call(self, detector, context):
        """Resolve Request instances that are first bound to a variable."""
        source = '''
        const req = new Request("/api/users");
        fetch(req);
        '''
        findings = self._analyze(source, detector, context)

        assert any(
            f.extracted_value == "/api/users"
            for f in findings
        )

    def test_resolve_request_url_property_in_fetch_call(self, detector, context):
        """Resolve `Request.url` property reads used as endpoint arguments."""
        source = '''
        const API_BASE = "https://api.example.com";
        const req = new Request(new URL("/users", API_BASE));
        fetch(req.url);
        '''
        findings = self._analyze(source, detector, context)

        assert any(
            f.extracted_value == "https://api.example.com/users"
            for f in findings
        )

    def test_resolve_request_clone_in_fetch_call(self, detector, context):
        """Resolve cloned Request instances passed into fetch."""
        source = '''
        const req = new Request("/api/users");
        fetch(req.clone());
        '''
        findings = self._analyze(source, detector, context)

        assert any(
            f.extracted_value == "/api/users"
            for f in findings
        )

    def test_resolve_inline_request_clone_in_fetch_call(self, detector, context):
        """Resolve inline Request clone chains passed directly to fetch."""
        source = '''
        fetch(new Request("/api/orders").clone());
        '''
        findings = self._analyze(source, detector, context)

        assert any(
            f.extracted_value == "/api/orders"
            for f in findings
        )

