"""Tests for IR builder enrichment."""

from bundleInspector.parser.export_scopes import (
    build_commonjs_default_object_export_members,
    build_commonjs_export_metadata,
    build_commonjs_named_object_export_members,
    build_commonjs_require_bindings,
    build_commonjs_re_export_bindings,
    build_default_object_export_members,
    build_export_scope_map,
    build_named_object_export_members,
    build_re_export_bindings,
)
from bundleInspector.parser.js_parser import parse_js
from bundleInspector.parser.ir_builder import build_ir


def test_build_call_graph_for_named_functions():
    """IR builder should record simple intra-file function call chains."""
    source = """
    function inner() {
      return fetch("/api/users");
    }

    function outer() {
      return inner();
    }
    """

    result = parse_js(source)
    assert result.success is True
    assert result.ast is not None

    ir = build_ir(result.ast, "file:///bundle.js", "hash123")

    assert ir.call_graph["function:outer"] == ["function:inner"]
    assert any(func.scope == "function:inner" for func in ir.function_defs)


def test_build_call_graph_for_object_and_class_methods():
    """IR builder should name object/class methods so same-file call graphs can reach them."""
    source = """
    const api = {
      loadUsers() {
        return "/api/users";
      }
    };

    class Client {
      saveUsers() {
        return loadUsers();
      }
    }

    function boot() {
      api.loadUsers();
      const client = new Client();
      return client.saveUsers();
    }
    """

    result = parse_js(source)
    assert result.success is True
    assert result.ast is not None

    ir = build_ir(result.ast, "file:///bundle.js", "hash123")

    assert "function:loadUsers" in ir.call_graph["function:boot"]
    assert "function:saveUsers" in ir.call_graph["function:boot"]
    assert ir.call_graph["function:saveUsers"] == ["function:loadUsers"]


def test_build_export_scope_map_for_default_and_aliased_arrow_exports():
    """Export scope metadata should resolve aliased/default exports back to arrow scopes."""
    source = """
    const fetchUsers = () => "/api/users";
    export { fetchUsers as loadUsers };
    export default fetchUsers;
    """

    result = parse_js(source)
    assert result.success is True
    assert result.ast is not None

    ir = build_ir(result.ast, "file:///bundle.js", "hash123")
    export_scopes = build_export_scope_map(ir)

    assert export_scopes["loadUsers"] == export_scopes["default"]
    assert export_scopes["default"][0].startswith("function:arrow@")


def test_build_export_scope_map_for_direct_default_object_members():
    """Default-exported object literals should expose callable member scopes for correlation."""
    source = """
    function fetchUsers() {}
    export default { loadUsers: fetchUsers };
    """

    result = parse_js(source)
    assert result.success is True
    assert result.ast is not None

    ir = build_ir(result.ast, "file:///bundle.js", "hash123")
    export_scopes = build_export_scope_map(ir)

    assert export_scopes["loadUsers"] == ["function:fetchUsers"]
    assert "default" in export_scopes


def test_build_export_scope_map_for_identifier_backed_default_object_members():
    """Identifier-backed default-exported object literals should expose callable member scopes."""
    source = """
    function fetchUsers() {}
    const api = { loadUsers: fetchUsers };
    export default api;
    """

    result = parse_js(source)
    assert result.success is True
    assert result.ast is not None

    ir = build_ir(result.ast, "file:///bundle.js", "hash123")
    export_scopes = build_export_scope_map(ir)

    assert export_scopes["loadUsers"] == ["function:fetchUsers"]
    assert "default" in export_scopes


def test_build_export_scope_map_for_default_and_named_class_members():
    """Class exports should expose callable member scopes for correlation."""
    source = """
    export class Api {
      loadUsers() {}
      static ping() {}
    }

    class Client {
      fetchToken() {}
    }

    export default Client;
    """

    result = parse_js(source)
    assert result.success is True
    assert result.ast is not None

    ir = build_ir(result.ast, "file:///bundle.js", "hash123")
    export_scopes = build_export_scope_map(ir)

    assert export_scopes["loadUsers"] == ["function:loadUsers"]
    assert export_scopes["ping"] == ["function:ping"]
    assert export_scopes["fetchToken"] == ["function:fetchToken"]


def test_build_default_object_export_members_for_direct_and_identifier_exports():
    """Default-object export helpers should surface callable member names."""
    direct_source = """
    function fetchUsers() {}
    export default { loadUsers: fetchUsers };
    """
    direct_result = parse_js(direct_source)
    assert direct_result.success is True
    assert direct_result.ast is not None
    direct_ir = build_ir(direct_result.ast, "file:///bundle.js", "hash123")
    assert build_default_object_export_members(direct_ir) == ["loadUsers"]

    identifier_source = """
    function fetchUsers() {}
    const api = { loadUsers: fetchUsers };
    export default api;
    """
    identifier_result = parse_js(identifier_source)
    assert identifier_result.success is True
    assert identifier_result.ast is not None
    identifier_ir = build_ir(identifier_result.ast, "file:///bundle.js", "hash123")
    assert build_default_object_export_members(identifier_ir) == ["loadUsers"]

    class_source = """
    export default class Client {
      loadUsers() {}
      ping() {}
    }
    """
    class_result = parse_js(class_source)
    assert class_result.success is True
    assert class_result.ast is not None
    class_ir = build_ir(class_result.ast, "file:///bundle.js", "hash123")
    assert build_default_object_export_members(class_ir) == ["loadUsers", "ping"]


def test_build_named_object_export_members_for_direct_and_aliased_exports():
    """Named object exports should surface callable member names under exported aliases."""
    source = """
    function fetchUsers() {}
    export const api = { loadUsers: fetchUsers };

    const client = { loadUsers: fetchUsers };
    export { client as sdk };
    """

    result = parse_js(source)
    assert result.success is True
    assert result.ast is not None

    ir = build_ir(result.ast, "file:///bundle.js", "hash123")

    assert build_named_object_export_members(ir) == {
        "api": ["loadUsers"],
        "sdk": ["loadUsers"],
    }


def test_build_named_object_export_members_for_class_exports():
    """Named class exports should surface callable member names under exported aliases."""
    source = """
    export class Api {
      loadUsers() {}
    }

    class Client {
      fetchToken() {}
    }

    export { Client as sdk };
    """

    result = parse_js(source)
    assert result.success is True
    assert result.ast is not None

    ir = build_ir(result.ast, "file:///bundle.js", "hash123")

    assert build_named_object_export_members(ir) == {
        "Api": ["loadUsers"],
        "sdk": ["fetchToken"],
    }


def test_build_commonjs_default_object_export_members():
    """CommonJS object default exports should surface callable member names."""
    source = """
    function fetchUsers() {}
    const api = { loadUsers: fetchUsers };
    module.exports = api;
    """

    result = parse_js(source)
    assert result.success is True
    assert result.ast is not None

    ir = build_ir(result.ast, "file:///bundle.js", "hash123")

    assert build_commonjs_default_object_export_members(ir) == ["loadUsers"]

    class_source = """
    class Api {
      loadUsers() {}
      ping() {}
    }
    module.exports = Api;
    """
    class_result = parse_js(class_source)
    assert class_result.success is True
    assert class_result.ast is not None
    class_ir = build_ir(class_result.ast, "file:///bundle.js", "hash123")

    assert build_commonjs_default_object_export_members(class_ir) == ["loadUsers", "ping"]


def test_build_commonjs_named_object_export_members():
    """Named CommonJS object exports should surface callable member names."""
    source = """
    function fetchUsers() {}
    const api = { loadUsers: fetchUsers };
    exports.client = api;
    module.exports = { sdk: api };
    """

    result = parse_js(source)
    assert result.success is True
    assert result.ast is not None

    ir = build_ir(result.ast, "file:///bundle.js", "hash123")

    assert build_commonjs_named_object_export_members(ir) == {
        "client": ["loadUsers"],
        "sdk": ["loadUsers"],
    }

    class_source = """
    class Api {
      loadUsers() {}
    }
    exports.client = Api;
    """
    class_result = parse_js(class_source)
    assert class_result.success is True
    assert class_result.ast is not None
    class_ir = build_ir(class_result.ast, "file:///bundle.js", "hash123")

    assert build_commonjs_named_object_export_members(class_ir) == {
        "client": ["loadUsers"],
    }


def test_build_reexport_bindings_for_named_and_default_export_from():
    """Re-export specifiers should map exported names back to forwarded sources."""
    source = 'export { fetchUsers as loadUsers, default as defaultClient } from "./api";'

    result = parse_js(source)
    assert result.success is True
    assert result.ast is not None

    ir = build_ir(result.ast, "file:///bundle.js", "hash123")
    bindings = build_re_export_bindings(ir)

    assert {
        "source": "./api",
        "imported": "fetchUsers",
        "local": "loadUsers",
        "kind": "named",
        "scope": "global",
        "is_dynamic": False,
        "is_reexport": True,
    } in bindings
    assert {
        "source": "./api",
        "imported": "default",
        "local": "defaultClient",
        "kind": "default",
        "scope": "global",
        "is_dynamic": False,
        "is_reexport": True,
    } in bindings


def test_build_reexport_bindings_for_export_all():
    """Export-all declarations should surface as same-name forwarding bindings."""
    source = 'export * from "./api";'

    result = parse_js(source)
    assert result.success is True
    assert result.ast is not None

    ir = build_ir(result.ast, "file:///bundle.js", "hash123")
    bindings = build_re_export_bindings(ir)

    assert {
        "source": "./api",
        "imported": "*",
        "local": "*",
        "kind": "namespace",
        "scope": "global",
        "is_dynamic": False,
        "is_reexport": True,
        "is_reexport_all": True,
    } in bindings


def test_build_commonjs_require_bindings_for_default_and_named_patterns():
    """CommonJS require patterns should produce practical import bindings."""
    source = """
    const api = require("./api");
    const { loadUsers, default: defaultClient } = require("./client");
    """

    result = parse_js(source)
    assert result.success is True
    assert result.ast is not None

    ir = build_ir(result.ast, "file:///bundle.js", "hash123")
    bindings = build_commonjs_require_bindings(ir)

    assert {
        "source": "./api",
        "imported": "default",
        "local": "api",
        "kind": "default",
        "scope": "global",
        "is_dynamic": False,
        "is_commonjs": True,
    } in bindings
    assert {
        "source": "./client",
        "imported": "loadUsers",
        "local": "loadUsers",
        "kind": "named",
        "scope": "global",
        "is_dynamic": False,
        "is_commonjs": True,
    } in bindings
    assert {
        "source": "./client",
        "imported": "default",
        "local": "defaultClient",
        "kind": "default",
        "scope": "global",
        "is_dynamic": False,
        "is_commonjs": True,
    } in bindings


def test_build_commonjs_export_metadata_for_default_named_and_object_exports():
    """CommonJS export assignments should resolve practical export names and scopes."""
    source = """
    function fetchUsers() {}
    function pingUsers() {}
    module.exports = fetchUsers;
    exports.loadUsers = fetchUsers;
    module.exports = { ping: pingUsers };
    """

    result = parse_js(source)
    assert result.success is True
    assert result.ast is not None

    ir = build_ir(result.ast, "file:///bundle.js", "hash123")
    exports, export_scopes = build_commonjs_export_metadata(ir)

    assert "default" in exports
    assert "loadUsers" in exports
    assert "ping" in exports
    assert export_scopes["default"] == ["function:fetchUsers"]
    assert export_scopes["loadUsers"] == ["function:fetchUsers"]
    assert export_scopes["ping"] == ["function:pingUsers"]


def test_build_commonjs_reexport_bindings_for_default_and_named_forwarding():
    """CommonJS barrel exports should surface as forwarding bindings."""
    source = """
    module.exports = require("./api");
    exports.loadUsers = require("./api").loadUsers;
    """

    result = parse_js(source)
    assert result.success is True
    assert result.ast is not None

    ir = build_ir(result.ast, "file:///bundle.js", "hash123")
    bindings = build_commonjs_re_export_bindings(ir)

    assert {
        "source": "./api",
        "imported": "default",
        "local": "default",
        "kind": "default",
        "scope": "global",
        "is_dynamic": False,
        "is_reexport": True,
        "is_commonjs_reexport": True,
    } in bindings
    assert {
        "source": "./api",
        "imported": "loadUsers",
        "local": "loadUsers",
        "kind": "named",
        "scope": "global",
        "is_dynamic": False,
        "is_reexport": True,
        "is_commonjs_reexport": True,
    } in bindings


def test_build_commonjs_reexport_bindings_for_object_barrel_forwarding():
    """Object-style CommonJS barrels should surface property-level forwarding bindings."""
    source = 'module.exports = { loadUsers: require("./api").loadUsers };'

    result = parse_js(source)
    assert result.success is True
    assert result.ast is not None

    ir = build_ir(result.ast, "file:///bundle.js", "hash123")
    bindings = build_commonjs_re_export_bindings(ir)

    assert {
        "source": "./api",
        "imported": "loadUsers",
        "local": "loadUsers",
        "kind": "named",
        "scope": "global",
        "is_dynamic": False,
        "is_reexport": True,
        "is_commonjs_reexport": True,
    } in bindings


def test_build_commonjs_reexport_bindings_for_identifier_backed_require_aliases():
    """Identifier-backed require aliases should still surface as CommonJS forwarding bindings."""
    source = """
    const api = require("./api");
    const pingUsers = require("./api").pingUsers;
    module.exports = api;
    module.exports.loadUsers = api.loadUsers;
    module.exports = { ping: pingUsers };
    """

    result = parse_js(source)
    assert result.success is True
    assert result.ast is not None

    ir = build_ir(result.ast, "file:///bundle.js", "hash123")
    bindings = build_commonjs_re_export_bindings(ir)

    assert {
        "source": "./api",
        "imported": "default",
        "local": "default",
        "kind": "default",
        "scope": "global",
        "is_dynamic": False,
        "is_reexport": True,
        "is_commonjs_reexport": True,
    } in bindings
    assert {
        "source": "./api",
        "imported": "loadUsers",
        "local": "loadUsers",
        "kind": "named",
        "scope": "global",
        "is_dynamic": False,
        "is_reexport": True,
        "is_commonjs_reexport": True,
    } in bindings
    assert {
        "source": "./api",
        "imported": "pingUsers",
        "local": "ping",
        "kind": "named",
        "scope": "global",
        "is_dynamic": False,
        "is_reexport": True,
        "is_commonjs_reexport": True,
    } in bindings

