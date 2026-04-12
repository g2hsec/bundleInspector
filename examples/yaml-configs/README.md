# YAML Configuration Examples

These YAML files are reference examples for a declarative rule configuration format.

## Files

- `default.yml` - Example default configuration with all settings
- `rulesets/meta.yml` - Ruleset metadata format
- `rulesets/rules/*.yml` - Rule definition examples per category

## Note

The current BundleInspector implementation now supports the practical rule/config surface
documented in this folder. The shipped runtime currently handles:

- top-level `category` inheritance
- `matcher.type: regex`
- `matcher.type: ast_pattern` for practical `CallExpression` and `VariableDeclarator` subsets
- `matcher.type: semantic` for practical `AssignmentExpression` and `CallExpression` subsets, including top-level `logic.any` / `logic.all` / `logic.none` clause objects or shorthand forms without explicit `and:` wrappers everywhere
- extracted-field masking, optional AST-path metadata, static member-expression resolution, regex-based left/callee matching, object-argument property matching, and negative semantic guards on supported matcher types

The example ruleset pack in this folder is intended to run as-is against the
current shipped runtime.

## Rule Format Example

```yaml
category: endpoints
rules:
  - id: EP_FETCH_LITERAL
    title: "Detect literal fetch endpoints"
    severity: medium
    confidence: high
    matcher:
      type: ast_pattern
      pattern:
        kind: CallExpression
        callee_any_of:
          - "fetch"
        args:
          - type: LiteralString
            capture_as: endpoint
    extract:
      fields:
        endpoint:
          from_capture: endpoint
    evidence:
      snippet_from: normalized
```

