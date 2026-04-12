# Custom Rules

BundleInspector now ships a lightweight custom rule loader for project-specific misses.
JSON and the shipped YAML subset both work without requiring `PyYAML`.

Supported entry points:

- `bundleInspector scan ... --rules-file custom-rules.json`
- `bundleInspector analyze ... --rules-file custom-rules.json`
- `bundleInspector scan ... --rules-file ./rules/`
- `bundleInspector analyze ... --rules-file ./rules/`
- `bundleInspector scan ... --rules-file ./ruleset/meta.yml`
- `bundleInspector analyze ... --rules-file ./ruleset/meta.yml`
- `bundleInspector scan ... --job-id my-job --resume`
- `bundleInspector analyze ... --job-id my-job --resume`
- `rules.custom_rules_file` inside a YAML/JSON config file

`--rules-file` may point at a single JSON/YAML rule file, a directory of rule
files, or a ruleset-style `meta.yml` file whose sibling `rules/` directory
contains the actual rule files.

The same job cache also stores stage checkpoints, so `--resume` can continue from
stored assets/ASTs/findings instead of only reusing a final report.

## Rule format

Top-level JSON/YAML may be either a list of rules or an object with a `rules` array.
YAML/JSON files may also provide inherited defaults for `category`, `description`,
`value_type`, `severity`, `confidence`, `tags`, `enabled`, `scope`,
`extract_group`, and `flags`. These can be set
either as top-level fields or inside a top-level `defaults:` block. Rule-local
values win, and top-level tags are merged with rule-local tags.
For declarative rules, `defaults:` may also provide `matcher`, `extract`,
`normalize`, and `evidence`, which are deep-merged with rule-local settings.

```json
{
  "rules": [
    {
      "id": "custom-internal-api",
      "title": "Internal API URL",
      "description": "Detect internal-only API hosts",
      "category": "endpoint",
      "severity": "high",
      "confidence": "high",
      "value_type": "internal_api",
      "pattern": "https://internal\\.example\\.com/api/[a-z]+",
      "scope": "source",
      "flags": ["i"],
      "tags": ["custom", "internal"]
    }
  ]
}
```

## Declarative matchers

Shipped declarative support currently covers:

- `matcher.type: regex` for source/string-literal regex rules with extracted fields
- `matcher.type: ast_pattern` for practical `CallExpression`, `NewExpression`, `VariableDeclarator`, `AssignmentExpression`, and `Property` subsets, including AST-side callee/id/left/property-path capture and positional arg-index capture
- `matcher.type: semantic` for practical `AssignmentExpression`, `CallExpression`, `NewExpression`, `VariableDeclarator`, and `Property` subsets, including top-level `logic.any` / `logic.all` / `logic.none` clause objects or shorthand forms without requiring an explicit `and:` wrapper everywhere
- semantic invocation matchers can inspect plain call/constructor arguments and string-valued or direct static member-path properties inside object arguments, including direct static member-path arguments and constant-key computed member lookups when no resolved string exists, plus constant-key computed object-argument property paths, shallow or practical nested object-destructured constant/helper aliases, practical array-destructured constant/helper aliases, practical destructuring aliases with default values, simple helper-returned strings or helper-returned config objects from plain helpers, object spreads and helper-returned spread config objects, spread-backed object-pattern helper arguments, straight-line block-bodied helpers, shallow or practical nested object-pattern helper parameters, practical array-pattern helper parameters, practical destructuring defaults inside those helper parameters, or object-literal helper methods, plus array-selected or locally aliased config objects when the index is statically known, with exact, exact-list, contains, or regex property-path filters and exact/contains/regex denylist path filters, and can capture the matched property path via `path_capture_as` and matched argument index via `index_capture_as`
- semantic variable-declarator matchers can exact-match or regex-match statically resolved initializer strings, direct static member-path initializers, or constant-key computed member lookups with optional negative guards
- semantic property matchers can exact-match or regex-match statically resolved object-literal property values, including helper-returned strings, direct static member-path values, and constant-key computed member lookups, with optional exact or regex property-path filters and optional negative guards
- semantic invocation matchers can exact-match or regex-match resolved plain call/constructor arguments, direct static member-path arguments, constant-key computed member lookups, and string-valued or direct static member-path object-argument properties
- semantic clauses can also use sibling `or:` / `not:` condition groups and apply negative guards to exclude known demo/test/example matches, including negative AST guards on semantic member-path, callee, identifier-name, and property-path filters, and top-level `logic.all` / `logic.none` now accept full clause objects as well as flat condition shorthands
- field-level `mask` handling for extracted metadata values
- optional AST-path attachment via `evidence.include_ast_path`

```json
{
  "rules": [
    {
      "id": "custom-fetch-endpoint",
      "title": "Literal fetch endpoint",
      "category": "endpoint",
      "severity": "medium",
      "confidence": "high",
      "matcher": {
        "type": "ast_pattern",
        "pattern": {
          "kind": "CallExpression",
          "callee_any_of": ["fetch"],
          "args": [
            {
              "type": "LiteralString",
              "capture_as": "endpoint"
            }
          ]
        }
      },
      "extract": {
        "fields": {
          "endpoint": {
            "from_capture": "endpoint"
          },
          "method": {
            "static": "GET|UNKNOWN"
          }
        }
      }
    }
  ]
}
```

## Fields

- `id`: unique rule id
- `title`: finding title
- `description`: optional finding description
- `category`: one of `endpoint`, `secret`, `domain`, `flag`, `debug`
- `severity`: `info`, `low`, `medium`, `high`, `critical`
- `confidence`: `low`, `medium`, `high`
- `value_type`: stored on the finding
- `pattern`: Python regular expression
- `scope`: `source` or `string_literal`; may be inherited from top-level or `defaults:`
- `extract_group`: optional capture group index to emit instead of the full match; may be inherited from top-level or `defaults:`
- `flags`: optional regex flags from `i`, `m`, `s`, `x`; top-level or `defaults:` flags merge with rule-local flags
- `tags`: optional extra finding tags

Declarative matcher fields:

- `matcher.type`: `regex`, `ast_pattern`, or `semantic`
- `matcher.pattern.kind`: currently `CallExpression`, `NewExpression`, `VariableDeclarator`, `AssignmentExpression`, or `Property`
- `matcher.pattern.callee_any_of`: allowed call names such as `fetch` or `axios.get`
- `matcher.pattern.not_callee_any_of`: exact denylist for call names
- `matcher.pattern.callee_contains_any_of`: substring allowlist for call names
- `matcher.pattern.not_callee_contains_any_of`: substring denylist for call names
- `matcher.pattern.callee_regex_any_of`: regex allowlist for call names; matches either the full callee path or its short name
- `matcher.pattern.not_callee_regex_any_of`: regex denylist for call names
- `matcher.pattern.callee_capture_as`: captures the matched full callee path
- `matcher.pattern.args`: positional or selected-argument matchers; current shipped matcher supports `LiteralString`, `TemplateLiteral`, `IdentifierString`, `IdentifierName`, `MemberPath`, and `Any`
- `matcher.pattern.args[]` / `matcher.pattern.init` / `matcher.pattern.right` / `matcher.pattern.value`: support `any_of` / `not_any_of`, `contains_any_of` / `not_contains_any_of`, optional `regex` / `not_regex`, and `capture_as`, and can resolve direct identifier names, static member-expression paths, or constant-key computed member lookups via `IdentifierName` / `MemberPath`
- `matcher.pattern.args[].index` / `matcher.pattern.args[].index_any_of`: optionally target one or more candidate argument positions instead of relying only on declaration order
- `matcher.pattern.args[].index_capture_as`: captures the matched positional argument index for `CallExpression` / `NewExpression`
- `matcher.pattern.id_name_any_of`: exact identifier allowlist for `VariableDeclarator`
- `matcher.pattern.not_id_name_any_of`: exact identifier denylist for `VariableDeclarator`
- `matcher.pattern.id_name_contains_any_of`: substring allowlist for `VariableDeclarator` identifier names
- `matcher.pattern.not_id_name_contains_any_of`: substring denylist for `VariableDeclarator` identifier names
- `matcher.pattern.id_name_regex`: regex allowlist for `VariableDeclarator` identifier names
- `matcher.pattern.not_id_name_regex`: regex denylist for `VariableDeclarator` identifier names
- `matcher.pattern.id_name_capture_as`: captures the matched declarator identifier
- `matcher.pattern.init`: initializer matcher for `VariableDeclarator`
- `matcher.pattern.left_any_of`: exact member-path allowlist for `AssignmentExpression`, including constant-key computed member paths
- `matcher.pattern.not_left_any_of`: exact member-path denylist for `AssignmentExpression`
- `matcher.pattern.left_contains_any_of`: substring allowlist for `AssignmentExpression` member paths
- `matcher.pattern.not_left_contains_any_of`: substring denylist for `AssignmentExpression` member paths
- `matcher.pattern.left_regex_any_of`: regex allowlist for `AssignmentExpression` member paths
- `matcher.pattern.not_left_regex_any_of`: regex denylist for `AssignmentExpression` member paths
- `matcher.pattern.left_capture_as`: captures the matched left-hand member path
- `matcher.pattern.right`: right-hand matcher for `AssignmentExpression`
- `matcher.pattern.property_path_any_of`: exact nested object-literal property-path allowlist for `Property`, including constant-key computed property keys
- `matcher.pattern.not_property_path_any_of`: exact nested object-literal property-path denylist for `Property`
- `matcher.pattern.property_path_contains_any_of`: substring allowlist for nested object-literal property paths
- `matcher.pattern.not_property_path_contains_any_of`: substring denylist for nested object-literal property paths
- `matcher.pattern.property_path_regex_any_of`: regex allowlist for nested object-literal property paths
- `matcher.pattern.not_property_path_regex_any_of`: regex denylist for nested object-literal property paths
- `matcher.pattern.property_path_capture_as`: captures the matched nested property path
- `matcher.pattern.value`: value matcher for `Property`
- `matcher.logic.any[].and[]` / direct `matcher.logic.any[]` clause objects / direct `matcher.logic.all` clause objects / direct `matcher.logic.none` clause objects / `matcher.logic.all[]` / `matcher.logic.none[]`: practical semantic matcher clauses; the current shipped subset supports sibling clause-level `or:` / `not:` groups and `AssignmentExpression` + `left_matches.any_of`/`left_matches.not_any_of`/`left_matches.contains_any_of`/`left_matches.not_contains_any_of`/`left_matches.regex_any_of`/`left_matches.not_regex_any_of` plus optional `left_capture_as`, including constant-key computed left-hand member paths, `VariableDeclarator` + `id_name_any_of`/`not_id_name_any_of`/`id_name_contains_any_of`/`not_id_name_contains_any_of`/`id_name_regex_any_of`/`not_id_name_regex_any_of` plus optional `id_name_capture_as`, `Property` + `property_path_any_of`/`not_property_path_any_of`/`property_path_contains_any_of`/`not_property_path_contains_any_of`/`property_path_regex_any_of`/`not_property_path_regex_any_of` plus optional `property_path_capture_as`, including constant-key computed property paths, and `CallExpression`/`NewExpression` + `callee_any_of`/`not_callee_any_of`/`callee_contains_any_of`/`not_callee_contains_any_of`/`callee_regex_any_of`/`not_callee_regex_any_of` plus optional `callee_capture_as`, alongside the existing `right_any_of`/`not_right_any_of` + `right_contains_any_of`/`not_right_contains_any_of` + `regex_on_right`/`not_regex_on_right`, `init_any_of`/`not_init_any_of` + `init_contains_any_of`/`not_init_contains_any_of` + `regex_on_init`/`not_regex_on_init`, `value_any_of`/`not_value_any_of` + `value_contains_any_of`/`not_value_contains_any_of` + `regex_on_value`/`not_regex_on_value`, `arg_any_of`/`not_arg_any_of` + `arg_contains_any_of`/`not_arg_contains_any_of` + `regex_on_arg`/`not_regex_on_arg`, and `object_arg_property_any_of`/`not_object_arg_property_any_of` + `object_arg_property_contains_any_of`/`not_object_arg_property_contains_any_of` + `regex_on_object_arg_property`/`not_regex_on_object_arg_property` for string-valued or direct static member-path properties inside object arguments with `path`, `path_any_of`, `not_path_any_of`, `path_contains_any_of`, `not_path_contains_any_of`, `path_regex_any_of`, or `not_path_regex_any_of`, including constant-key computed object-argument property paths, shallow or practical nested object-destructured constant/helper aliases, practical array-destructured constant/helper aliases, practical destructuring aliases with default values, simple helper-returned string arguments, helper-returned config objects from plain helpers, object spreads and helper-returned spread config objects, spread-backed object-pattern helper arguments, straight-line block-bodied helpers, shallow or practical nested object-pattern helper parameters, practical array-pattern helper parameters, practical destructuring defaults inside those helper parameters, or object-literal helper methods, and array-selected or locally aliased config objects when the index is statically known
- `matcher.logic.any[].and[].regex_on_arg` / `arg_any_of` / `arg_contains_any_of`: plain argument filters support `index` or `index_any_of`, plus `index_capture_as`
- `matcher.logic.any[].and[].regex_on_object_arg_property` / `object_arg_property_any_of` / `object_arg_property_contains_any_of`: object-argument property filters support `index` or `index_any_of`, `path`, `path_any_of`, `not_path_any_of`, `path_contains_any_of`, `not_path_contains_any_of`, `path_regex_any_of`, or `not_path_regex_any_of`, plus `path_capture_as` and `index_capture_as`
- `extract.fields`: maps captures or static values into finding metadata
- `extract.fields.<name>.mask`: supports patterns such as `keep_prefix_6_suffix_4`
- `normalize.<field>`: supports `strip_query` and `lowercase` on extracted fields
- `evidence.include_ast_path`: stores a stable AST path in finding metadata when the matcher can determine it

Call-expression semantic example:

```yaml
category: secrets
rules:
  - id: SEC_AUTH_HEADER_SETTER
    title: "Bearer token passed to headers.set"
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: CallExpression
                  callee_any_of:
                    - "headers.set"
              - regex_on_arg:
                  index: 0
                  pattern: "(?i)^Authorization$"
              - regex_on_arg:
                  index: 1
                  pattern: "(?i)^Bearer\\s+[A-Za-z0-9\\-\\._~\\+\\/]+=*$"
                  capture_as: token
    extract:
      fields:
        secret_value: { from_capture: token, mask: "keep_prefix_6_suffix_4" }
```

Helper-returned object semantic example:

```yaml
category: secrets
rules:
  - id: SEC_CLIENT_AUTH_HELPER_OBJECT
    title: "Bearer token passed via helper-returned config object"
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: CallExpression
                  callee_any_of:
                    - "client.request"
              - regex_on_object_arg_property:
                  index: 0
                  path: "headers.Authorization"
                  pattern: "(?i)^Bearer\\s+[A-Za-z0-9\\-\\._~\\+\\/]+=*$"
                  capture_as: token
    extract:
      fields:
        secret_value: { from_capture: token, mask: "keep_prefix_6_suffix_4" }
```

Object-argument semantic example:

```yaml
category: secrets
rules:
  - id: SEC_FETCH_AUTH_OPTION
    title: "Bearer token passed inside fetch options headers"
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: CallExpression
                  callee_any_of:
                    - "fetch"
              - regex_on_object_arg_property:
                  index: 1
                  path: "headers.Authorization"
                  pattern: "(?i)^Bearer\\s+[A-Za-z0-9\\-\\._~\\+\\/]+=*$"
                  capture_as: token
    extract:
      fields:
        secret_value: { from_capture: token, mask: "keep_prefix_6_suffix_4" }
```

Property-value semantic example:

```yaml
category: secrets
rules:
  - id: SEC_CONFIG_AUTH_PROPERTY
    title: "Bearer token stored in nested config property"
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: Property
                  property_path_any_of:
                    - "headers.Authorization"
              - regex_on_value:
                  pattern: "(?i)^Bearer\\s+[A-Za-z0-9\\-\\._~\\+\\/]+=*$"
                  capture_as: token
              - not_regex_on_value:
                  pattern: "(?i)demo|example|mock"
    extract:
      fields:
        secret_value: { from_capture: token, mask: "keep_prefix_6_suffix_4" }
```

Negative-guard semantic example:

```yaml
category: secrets
rules:
  - id: SEC_AUTH_HEADER_LIVE_ONLY
    title: "Bearer token passed to headers.set excluding demo values"
    matcher:
      type: semantic
      logic:
        any:
          - and:
              - ast:
                  kind: CallExpression
                  callee_any_of:
                    - "headers.set"
              - regex_on_arg:
                  index: 0
                  pattern: "(?i)^Authorization$"
              - regex_on_arg:
                  index: 1
                  pattern: "(?i)^Bearer\\s+[A-Za-z0-9\\-\\._~\\+\\/]+=*$"
                  capture_as: token
              - not_regex_on_arg:
                  index: 1
                  pattern: "(?i)^Bearer\\s+(test|demo)-"
    extract:
      fields:
        secret_value: { from_capture: token, mask: "keep_prefix_6_suffix_4" }
```

## FP/FN guidance

- Prefer `scope: "string_literal"` when the signal should only come from literal values. This reduces false positives from comments or surrounding syntax.
- Anchor patterns as tightly as possible. Avoid generic substrings like `token` or `admin`.
- Use `extract_group` when the full match contains extra assignment syntax and only the captured value should appear in the finding.
- Prefer the declarative `ast_pattern` matcher when the signal is tied to a real call site such as `fetch("...")`. That reduces false positives compared with broad source regexes.
- Add a focused test fixture for each custom rule so project-specific false negatives stay closed over time.

