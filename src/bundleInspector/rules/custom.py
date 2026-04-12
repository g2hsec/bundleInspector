"""
Custom rule loading for user-defined regex, AST-pattern, and semantic detectors.
"""

from __future__ import annotations

import json
import re
from copy import deepcopy
from pathlib import Path
from typing import Any, Iterator, Literal, Optional
from urllib.parse import urlsplit, urlunsplit

from pydantic import BaseModel, Field, model_validator

from bundleInspector.rules.base import AnalysisContext, BaseRule, RuleResult
from bundleInspector.storage.models import Category, Confidence, IntermediateRepresentation, Severity
from bundleInspector.utils.yaml_loader import load_yaml

_CATEGORY_ALIASES = {
    "endpoint": Category.ENDPOINT,
    "endpoints": Category.ENDPOINT,
    "secret": Category.SECRET,
    "secrets": Category.SECRET,
    "domain": Category.DOMAIN,
    "domains": Category.DOMAIN,
    "flag": Category.FLAG,
    "flags": Category.FLAG,
    "feature_flag": Category.FLAG,
    "feature_flags": Category.FLAG,
    "feature-flags": Category.FLAG,
    "featureflags": Category.FLAG,
    "debug": Category.DEBUG,
}


class CustomRuleSpec(BaseModel):
    """Schema for a custom regex rule."""

    id: str
    title: str
    description: str = ""
    category: Category
    severity: Severity = Severity.INFO
    confidence: Confidence = Confidence.MEDIUM
    value_type: str = "custom_match"
    pattern: str
    scope: Literal["source", "string_literal"] = "source"
    extract_group: int = 0
    flags: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    enabled: bool = True


class AstPatternArgSpec(BaseModel):
    """Single positional argument matcher for AST-pattern rules."""

    type: Literal["LiteralString", "TemplateLiteral", "IdentifierString", "IdentifierName", "MemberPath", "Any"] = "Any"
    index: Optional[int] = None
    index_any_of: list[int] = Field(default_factory=list)
    any_of: list[str] = Field(default_factory=list)
    not_any_of: list[str] = Field(default_factory=list)
    contains_any_of: list[str] = Field(default_factory=list)
    not_contains_any_of: list[str] = Field(default_factory=list)
    regex: Optional[str] = None
    not_regex: Optional[str] = None
    index_capture_as: Optional[str] = None
    capture_as: Optional[str] = None
    capture_group: int = 0


class AstPatternSpec(BaseModel):
    """Minimal AST pattern supported by shipped custom rules."""

    kind: Literal["CallExpression", "NewExpression", "VariableDeclarator", "AssignmentExpression", "Property"] = "CallExpression"
    callee_any_of: list[str] = Field(default_factory=list)
    not_callee_any_of: list[str] = Field(default_factory=list)
    callee_contains_any_of: list[str] = Field(default_factory=list)
    not_callee_contains_any_of: list[str] = Field(default_factory=list)
    callee_regex_any_of: list[str] = Field(default_factory=list)
    not_callee_regex_any_of: list[str] = Field(default_factory=list)
    callee_capture_as: Optional[str] = None
    args: list[AstPatternArgSpec] = Field(default_factory=list)
    id_name_any_of: list[str] = Field(default_factory=list)
    not_id_name_any_of: list[str] = Field(default_factory=list)
    id_name_contains_any_of: list[str] = Field(default_factory=list)
    not_id_name_contains_any_of: list[str] = Field(default_factory=list)
    id_name_regex: Optional[str] = None
    not_id_name_regex: Optional[str] = None
    id_name_capture_as: Optional[str] = None
    left_any_of: list[str] = Field(default_factory=list)
    not_left_any_of: list[str] = Field(default_factory=list)
    left_contains_any_of: list[str] = Field(default_factory=list)
    not_left_contains_any_of: list[str] = Field(default_factory=list)
    left_regex_any_of: list[str] = Field(default_factory=list)
    not_left_regex_any_of: list[str] = Field(default_factory=list)
    left_capture_as: Optional[str] = None
    property_path_any_of: list[str] = Field(default_factory=list)
    not_property_path_any_of: list[str] = Field(default_factory=list)
    property_path_contains_any_of: list[str] = Field(default_factory=list)
    not_property_path_contains_any_of: list[str] = Field(default_factory=list)
    property_path_regex_any_of: list[str] = Field(default_factory=list)
    not_property_path_regex_any_of: list[str] = Field(default_factory=list)
    property_path_capture_as: Optional[str] = None
    init: Optional[AstPatternArgSpec] = None
    right: Optional[AstPatternArgSpec] = None
    value: Optional[AstPatternArgSpec] = None


class MatcherSpec(BaseModel):
    """Declarative matcher definition."""

    model_config = {"extra": "allow"}
    type: Literal["ast_pattern", "regex", "semantic"]
    pattern: Optional[AstPatternSpec] = None


class RegexMatcherSpec(BaseModel):
    """Declarative regex matcher definition."""

    type: Literal["regex"] = "regex"
    pattern: str
    capture_as: Optional[str] = None
    capture_group: int = 0
    scope: Literal["source", "string_literal"] = "source"
    flags: list[str] = Field(default_factory=list)


class ExtractFieldSpec(BaseModel):
    """Field extraction definition for declarative rules."""

    from_capture: Optional[str] = None
    static: Optional[str] = None
    mask: Optional[str] = None


class ExtractSpec(BaseModel):
    """Collection of extracted fields."""

    fields: dict[str, ExtractFieldSpec] = Field(default_factory=dict)


class NormalizeFieldSpec(BaseModel):
    """Normalization instructions for an extracted field."""

    strip_query: bool = False
    lowercase: bool = False


class NormalizeSpec(BaseModel):
    """Field-level normalization configuration."""

    model_config = {"extra": "allow"}


class EvidenceSpec(BaseModel):
    """Declarative evidence-related options."""

    snippet_from: Literal["raw", "normalized"] = "normalized"
    include_ast_path: bool = False


class CustomDeclarativeRuleSpec(BaseModel):
    """Schema for declarative custom matcher rules."""

    id: str
    title: str
    description: str = ""
    category: Category
    severity: Severity = Severity.INFO
    confidence: Confidence = Confidence.MEDIUM
    value_type: str = ""
    matcher: dict[str, Any]
    extract: ExtractSpec = Field(default_factory=ExtractSpec)
    normalize: NormalizeSpec = Field(default_factory=NormalizeSpec)
    evidence: EvidenceSpec = Field(default_factory=EvidenceSpec)
    tags: list[str] = Field(default_factory=list)
    enabled: bool = True


class CustomAstRuleSpec(BaseModel):
    """Schema for a minimal declarative AST-pattern rule."""

    id: str
    title: str
    description: str = ""
    category: Category
    severity: Severity = Severity.INFO
    confidence: Confidence = Confidence.MEDIUM
    value_type: str = ""
    matcher: MatcherSpec
    extract: ExtractSpec = Field(default_factory=ExtractSpec)
    normalize: NormalizeSpec = Field(default_factory=NormalizeSpec)
    tags: list[str] = Field(default_factory=list)
    enabled: bool = True


class MemberMatchSpec(BaseModel):
    """Supported left-hand member-expression matcher."""

    any_of: list[str] = Field(default_factory=list)
    not_any_of: list[str] = Field(default_factory=list)
    contains_any_of: list[str] = Field(default_factory=list)
    not_contains_any_of: list[str] = Field(default_factory=list)
    regex_any_of: list[str] = Field(default_factory=list)
    not_regex_any_of: list[str] = Field(default_factory=list)


class SemanticAstConditionSpec(BaseModel):
    """Supported AST condition for semantic matching."""

    kind: Literal["AssignmentExpression", "CallExpression", "NewExpression", "VariableDeclarator", "Property"] = "AssignmentExpression"
    left_matches: MemberMatchSpec = Field(default_factory=MemberMatchSpec)
    left_capture_as: Optional[str] = None
    callee_any_of: list[str] = Field(default_factory=list)
    not_callee_any_of: list[str] = Field(default_factory=list)
    callee_contains_any_of: list[str] = Field(default_factory=list)
    not_callee_contains_any_of: list[str] = Field(default_factory=list)
    callee_regex_any_of: list[str] = Field(default_factory=list)
    not_callee_regex_any_of: list[str] = Field(default_factory=list)
    callee_capture_as: Optional[str] = None
    id_name_any_of: list[str] = Field(default_factory=list)
    not_id_name_any_of: list[str] = Field(default_factory=list)
    id_name_contains_any_of: list[str] = Field(default_factory=list)
    not_id_name_contains_any_of: list[str] = Field(default_factory=list)
    id_name_regex_any_of: list[str] = Field(default_factory=list)
    not_id_name_regex_any_of: list[str] = Field(default_factory=list)
    id_name_capture_as: Optional[str] = None
    property_path_any_of: list[str] = Field(default_factory=list)
    not_property_path_any_of: list[str] = Field(default_factory=list)
    property_path_contains_any_of: list[str] = Field(default_factory=list)
    not_property_path_contains_any_of: list[str] = Field(default_factory=list)
    property_path_regex_any_of: list[str] = Field(default_factory=list)
    not_property_path_regex_any_of: list[str] = Field(default_factory=list)
    property_path_capture_as: Optional[str] = None


class RegexConditionSpec(BaseModel):
    """Regex condition applied to a resolved right-hand value."""

    pattern: str
    capture_as: Optional[str] = None
    capture_group: int = 0
    flags: list[str] = Field(default_factory=list)


class ExactValueConditionSpec(BaseModel):
    """Exact-string condition applied to a resolved string value."""

    any_of: list[str] = Field(default_factory=list)
    capture_as: Optional[str] = None


class ContainsValueConditionSpec(BaseModel):
    """Substring condition applied to a resolved string value."""

    any_of: list[str] = Field(default_factory=list)
    capture_as: Optional[str] = None


class RegexArgConditionSpec(BaseModel):
    """Regex condition applied to a statically resolved call argument."""

    index: int = 0
    index_any_of: list[int] = Field(default_factory=list)
    pattern: str
    index_capture_as: Optional[str] = None
    capture_as: Optional[str] = None
    capture_group: int = 0
    flags: list[str] = Field(default_factory=list)


class ExactArgConditionSpec(BaseModel):
    """Exact-string condition applied to a statically resolved call argument."""

    index: int = 0
    index_any_of: list[int] = Field(default_factory=list)
    any_of: list[str] = Field(default_factory=list)
    index_capture_as: Optional[str] = None
    capture_as: Optional[str] = None


class ContainsArgConditionSpec(BaseModel):
    """Substring condition applied to a statically resolved call argument."""

    index: int = 0
    index_any_of: list[int] = Field(default_factory=list)
    any_of: list[str] = Field(default_factory=list)
    index_capture_as: Optional[str] = None
    capture_as: Optional[str] = None


class RegexObjectArgPropertyConditionSpec(BaseModel):
    """Regex condition applied to a string-valued property inside an object argument."""

    index: int = 0
    index_any_of: list[int] = Field(default_factory=list)
    path: Optional[str] = None
    path_any_of: list[str] = Field(default_factory=list)
    not_path_any_of: list[str] = Field(default_factory=list)
    path_contains_any_of: list[str] = Field(default_factory=list)
    not_path_contains_any_of: list[str] = Field(default_factory=list)
    path_regex_any_of: list[str] = Field(default_factory=list)
    not_path_regex_any_of: list[str] = Field(default_factory=list)
    pattern: str
    index_capture_as: Optional[str] = None
    path_capture_as: Optional[str] = None
    capture_as: Optional[str] = None
    capture_group: int = 0
    flags: list[str] = Field(default_factory=list)


class ExactObjectArgPropertyConditionSpec(BaseModel):
    """Exact-string condition applied to a string-valued property inside an object argument."""

    index: int = 0
    index_any_of: list[int] = Field(default_factory=list)
    path: Optional[str] = None
    path_any_of: list[str] = Field(default_factory=list)
    not_path_any_of: list[str] = Field(default_factory=list)
    path_contains_any_of: list[str] = Field(default_factory=list)
    not_path_contains_any_of: list[str] = Field(default_factory=list)
    path_regex_any_of: list[str] = Field(default_factory=list)
    not_path_regex_any_of: list[str] = Field(default_factory=list)
    any_of: list[str] = Field(default_factory=list)
    index_capture_as: Optional[str] = None
    path_capture_as: Optional[str] = None
    capture_as: Optional[str] = None


class ContainsObjectArgPropertyConditionSpec(BaseModel):
    """Substring condition applied to a string-valued property inside an object argument."""

    index: int = 0
    index_any_of: list[int] = Field(default_factory=list)
    path: Optional[str] = None
    path_any_of: list[str] = Field(default_factory=list)
    not_path_any_of: list[str] = Field(default_factory=list)
    path_contains_any_of: list[str] = Field(default_factory=list)
    not_path_contains_any_of: list[str] = Field(default_factory=list)
    path_regex_any_of: list[str] = Field(default_factory=list)
    not_path_regex_any_of: list[str] = Field(default_factory=list)
    any_of: list[str] = Field(default_factory=list)
    index_capture_as: Optional[str] = None
    path_capture_as: Optional[str] = None
    capture_as: Optional[str] = None


class SemanticConditionSpec(BaseModel):
    """Single condition in a semantic AND clause."""

    ast: Optional[SemanticAstConditionSpec] = None
    right_any_of: Optional[ExactValueConditionSpec] = None
    not_right_any_of: Optional[ExactValueConditionSpec] = None
    right_contains_any_of: Optional[ContainsValueConditionSpec] = None
    not_right_contains_any_of: Optional[ContainsValueConditionSpec] = None
    regex_on_right: Optional[RegexConditionSpec] = None
    not_regex_on_right: Optional[RegexConditionSpec] = None
    init_any_of: Optional[ExactValueConditionSpec] = None
    not_init_any_of: Optional[ExactValueConditionSpec] = None
    init_contains_any_of: Optional[ContainsValueConditionSpec] = None
    not_init_contains_any_of: Optional[ContainsValueConditionSpec] = None
    regex_on_init: Optional[RegexConditionSpec] = None
    not_regex_on_init: Optional[RegexConditionSpec] = None
    value_any_of: Optional[ExactValueConditionSpec] = None
    not_value_any_of: Optional[ExactValueConditionSpec] = None
    value_contains_any_of: Optional[ContainsValueConditionSpec] = None
    not_value_contains_any_of: Optional[ContainsValueConditionSpec] = None
    regex_on_value: Optional[RegexConditionSpec] = None
    not_regex_on_value: Optional[RegexConditionSpec] = None
    arg_any_of: Optional[ExactArgConditionSpec] = None
    not_arg_any_of: Optional[ExactArgConditionSpec] = None
    arg_contains_any_of: Optional[ContainsArgConditionSpec] = None
    not_arg_contains_any_of: Optional[ContainsArgConditionSpec] = None
    regex_on_arg: Optional[RegexArgConditionSpec] = None
    not_regex_on_arg: Optional[RegexArgConditionSpec] = None
    object_arg_property_any_of: Optional[ExactObjectArgPropertyConditionSpec] = None
    not_object_arg_property_any_of: Optional[ExactObjectArgPropertyConditionSpec] = None
    object_arg_property_contains_any_of: Optional[ContainsObjectArgPropertyConditionSpec] = None
    not_object_arg_property_contains_any_of: Optional[ContainsObjectArgPropertyConditionSpec] = None
    regex_on_object_arg_property: Optional[RegexObjectArgPropertyConditionSpec] = None
    not_regex_on_object_arg_property: Optional[RegexObjectArgPropertyConditionSpec] = None


class SemanticClauseSpec(BaseModel):
    """Boolean clause for semantic rules."""

    conditions: list[SemanticConditionSpec] = Field(default_factory=list, alias="and")
    any_conditions: list[SemanticConditionSpec] = Field(default_factory=list, alias="or")
    none_conditions: list[SemanticConditionSpec] = Field(default_factory=list, alias="not")

    @model_validator(mode="before")
    @classmethod
    def _coerce_shorthand(cls, data: Any) -> Any:
        """Allow direct clause shorthand without an explicit `and:` wrapper."""
        if isinstance(data, list):
            return {"and": data}
        if isinstance(data, dict) and not any(key in data for key in {"and", "or", "not"}):
            condition_fields = set(SemanticConditionSpec.model_fields)
            if any(key in condition_fields for key in data):
                return {"and": [data]}
        return data


class SemanticLogicSpec(BaseModel):
    """Top-level semantic logic."""

    any: list[SemanticClauseSpec] = Field(default_factory=list)
    all: list[SemanticClauseSpec] = Field(default_factory=list)
    none: list[SemanticClauseSpec] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def _coerce_clause_groups(cls, data: Any) -> Any:
        """Allow top-level clause groups to accept a single clause or condition shorthand."""
        if not isinstance(data, dict):
            return data
        coerced = dict(data)
        for key in ("any", "all", "none"):
            raw_value = coerced.get(key)
            if raw_value is None:
                continue
            if isinstance(raw_value, list):
                continue
            coerced[key] = [raw_value]
        return coerced


class SemanticMatcherSpec(BaseModel):
    """Minimal semantic matcher definition."""

    type: Literal["semantic"] = "semantic"
    logic: SemanticLogicSpec = Field(default_factory=SemanticLogicSpec)


class _CustomRuleBase(BaseRule):
    """Common helpers for custom rule implementations."""

    def _base_result(
        self,
        extracted_value: str,
        value_type: str,
        line: int,
        column: int,
        ast_node_type: str,
        metadata: Optional[dict[str, Any]] = None,
    ) -> RuleResult:
        return RuleResult(
            rule_id=self.id,
            category=self.category,
            severity=self.severity,
            confidence=self.confidence,
            title=self.name,
            description=self.description or f"Matched custom rule {self.id}",
            extracted_value=extracted_value,
            value_type=value_type,
            line=line,
            column=column,
            ast_node_type=ast_node_type,
            tags=["custom_rule", *self.tags],
            metadata=metadata or {},
        )


class _CustomDeclarativeRuleBase(_CustomRuleBase):
    """Shared extract/normalize helpers for declarative custom rules."""

    spec: CustomDeclarativeRuleSpec

    def _extract_fields(self, captures: dict[str, str]) -> dict[str, str]:
        """Materialize configured extracted fields from captures/static values."""
        if not self.spec.extract.fields:
            return dict(captures)

        fields: dict[str, str] = {}
        for field_name, field_spec in self.spec.extract.fields.items():
            if field_spec.from_capture:
                value = captures.get(field_spec.from_capture, "")
                if value:
                    fields[field_name] = value
            elif field_spec.static:
                fields[field_name] = field_spec.static
        return fields

    def _normalize_fields(self, fields: dict[str, str]) -> dict[str, str]:
        """Apply field-level normalization from the custom rule spec."""
        normalized = dict(fields)
        for field_name, field_value in list(normalized.items()):
            raw_spec = getattr(self.spec.normalize, field_name, None)
            if isinstance(raw_spec, dict):
                spec = NormalizeFieldSpec.model_validate(raw_spec)
            elif isinstance(raw_spec, NormalizeFieldSpec):
                spec = raw_spec
            else:
                continue
            normalized[field_name] = _normalize_value(field_value, spec)
        return normalized

    def _build_metadata(
        self,
        raw_fields: dict[str, str],
        ast_path: Optional[str] = None,
        **extra: Any,
    ) -> dict[str, Any]:
        """Build rule metadata with masked extracted fields when configured."""
        visible_fields, masked_fields = self._mask_fields(raw_fields)
        metadata: dict[str, Any] = {}
        if visible_fields:
            metadata["extracted_fields"] = visible_fields
        if masked_fields:
            metadata["masked_fields"] = masked_fields
        if ast_path and self.spec.evidence.include_ast_path:
            metadata["ast_path"] = ast_path
        metadata.update(extra)
        return metadata

    def _mask_fields(self, fields: dict[str, str]) -> tuple[dict[str, str], dict[str, str]]:
        """Apply field-level masking rules while preserving raw extraction for analysis."""
        visible = dict(fields)
        masked_only: dict[str, str] = {}

        for field_name, field_value in fields.items():
            field_spec = self.spec.extract.fields.get(field_name)
            if not field_spec or not field_spec.mask:
                continue
            masked_value = _mask_value(field_value, field_spec.mask)
            visible[field_name] = masked_value
            masked_only[field_name] = masked_value

        return visible, masked_only

    def _resolve_primary_value(
        self,
        extracted_fields: dict[str, str],
        captures: dict[str, str],
        fallback_value: str = "",
    ) -> tuple[str, str]:
        """Resolve the finding's primary extracted value and value type."""
        if self.spec.extract.fields and extracted_fields:
            for field_name, field_spec in self.spec.extract.fields.items():
                if field_spec.from_capture and field_name in extracted_fields:
                    return extracted_fields[field_name], self.value_type or field_name
        if extracted_fields:
            field_name, value = next(iter(extracted_fields.items()))
            return value, self.value_type or field_name
        if captures:
            capture_name, value = next(iter(captures.items()))
            return value, self.value_type or capture_name
        if fallback_value:
            return fallback_value, self.value_type or "custom_match"
        return "", self.value_type or "custom_match"


class CustomRegexRule(_CustomRuleBase):
    """Regex-based rule loaded from a user-provided file."""

    def __init__(self, spec: CustomRuleSpec):
        self.spec = spec
        self.id = spec.id
        self.name = spec.title
        self.description = spec.description
        self.category = spec.category
        self.severity = spec.severity
        self.confidence = spec.confidence
        self.value_type = spec.value_type
        self.tags = spec.tags
        self.enabled = spec.enabled
        self._pattern = re.compile(spec.pattern, _compile_flags(spec.flags))

    def match(
        self,
        ir: IntermediateRepresentation,
        context: AnalysisContext,
    ) -> Iterator[RuleResult]:
        """Match custom regex rules against the source or string literals."""
        seen: set[tuple[str, int, int]] = set()

        if self.spec.scope == "string_literal":
            for literal in ir.string_literals:
                for match in self._pattern.finditer(literal.value):
                    extracted = _extract_match_value(match, self.spec.extract_group)
                    key = (extracted, literal.line, literal.column)
                    if key in seen:
                        continue
                    seen.add(key)
                    yield self._base_result(
                        extracted_value=extracted,
                        value_type=self.value_type,
                        line=literal.line,
                        column=literal.column,
                        ast_node_type="Literal",
                    )
            return

        source = context.source_content
        for match in self._pattern.finditer(source):
            extracted = _extract_match_value(match, self.spec.extract_group)
            line, column = _offset_to_line_column(source, match.start())
            key = (extracted, line, column)
            if key in seen:
                continue
            seen.add(key)
            yield self._base_result(
                extracted_value=extracted,
                value_type=self.value_type,
                line=line,
                column=column,
                ast_node_type="Expression",
            )


class CustomRegexMatcherRule(_CustomDeclarativeRuleBase):
    """Declarative regex matcher loaded from JSON/YAML rules."""

    def __init__(self, spec: CustomDeclarativeRuleSpec):
        self.spec = spec
        self.id = spec.id
        self.name = spec.title
        self.description = spec.description
        self.category = spec.category
        self.severity = spec.severity
        self.confidence = spec.confidence
        self.value_type = spec.value_type
        self.tags = spec.tags
        self.enabled = spec.enabled
        self.matcher = RegexMatcherSpec.model_validate(spec.matcher)
        self._pattern = re.compile(self.matcher.pattern, _compile_flags(self.matcher.flags))

    def match(
        self,
        ir: IntermediateRepresentation,
        context: AnalysisContext,
    ) -> Iterator[RuleResult]:
        """Match declarative regex rules against source or string literals."""
        seen: set[tuple[str, int, int]] = set()

        if self.matcher.scope == "string_literal":
            for literal in ir.string_literals:
                for match in self._pattern.finditer(literal.value):
                    result = self._resolve_match(match)
                    if not result:
                        continue
                    extracted_value, value_type, metadata = result
                    key = (extracted_value, literal.line, literal.column)
                    if key in seen:
                        continue
                    seen.add(key)
                    yield self._base_result(
                        extracted_value=extracted_value,
                        value_type=value_type,
                        line=literal.line,
                        column=literal.column,
                        ast_node_type="Literal",
                        metadata=metadata,
                    )
            return

        source = context.source_content
        for match in self._pattern.finditer(source):
            line, column = _offset_to_line_column(source, match.start())
            result = self._resolve_match(match)
            if not result:
                continue
            extracted_value, value_type, metadata = result
            key = (extracted_value, line, column)
            if key in seen:
                continue
            seen.add(key)
            yield self._base_result(
                extracted_value=extracted_value,
                value_type=value_type,
                line=line,
                column=column,
                ast_node_type="Expression",
                metadata=metadata,
            )

    def _resolve_match(
        self,
        match: re.Match[str],
    ) -> Optional[tuple[str, str, dict[str, Any]]]:
        """Build an extracted value and metadata from a regex match."""
        captures: dict[str, str] = {}
        extracted = _extract_match_value(match, self.matcher.capture_group)
        if self.matcher.capture_as:
            captures[self.matcher.capture_as] = extracted
        extracted_fields = self._normalize_fields(self._extract_fields(captures))
        extracted_value, value_type = self._resolve_primary_value(
            extracted_fields,
            captures,
            fallback_value=extracted,
        )
        if not extracted_value:
            return None
        metadata = self._build_metadata(extracted_fields)
        return extracted_value, value_type, metadata


class CustomAstPatternRule(_CustomDeclarativeRuleBase):
    """Minimal declarative AST-pattern rule for call/variable matches."""

    def __init__(self, spec: CustomDeclarativeRuleSpec):
        self.spec = spec
        self.id = spec.id
        self.name = spec.title
        self.description = spec.description
        self.category = spec.category
        self.severity = spec.severity
        self.confidence = spec.confidence
        self.value_type = spec.value_type
        self.tags = spec.tags
        self.enabled = spec.enabled
        self.pattern = AstPatternSpec.model_validate(spec.matcher.get("pattern", {}))

    def match(
        self,
        ir: IntermediateRepresentation,
        context: AnalysisContext,
    ) -> Iterator[RuleResult]:
        """Match the supported declarative AST-pattern subset."""
        del context
        seen: set[tuple[str, int, int]] = set()
        constants = _build_constant_table(ir.raw_ast or {})

        if self.pattern.kind in {"CallExpression", "NewExpression"}:
            root_path = (ir.raw_ast or {}).get("type", "root")
            for node, ast_path in _iter_nodes_with_path(ir.raw_ast or {}, root_path):
                if node.get("type") != self.pattern.kind:
                    continue
                call_name = _get_call_expression_name(node.get("callee", {}))
                if not self._call_name_matches(
                    call_name,
                    self.pattern.callee_any_of,
                    self.pattern.callee_contains_any_of,
                    self.pattern.callee_regex_any_of,
                    self.pattern.not_callee_any_of,
                    self.pattern.not_callee_contains_any_of,
                    self.pattern.not_callee_regex_any_of,
                ):
                    continue

                captures = self._match_call_args(node.get("arguments", []), self.pattern.args, constants)
                if captures is None:
                    continue
                if self.pattern.callee_capture_as:
                    captures[self.pattern.callee_capture_as] = call_name

                extracted_fields = self._normalize_fields(self._extract_fields(captures))
                extracted_value, value_type = self._resolve_primary_value(
                    extracted_fields,
                    captures,
                )
                if not extracted_value:
                    continue

                line, column = _get_node_position(node)
                key = (extracted_value, line, column)
                if key in seen:
                    continue
                seen.add(key)

                yield self._base_result(
                    extracted_value=extracted_value,
                    value_type=value_type,
                    line=line,
                    column=column,
                    ast_node_type=self.pattern.kind,
                    metadata=self._build_metadata(extracted_fields, ast_path=ast_path),
                )
            return

        if self.pattern.kind == "VariableDeclarator":
            yield from self._match_variable_declarators(ir, constants, seen)
            return

        if self.pattern.kind == "AssignmentExpression":
            yield from self._match_assignments(ir, constants, seen)
            return

        if self.pattern.kind == "Property":
            yield from self._match_properties(ir, constants, seen)

    def _call_name_matches(
        self,
        call_name: str,
        allowed: list[str],
        contains_allowed: list[str],
        regex_allowed: list[str],
        denied: list[str],
        contains_denied: list[str],
        regex_denied: list[str],
    ) -> bool:
        """Check whether the current call matches any configured callee name."""
        if not _call_name_matches(call_name, allowed, regex_allowed, contains_allowed):
            return False
        if denied and _call_name_matches(call_name, denied, [], []):
            return False
        if contains_denied and _call_name_contains(call_name, contains_denied):
            return False
        if regex_denied and any(re.search(pattern, call_name) for pattern in regex_denied):
            return False
        return True

    def _match_call_args(
        self,
        arguments: list[Any],
        patterns: list[AstPatternArgSpec],
        constants: dict[str, str],
    ) -> Optional[dict[str, str]]:
        """Match positional call arguments and return captured values."""
        captures: dict[str, str] = {}
        used_indices: set[int] = set()

        for fallback_index, arg_pattern in enumerate(patterns):
            matched = False
            for index in self._resolve_ast_pattern_arg_indices(
                arg_pattern,
                fallback_index,
                len(arguments),
            ):
                if index in used_indices:
                    continue
                arg = arguments[index]
                if (
                    arg_pattern.type == "Any"
                    and not arg_pattern.any_of
                    and not arg_pattern.not_any_of
                    and not arg_pattern.contains_any_of
                    and not arg_pattern.not_contains_any_of
                    and not arg_pattern.regex
                    and not arg_pattern.not_regex
                    and not arg_pattern.capture_as
                ):
                    if arg_pattern.index_capture_as:
                        captures[arg_pattern.index_capture_as] = str(index)
                    used_indices.add(index)
                    matched = True
                    break
                if (
                    arg_pattern.type == "Any"
                    and not arg_pattern.regex
                    and not arg_pattern.capture_as
                    and not arg_pattern.index_capture_as
                ):
                    used_indices.add(index)
                    matched = True
                    break
                value = _match_ast_value(arg, arg_pattern, constants)
                if value is None:
                    continue
                if arg_pattern.index_capture_as:
                    captures[arg_pattern.index_capture_as] = str(index)
                if arg_pattern.capture_as:
                    captures[arg_pattern.capture_as] = value
                used_indices.add(index)
                matched = True
                break
            if not matched:
                return None

        return captures

    def _resolve_ast_pattern_arg_indices(
        self,
        pattern: AstPatternArgSpec,
        fallback_index: int,
        arg_count: int,
    ) -> list[int]:
        """Resolve practical candidate indices for an AST-pattern arg matcher."""
        if pattern.index_any_of:
            raw_indices = pattern.index_any_of
        elif pattern.index is not None:
            raw_indices = [pattern.index]
        else:
            raw_indices = [fallback_index]

        resolved: list[int] = []
        seen: set[int] = set()
        for raw_index in raw_indices:
            if not isinstance(raw_index, int):
                continue
            if raw_index < 0 or raw_index >= arg_count or raw_index in seen:
                continue
            seen.add(raw_index)
            resolved.append(raw_index)
        return resolved

    def _match_variable_declarators(
        self,
        ir: IntermediateRepresentation,
        constants: dict[str, str],
        seen: set[tuple[str, int, int]],
    ) -> Iterator[RuleResult]:
        """Match a minimal VariableDeclarator subset from the raw AST."""
        id_regex = re.compile(self.pattern.id_name_regex or ".*", re.IGNORECASE)
        not_id_regex = (
            re.compile(self.pattern.not_id_name_regex, re.IGNORECASE)
            if self.pattern.not_id_name_regex
            else None
        )
        init_pattern = self.pattern.init

        root_path = (ir.raw_ast or {}).get("type", "root")
        for node, ast_path in _iter_nodes_with_path(ir.raw_ast or {}, root_path):
            if node.get("type") != "VariableDeclarator":
                continue

            identifier = node.get("id", {})
            if identifier.get("type") != "Identifier":
                continue

            identifier_name = identifier.get("name", "")
            if self.pattern.id_name_any_of and identifier_name not in self.pattern.id_name_any_of:
                continue
            if self.pattern.not_id_name_any_of and identifier_name in self.pattern.not_id_name_any_of:
                continue
            if self.pattern.id_name_contains_any_of and not _contains_any(
                identifier_name,
                self.pattern.id_name_contains_any_of,
            ):
                continue
            if self.pattern.not_id_name_contains_any_of and _contains_any(
                identifier_name,
                self.pattern.not_id_name_contains_any_of,
            ):
                continue
            if not id_regex.search(identifier_name):
                continue
            if not_id_regex and not_id_regex.search(identifier_name):
                continue

            captures: dict[str, str] = {}
            if self.pattern.id_name_capture_as:
                captures[self.pattern.id_name_capture_as] = identifier_name
            if init_pattern:
                value = _match_ast_value(node.get("init"), init_pattern, constants)
                if value is None:
                    continue
                if init_pattern.capture_as:
                    captures[init_pattern.capture_as] = value

            extracted_fields = self._normalize_fields(self._extract_fields(captures))
            extracted_value, value_type = self._resolve_primary_value(
                extracted_fields,
                captures,
            )
            if not extracted_value:
                continue

            line, column = _get_node_position(node)
            key = (extracted_value, line, column)
            if key in seen:
                continue
            seen.add(key)

            metadata = self._build_metadata(
                extracted_fields,
                ast_path=ast_path,
                identifier_name=identifier_name,
            )
            yield self._base_result(
                extracted_value=extracted_value,
                value_type=value_type,
                line=line,
                column=column,
                ast_node_type="VariableDeclarator",
                metadata=metadata,
            )

    def _match_assignments(
        self,
        ir: IntermediateRepresentation,
        constants: dict[str, str],
        seen: set[tuple[str, int, int]],
    ) -> Iterator[RuleResult]:
        """Match a minimal AssignmentExpression subset from the raw AST."""
        right_pattern = self.pattern.right
        root_path = (ir.raw_ast or {}).get("type", "root")

        for node, ast_path in _iter_nodes_with_path(ir.raw_ast or {}, root_path):
            if node.get("type") != "AssignmentExpression":
                continue

            left_path = _resolve_member_path_expr(node.get("left"), constants)
            if not left_path:
                continue
            if self.pattern.left_any_of and left_path not in self.pattern.left_any_of:
                continue
            if self.pattern.not_left_any_of and left_path in self.pattern.not_left_any_of:
                continue
            if self.pattern.left_contains_any_of and not _contains_any(
                left_path,
                self.pattern.left_contains_any_of,
            ):
                continue
            if self.pattern.not_left_contains_any_of and _contains_any(
                left_path,
                self.pattern.not_left_contains_any_of,
            ):
                continue
            if self.pattern.left_regex_any_of and not any(
                re.search(pattern, left_path)
                for pattern in self.pattern.left_regex_any_of
            ):
                continue
            if self.pattern.not_left_regex_any_of and any(
                re.search(pattern, left_path)
                for pattern in self.pattern.not_left_regex_any_of
            ):
                continue

            captures: dict[str, str] = {}
            if self.pattern.left_capture_as:
                captures[self.pattern.left_capture_as] = left_path
            if right_pattern:
                value = _match_ast_value(node.get("right"), right_pattern, constants)
                if value is None:
                    continue
                if right_pattern.capture_as:
                    captures[right_pattern.capture_as] = value

            extracted_fields = self._normalize_fields(self._extract_fields(captures))
            extracted_value, value_type = self._resolve_primary_value(
                extracted_fields,
                captures,
            )
            if not extracted_value:
                continue

            line, column = _get_node_position(node)
            key = (extracted_value, line, column)
            if key in seen:
                continue
            seen.add(key)

            metadata = self._build_metadata(
                extracted_fields,
                ast_path=ast_path,
                left_path=left_path,
            )
            yield self._base_result(
                extracted_value=extracted_value,
                value_type=value_type,
                line=line,
                column=column,
                ast_node_type="AssignmentExpression",
                metadata=metadata,
            )

    def _match_properties(
        self,
        ir: IntermediateRepresentation,
        constants: dict[str, str],
        seen: set[tuple[str, int, int]],
    ) -> Iterator[RuleResult]:
        """Match a minimal object-property subset from the raw AST."""
        value_pattern = self.pattern.value
        root = ir.raw_ast or {}
        root_path = root.get("type", "root")

        for object_node, object_ast_path in _iter_nodes_with_path(root, root_path):
            if object_node.get("type") != "ObjectExpression":
                continue
            for node, property_path, ast_path in _iter_object_properties_with_path(
                object_node,
                object_ast_path,
                constants=constants,
            ):
                if self.pattern.property_path_any_of and property_path not in self.pattern.property_path_any_of:
                    continue
                if self.pattern.not_property_path_any_of and property_path in self.pattern.not_property_path_any_of:
                    continue
                if self.pattern.property_path_contains_any_of and not _contains_any(
                    property_path,
                    self.pattern.property_path_contains_any_of,
                ):
                    continue
                if self.pattern.not_property_path_contains_any_of and _contains_any(
                    property_path,
                    self.pattern.not_property_path_contains_any_of,
                ):
                    continue
                if self.pattern.property_path_regex_any_of and not any(
                    re.search(pattern, property_path)
                    for pattern in self.pattern.property_path_regex_any_of
                ):
                    continue
                if self.pattern.not_property_path_regex_any_of and any(
                    re.search(pattern, property_path)
                    for pattern in self.pattern.not_property_path_regex_any_of
                ):
                    continue

                captures: dict[str, str] = {}
                if self.pattern.property_path_capture_as:
                    captures[self.pattern.property_path_capture_as] = property_path
                if value_pattern:
                    value = _match_ast_value(node.get("value"), value_pattern, constants)
                    if value is None:
                        continue
                    if value_pattern.capture_as:
                        captures[value_pattern.capture_as] = value

                extracted_fields = self._normalize_fields(self._extract_fields(captures))
                extracted_value, value_type = self._resolve_primary_value(
                    extracted_fields,
                    captures,
                )
                if not extracted_value:
                    continue

                line, column = _get_node_position(node)
                key = (extracted_value, line, column)
                if key in seen:
                    continue
                seen.add(key)

                metadata = self._build_metadata(
                    extracted_fields,
                    ast_path=ast_path,
                    property_path=property_path,
                )
                yield self._base_result(
                    extracted_value=extracted_value,
                    value_type=value_type,
                    line=line,
                    column=column,
                    ast_node_type="Property",
                    metadata=metadata,
                )


class CustomSemanticRule(_CustomDeclarativeRuleBase):
    """Declarative semantic matcher for assignment and call-expression patterns."""

    def __init__(self, spec: CustomDeclarativeRuleSpec):
        self.spec = spec
        self.id = spec.id
        self.name = spec.title
        self.description = spec.description
        self.category = spec.category
        self.severity = spec.severity
        self.confidence = spec.confidence
        self.value_type = spec.value_type
        self.tags = spec.tags
        self.enabled = spec.enabled
        self.matcher = SemanticMatcherSpec.model_validate(spec.matcher)

    def match(
        self,
        ir: IntermediateRepresentation,
        context: AnalysisContext,
    ) -> Iterator[RuleResult]:
        """Match the supported semantic subset against raw AST nodes."""
        del context
        if not ir.raw_ast:
            return

        seen: set[tuple[str, int, int]] = set()
        function_returns = _build_function_return_table(ir.raw_ast)
        constants = _build_constant_table(ir.raw_ast, function_returns)
        candidate_node_types = self._candidate_node_types()
        property_paths = (
            _build_property_path_map(ir.raw_ast, constants)
            if "Property" in candidate_node_types
            else {}
        )

        root_path = ir.raw_ast.get("type", "root")
        for node, ast_path in _iter_nodes_with_path(ir.raw_ast, root_path):
            if node.get("type") not in candidate_node_types:
                continue
            property_path = property_paths.get(id(node))

            captures = self._match_logic(
                node,
                constants,
                function_returns,
                property_path,
            )
            if captures is None:
                continue

            extracted_fields = self._normalize_fields(self._extract_fields(captures))
            extracted_value, value_type = self._resolve_primary_value(
                extracted_fields,
                captures,
            )
            if not extracted_value:
                continue

            line, column = _get_node_position(node)
            key = (extracted_value, line, column)
            if key in seen:
                continue
            seen.add(key)

            metadata = self._build_metadata(
                extracted_fields,
                ast_path=ast_path,
                property_path=property_path,
            )
            metadata.update(self._build_semantic_metadata(node, constants, property_path))

            yield self._base_result(
                extracted_value=extracted_value,
                value_type=value_type,
                line=line,
                column=column,
                ast_node_type=node.get("type", "Expression"),
                metadata=metadata,
            )

    def _candidate_node_types(self) -> set[str]:
        """Infer AST node kinds that may satisfy the configured semantic rule."""
        candidate_types: set[str] = set()
        for clause in self._iter_clauses():
            for condition in clause.conditions:
                if condition.ast:
                    candidate_types.add(condition.ast.kind)
                elif condition.right_any_of:
                    candidate_types.add("AssignmentExpression")
                elif condition.not_right_any_of:
                    candidate_types.add("AssignmentExpression")
                elif condition.right_contains_any_of:
                    candidate_types.add("AssignmentExpression")
                elif condition.not_right_contains_any_of:
                    candidate_types.add("AssignmentExpression")
                elif condition.regex_on_right:
                    candidate_types.add("AssignmentExpression")
                elif condition.not_regex_on_right:
                    candidate_types.add("AssignmentExpression")
                elif condition.init_any_of:
                    candidate_types.add("VariableDeclarator")
                elif condition.not_init_any_of:
                    candidate_types.add("VariableDeclarator")
                elif condition.init_contains_any_of:
                    candidate_types.add("VariableDeclarator")
                elif condition.not_init_contains_any_of:
                    candidate_types.add("VariableDeclarator")
                elif condition.regex_on_init:
                    candidate_types.add("VariableDeclarator")
                elif condition.not_regex_on_init:
                    candidate_types.add("VariableDeclarator")
                elif condition.value_any_of:
                    candidate_types.add("Property")
                elif condition.not_value_any_of:
                    candidate_types.add("Property")
                elif condition.value_contains_any_of:
                    candidate_types.add("Property")
                elif condition.not_value_contains_any_of:
                    candidate_types.add("Property")
                elif condition.regex_on_value:
                    candidate_types.add("Property")
                elif condition.not_regex_on_value:
                    candidate_types.add("Property")
                elif condition.arg_any_of:
                    candidate_types.add("CallExpression")
                    candidate_types.add("NewExpression")
                elif condition.not_arg_any_of:
                    candidate_types.add("CallExpression")
                    candidate_types.add("NewExpression")
                elif condition.arg_contains_any_of:
                    candidate_types.add("CallExpression")
                    candidate_types.add("NewExpression")
                elif condition.not_arg_contains_any_of:
                    candidate_types.add("CallExpression")
                    candidate_types.add("NewExpression")
                elif condition.regex_on_arg:
                    candidate_types.add("CallExpression")
                    candidate_types.add("NewExpression")
                elif condition.not_regex_on_arg:
                    candidate_types.add("CallExpression")
                    candidate_types.add("NewExpression")
                elif condition.object_arg_property_any_of:
                    candidate_types.add("CallExpression")
                    candidate_types.add("NewExpression")
                elif condition.not_object_arg_property_any_of:
                    candidate_types.add("CallExpression")
                    candidate_types.add("NewExpression")
                elif condition.object_arg_property_contains_any_of:
                    candidate_types.add("CallExpression")
                    candidate_types.add("NewExpression")
                elif condition.not_object_arg_property_contains_any_of:
                    candidate_types.add("CallExpression")
                    candidate_types.add("NewExpression")
                elif condition.regex_on_object_arg_property:
                    candidate_types.add("CallExpression")
                    candidate_types.add("NewExpression")
                elif condition.not_regex_on_object_arg_property:
                    candidate_types.add("CallExpression")
                    candidate_types.add("NewExpression")
        return candidate_types or {"AssignmentExpression", "CallExpression", "NewExpression"}

    def _iter_clauses(self) -> Iterator[SemanticClauseSpec]:
        """Iterate every semantic clause referenced by the matcher."""
        yield from self.matcher.logic.any
        yield from self.matcher.logic.all
        yield from self.matcher.logic.none

    def _match_logic(
        self,
        node: dict[str, Any],
        constants: dict[str, str],
        function_returns: dict[str, dict[str, Any]],
        property_path: Optional[str] = None,
    ) -> Optional[dict[str, str]]:
        """Match the top-level semantic boolean structure against a single AST node."""
        if not (self.matcher.logic.any or self.matcher.logic.all or self.matcher.logic.none):
            return None

        candidate_clauses = list(self.matcher.logic.any) or [SemanticClauseSpec()]
        for candidate_clause in candidate_clauses:
            captures = self._match_clause(
                node,
                candidate_clause,
                constants,
                function_returns,
                property_path,
            )
            if captures is None:
                continue

            merged_captures = dict(captures)
            failed_all = False
            for clause in self.matcher.logic.all:
                clause_captures = self._match_clause(
                    node,
                    clause,
                    constants,
                    function_returns,
                    property_path,
                )
                if clause_captures is None:
                    failed_all = True
                    break
                merged_captures.update(clause_captures)
            if failed_all:
                continue

            blocked = False
            for clause in self.matcher.logic.none:
                if self._match_clause(
                    node,
                    clause,
                    constants,
                    function_returns,
                    property_path,
                ) is not None:
                    blocked = True
                    break
            if blocked:
                continue

            return merged_captures

        return None

    def _match_clause(
        self,
        node: dict[str, Any],
        clause: SemanticClauseSpec,
        constants: dict[str, str],
        function_returns: dict[str, dict[str, Any]],
        property_path: Optional[str] = None,
    ) -> Optional[dict[str, str]]:
        """Match a semantic boolean clause against a single AST node."""
        captures: dict[str, str] = {}

        for condition in clause.conditions:
            if condition.ast and not self._match_ast_condition(node, condition.ast, constants):
                return None
            if condition.ast and condition.ast.kind == "Property":
                if not property_path:
                    return None
                if condition.ast.property_path_any_of and property_path not in condition.ast.property_path_any_of:
                    return None
                if condition.ast.not_property_path_any_of and property_path in condition.ast.not_property_path_any_of:
                    return None
                if condition.ast.property_path_contains_any_of and not _contains_any(
                    property_path,
                    condition.ast.property_path_contains_any_of,
                ):
                    return None
                if condition.ast.not_property_path_contains_any_of and _contains_any(
                    property_path,
                    condition.ast.not_property_path_contains_any_of,
                ):
                    return None
                if condition.ast.property_path_regex_any_of and not any(
                    re.search(pattern, property_path)
                    for pattern in condition.ast.property_path_regex_any_of
                ):
                    return None
                if condition.ast.not_property_path_regex_any_of and any(
                    re.search(pattern, property_path)
                    for pattern in condition.ast.not_property_path_regex_any_of
                ):
                    return None
            if condition.ast:
                captures.update(
                    self._capture_ast_condition(
                        node,
                        condition.ast,
                        constants,
                        property_path,
                    )
                )
            if condition.right_any_of:
                if node.get("type") != "AssignmentExpression":
                    return None
                right_value = _resolve_semantic_value_expr(node.get("right"), constants, function_returns)
                if right_value is None or right_value not in condition.right_any_of.any_of:
                    return None
                if condition.right_any_of.capture_as:
                    captures[condition.right_any_of.capture_as] = right_value
            if condition.not_right_any_of:
                if node.get("type") != "AssignmentExpression":
                    return None
                right_value = _resolve_semantic_value_expr(node.get("right"), constants, function_returns)
                if right_value is None:
                    return None
                if right_value in condition.not_right_any_of.any_of:
                    return None
            if condition.right_contains_any_of:
                if node.get("type") != "AssignmentExpression":
                    return None
                right_value = _resolve_semantic_value_expr(node.get("right"), constants, function_returns)
                if right_value is None or not _contains_any(
                    right_value,
                    condition.right_contains_any_of.any_of,
                ):
                    return None
                if condition.right_contains_any_of.capture_as:
                    captures[condition.right_contains_any_of.capture_as] = right_value
            if condition.not_right_contains_any_of:
                if node.get("type") != "AssignmentExpression":
                    return None
                right_value = _resolve_semantic_value_expr(node.get("right"), constants, function_returns)
                if right_value is None:
                    return None
                if _contains_any(right_value, condition.not_right_contains_any_of.any_of):
                    return None
            if condition.regex_on_right:
                if node.get("type") != "AssignmentExpression":
                    return None
                right_value = _resolve_semantic_value_expr(node.get("right"), constants, function_returns)
                if right_value is None:
                    return None
                pattern = re.compile(
                    condition.regex_on_right.pattern,
                    _compile_flags(condition.regex_on_right.flags),
                )
                match = pattern.search(right_value)
                if not match:
                    return None
                if condition.regex_on_right.capture_as:
                    captures[condition.regex_on_right.capture_as] = _extract_match_value(
                        match,
                        condition.regex_on_right.capture_group,
                    )
            if condition.not_regex_on_right:
                if node.get("type") != "AssignmentExpression":
                    return None
                right_value = _resolve_semantic_value_expr(node.get("right"), constants, function_returns)
                if right_value is None:
                    return None
                pattern = re.compile(
                    condition.not_regex_on_right.pattern,
                    _compile_flags(condition.not_regex_on_right.flags),
                )
                if pattern.search(right_value):
                    return None
            if condition.init_any_of:
                if node.get("type") != "VariableDeclarator":
                    return None
                init_value = _resolve_semantic_value_expr(node.get("init"), constants, function_returns)
                if init_value is None or init_value not in condition.init_any_of.any_of:
                    return None
                if condition.init_any_of.capture_as:
                    captures[condition.init_any_of.capture_as] = init_value
            if condition.not_init_any_of:
                if node.get("type") != "VariableDeclarator":
                    return None
                init_value = _resolve_semantic_value_expr(node.get("init"), constants, function_returns)
                if init_value is None:
                    return None
                if init_value in condition.not_init_any_of.any_of:
                    return None
            if condition.init_contains_any_of:
                if node.get("type") != "VariableDeclarator":
                    return None
                init_value = _resolve_semantic_value_expr(node.get("init"), constants, function_returns)
                if init_value is None or not _contains_any(
                    init_value,
                    condition.init_contains_any_of.any_of,
                ):
                    return None
                if condition.init_contains_any_of.capture_as:
                    captures[condition.init_contains_any_of.capture_as] = init_value
            if condition.not_init_contains_any_of:
                if node.get("type") != "VariableDeclarator":
                    return None
                init_value = _resolve_semantic_value_expr(node.get("init"), constants, function_returns)
                if init_value is None:
                    return None
                if _contains_any(init_value, condition.not_init_contains_any_of.any_of):
                    return None
            if condition.regex_on_init:
                if node.get("type") != "VariableDeclarator":
                    return None
                init_value = _resolve_semantic_value_expr(node.get("init"), constants, function_returns)
                if init_value is None:
                    return None
                pattern = re.compile(
                    condition.regex_on_init.pattern,
                    _compile_flags(condition.regex_on_init.flags),
                )
                match = pattern.search(init_value)
                if not match:
                    return None
                if condition.regex_on_init.capture_as:
                    captures[condition.regex_on_init.capture_as] = _extract_match_value(
                        match,
                        condition.regex_on_init.capture_group,
                    )
            if condition.not_regex_on_init:
                if node.get("type") != "VariableDeclarator":
                    return None
                init_value = _resolve_semantic_value_expr(node.get("init"), constants, function_returns)
                if init_value is None:
                    return None
                pattern = re.compile(
                    condition.not_regex_on_init.pattern,
                    _compile_flags(condition.not_regex_on_init.flags),
                )
                if pattern.search(init_value):
                    return None
            if condition.value_any_of:
                if node.get("type") != "Property":
                    return None
                value = _resolve_semantic_value_expr(node.get("value"), constants, function_returns)
                if value is None or value not in condition.value_any_of.any_of:
                    return None
                if condition.value_any_of.capture_as:
                    captures[condition.value_any_of.capture_as] = value
            if condition.not_value_any_of:
                if node.get("type") != "Property":
                    return None
                value = _resolve_semantic_value_expr(node.get("value"), constants, function_returns)
                if value is None:
                    return None
                if value in condition.not_value_any_of.any_of:
                    return None
            if condition.value_contains_any_of:
                if node.get("type") != "Property":
                    return None
                value = _resolve_semantic_value_expr(node.get("value"), constants, function_returns)
                if value is None or not _contains_any(
                    value,
                    condition.value_contains_any_of.any_of,
                ):
                    return None
                if condition.value_contains_any_of.capture_as:
                    captures[condition.value_contains_any_of.capture_as] = value
            if condition.not_value_contains_any_of:
                if node.get("type") != "Property":
                    return None
                value = _resolve_semantic_value_expr(node.get("value"), constants, function_returns)
                if value is None:
                    return None
                if _contains_any(value, condition.not_value_contains_any_of.any_of):
                    return None
            if condition.regex_on_value:
                if node.get("type") != "Property":
                    return None
                value = _resolve_semantic_value_expr(node.get("value"), constants, function_returns)
                if value is None:
                    return None
                pattern = re.compile(
                    condition.regex_on_value.pattern,
                    _compile_flags(condition.regex_on_value.flags),
                )
                match = pattern.search(value)
                if not match:
                    return None
                if condition.regex_on_value.capture_as:
                    captures[condition.regex_on_value.capture_as] = _extract_match_value(
                        match,
                        condition.regex_on_value.capture_group,
                    )
            if condition.not_regex_on_value:
                if node.get("type") != "Property":
                    return None
                value = _resolve_semantic_value_expr(node.get("value"), constants, function_returns)
                if value is None:
                    return None
                pattern = re.compile(
                    condition.not_regex_on_value.pattern,
                    _compile_flags(condition.not_regex_on_value.flags),
                )
                if pattern.search(value):
                    return None
            if condition.arg_any_of:
                if not _is_invocation_expression(node):
                    return None
                arguments = _get_invocation_arguments(node)
                indices = _resolve_match_indices(condition.arg_any_of, len(arguments))
                if not indices:
                    return None
                matched_index = -1
                arg_value: Optional[str] = None
                for index in indices:
                    candidate_value = _resolve_invocation_argument_value(
                        arguments[index],
                        constants,
                        function_returns,
                    )
                    if candidate_value is None or candidate_value not in condition.arg_any_of.any_of:
                        continue
                    matched_index = index
                    arg_value = candidate_value
                    break
                if matched_index < 0 or arg_value is None:
                    return None
                if condition.arg_any_of.index_capture_as:
                    captures[condition.arg_any_of.index_capture_as] = str(matched_index)
                if condition.arg_any_of.capture_as:
                    captures[condition.arg_any_of.capture_as] = arg_value
            if condition.not_arg_any_of:
                if not _is_invocation_expression(node):
                    return None
                arguments = _get_invocation_arguments(node)
                indices = _resolve_match_indices(condition.not_arg_any_of, len(arguments))
                if not indices:
                    return None
                resolved_any = False
                for index in indices:
                    arg_value = _resolve_invocation_argument_value(
                        arguments[index],
                        constants,
                        function_returns,
                    )
                    if arg_value is None:
                        continue
                    resolved_any = True
                    if arg_value in condition.not_arg_any_of.any_of:
                        return None
                if not resolved_any:
                    return None
            if condition.arg_contains_any_of:
                if not _is_invocation_expression(node):
                    return None
                arguments = _get_invocation_arguments(node)
                indices = _resolve_match_indices(condition.arg_contains_any_of, len(arguments))
                if not indices:
                    return None
                matched_index = -1
                arg_value: Optional[str] = None
                for index in indices:
                    candidate_value = _resolve_invocation_argument_value(
                        arguments[index],
                        constants,
                        function_returns,
                    )
                    if candidate_value is None or not _contains_any(
                        candidate_value,
                        condition.arg_contains_any_of.any_of,
                    ):
                        continue
                    matched_index = index
                    arg_value = candidate_value
                    break
                if matched_index < 0 or arg_value is None:
                    return None
                if condition.arg_contains_any_of.index_capture_as:
                    captures[condition.arg_contains_any_of.index_capture_as] = str(matched_index)
                if condition.arg_contains_any_of.capture_as:
                    captures[condition.arg_contains_any_of.capture_as] = arg_value
            if condition.not_arg_contains_any_of:
                if not _is_invocation_expression(node):
                    return None
                arguments = _get_invocation_arguments(node)
                indices = _resolve_match_indices(condition.not_arg_contains_any_of, len(arguments))
                if not indices:
                    return None
                resolved_any = False
                for index in indices:
                    arg_value = _resolve_invocation_argument_value(
                        arguments[index],
                        constants,
                        function_returns,
                    )
                    if arg_value is None:
                        continue
                    resolved_any = True
                    if _contains_any(arg_value, condition.not_arg_contains_any_of.any_of):
                        return None
                if not resolved_any:
                    return None
            if condition.regex_on_arg:
                if not _is_invocation_expression(node):
                    return None
                arguments = _get_invocation_arguments(node)
                indices = _resolve_match_indices(condition.regex_on_arg, len(arguments))
                if not indices:
                    return None
                pattern = re.compile(
                    condition.regex_on_arg.pattern,
                    _compile_flags(condition.regex_on_arg.flags),
                )
                matched_index = -1
                match: Optional[re.Match[str]] = None
                for index in indices:
                    arg_value = _resolve_invocation_argument_value(
                        arguments[index],
                        constants,
                        function_returns,
                    )
                    if arg_value is None:
                        continue
                    candidate_match = pattern.search(arg_value)
                    if not candidate_match:
                        continue
                    matched_index = index
                    match = candidate_match
                    break
                if matched_index < 0 or match is None:
                    return None
                if condition.regex_on_arg.index_capture_as:
                    captures[condition.regex_on_arg.index_capture_as] = str(matched_index)
                if condition.regex_on_arg.capture_as:
                    captures[condition.regex_on_arg.capture_as] = _extract_match_value(
                        match,
                        condition.regex_on_arg.capture_group,
                    )
            if condition.not_regex_on_arg:
                if not _is_invocation_expression(node):
                    return None
                arguments = _get_invocation_arguments(node)
                indices = _resolve_match_indices(condition.not_regex_on_arg, len(arguments))
                if not indices:
                    return None
                pattern = re.compile(
                    condition.not_regex_on_arg.pattern,
                    _compile_flags(condition.not_regex_on_arg.flags),
                )
                resolved_any = False
                for index in indices:
                    arg_value = _resolve_invocation_argument_value(
                        arguments[index],
                        constants,
                        function_returns,
                    )
                    if arg_value is None:
                        continue
                    resolved_any = True
                    if pattern.search(arg_value):
                        return None
                if not resolved_any:
                    return None
            if condition.object_arg_property_any_of:
                if not _is_invocation_expression(node):
                    return None
                arguments = _get_invocation_arguments(node)
                indices = _resolve_match_indices(condition.object_arg_property_any_of, len(arguments))
                if not indices:
                    return None
                matched_index = -1
                property_path: Optional[str] = None
                property_value: Optional[str] = None
                for index in indices:
                    property_match = self._resolve_object_arg_property_match(
                        arguments[index],
                        condition.object_arg_property_any_of,
                        constants,
                        function_returns,
                    )
                    if property_match is None:
                        continue
                    candidate_path, candidate_value = property_match
                    if candidate_value not in condition.object_arg_property_any_of.any_of:
                        continue
                    matched_index = index
                    property_path = candidate_path
                    property_value = candidate_value
                    break
                if matched_index < 0 or property_path is None or property_value is None:
                    return None
                if condition.object_arg_property_any_of.index_capture_as:
                    captures[condition.object_arg_property_any_of.index_capture_as] = str(matched_index)
                if condition.object_arg_property_any_of.path_capture_as:
                    captures[condition.object_arg_property_any_of.path_capture_as] = property_path
                if condition.object_arg_property_any_of.capture_as:
                    captures[condition.object_arg_property_any_of.capture_as] = property_value
            if condition.not_object_arg_property_any_of:
                if not _is_invocation_expression(node):
                    return None
                arguments = _get_invocation_arguments(node)
                indices = _resolve_match_indices(condition.not_object_arg_property_any_of, len(arguments))
                if not indices:
                    return None
                resolved_any = False
                for index in indices:
                    property_match = self._resolve_object_arg_property_match(
                        arguments[index],
                        condition.not_object_arg_property_any_of,
                        constants,
                        function_returns,
                    )
                    if property_match is None:
                        continue
                    resolved_any = True
                    _, property_value = property_match
                    if property_value in condition.not_object_arg_property_any_of.any_of:
                        return None
                if not resolved_any:
                    return None
            if condition.object_arg_property_contains_any_of:
                if not _is_invocation_expression(node):
                    return None
                arguments = _get_invocation_arguments(node)
                indices = _resolve_match_indices(condition.object_arg_property_contains_any_of, len(arguments))
                if not indices:
                    return None
                matched_index = -1
                property_path: Optional[str] = None
                property_value: Optional[str] = None
                for index in indices:
                    property_match = self._resolve_object_arg_property_match(
                        arguments[index],
                        condition.object_arg_property_contains_any_of,
                        constants,
                        function_returns,
                    )
                    if property_match is None:
                        continue
                    candidate_path, candidate_value = property_match
                    if not _contains_any(
                        candidate_value,
                        condition.object_arg_property_contains_any_of.any_of,
                    ):
                        continue
                    matched_index = index
                    property_path = candidate_path
                    property_value = candidate_value
                    break
                if matched_index < 0 or property_path is None or property_value is None:
                    return None
                if condition.object_arg_property_contains_any_of.index_capture_as:
                    captures[condition.object_arg_property_contains_any_of.index_capture_as] = str(matched_index)
                if condition.object_arg_property_contains_any_of.path_capture_as:
                    captures[condition.object_arg_property_contains_any_of.path_capture_as] = property_path
                if condition.object_arg_property_contains_any_of.capture_as:
                    captures[condition.object_arg_property_contains_any_of.capture_as] = property_value
            if condition.not_object_arg_property_contains_any_of:
                if not _is_invocation_expression(node):
                    return None
                arguments = _get_invocation_arguments(node)
                indices = _resolve_match_indices(condition.not_object_arg_property_contains_any_of, len(arguments))
                if not indices:
                    return None
                resolved_any = False
                for index in indices:
                    property_match = self._resolve_object_arg_property_match(
                        arguments[index],
                        condition.not_object_arg_property_contains_any_of,
                        constants,
                        function_returns,
                    )
                    if property_match is None:
                        continue
                    resolved_any = True
                    _, property_value = property_match
                    if _contains_any(property_value, condition.not_object_arg_property_contains_any_of.any_of):
                        return None
                if not resolved_any:
                    return None
            if condition.regex_on_object_arg_property:
                if not _is_invocation_expression(node):
                    return None
                arguments = _get_invocation_arguments(node)
                indices = _resolve_match_indices(condition.regex_on_object_arg_property, len(arguments))
                if not indices:
                    return None
                pattern = re.compile(
                    condition.regex_on_object_arg_property.pattern,
                    _compile_flags(condition.regex_on_object_arg_property.flags),
                )
                matched_index = -1
                property_path: Optional[str] = None
                match: Optional[re.Match[str]] = None
                for index in indices:
                    property_match = self._resolve_object_arg_property_match(
                        arguments[index],
                        condition.regex_on_object_arg_property,
                        constants,
                        function_returns,
                    )
                    if property_match is None:
                        continue
                    candidate_path, property_value = property_match
                    candidate_match = pattern.search(property_value)
                    if not candidate_match:
                        continue
                    matched_index = index
                    property_path = candidate_path
                    match = candidate_match
                    break
                if matched_index < 0 or property_path is None or match is None:
                    return None
                if condition.regex_on_object_arg_property.index_capture_as:
                    captures[condition.regex_on_object_arg_property.index_capture_as] = str(matched_index)
                if condition.regex_on_object_arg_property.path_capture_as:
                    captures[condition.regex_on_object_arg_property.path_capture_as] = property_path
                if condition.regex_on_object_arg_property.capture_as:
                    captures[condition.regex_on_object_arg_property.capture_as] = _extract_match_value(
                        match,
                        condition.regex_on_object_arg_property.capture_group,
                    )
            if condition.not_regex_on_object_arg_property:
                if not _is_invocation_expression(node):
                    return None
                arguments = _get_invocation_arguments(node)
                indices = _resolve_match_indices(condition.not_regex_on_object_arg_property, len(arguments))
                if not indices:
                    return None
                pattern = re.compile(
                    condition.not_regex_on_object_arg_property.pattern,
                    _compile_flags(condition.not_regex_on_object_arg_property.flags),
                )
                resolved_any = False
                for index in indices:
                    property_match = self._resolve_object_arg_property_match(
                        arguments[index],
                        condition.not_regex_on_object_arg_property,
                        constants,
                        function_returns,
                    )
                    if property_match is None:
                        continue
                    resolved_any = True
                    _, property_value = property_match
                    if pattern.search(property_value):
                        return None
                if not resolved_any:
                    return None

        if clause.any_conditions:
            any_captures: Optional[dict[str, str]] = None
            for condition in clause.any_conditions:
                candidate = self._match_clause(
                    node,
                    SemanticClauseSpec.model_validate({"and": [condition]}),
                    constants,
                    function_returns,
                    property_path,
                )
                if candidate is not None:
                    any_captures = candidate
                    break
            if any_captures is None:
                return None
            captures.update(any_captures)

        for condition in clause.none_conditions:
            candidate = self._match_clause(
                node,
                SemanticClauseSpec.model_validate({"and": [condition]}),
                constants,
                function_returns,
                property_path,
            )
            if candidate is not None:
                return None

        return captures

    def _resolve_object_arg_property_match(
        self,
        argument_node: Any,
        condition: (
            RegexObjectArgPropertyConditionSpec
            | ExactObjectArgPropertyConditionSpec
            | ContainsObjectArgPropertyConditionSpec
        ),
        constants: dict[str, str],
        function_returns: dict[str, dict[str, Any]],
    ) -> Optional[tuple[str, str]]:
        """Resolve an object-argument property match as `(path, value)`."""
        if condition.path:
            value = _resolve_object_property_expr(
                argument_node,
                condition.path,
                constants,
                function_returns,
            )
            candidates = {condition.path: value} if value is not None else {}
        elif condition.path_any_of:
            candidates = {
                path: value
                for path in condition.path_any_of
                for value in [
                    _resolve_object_property_expr(
                        argument_node,
                        path,
                        constants,
                        function_returns,
                    )
                ]
                if value is not None
            }
        else:
            candidates = _resolve_object_property_candidates_expr(
                argument_node,
                constants,
                function_returns,
            )

        if condition.not_path_any_of:
            candidates = {
                path: value
                for path, value in candidates.items()
                if path not in condition.not_path_any_of
            }

        if condition.path_regex_any_of:
            compiled_patterns = [
                re.compile(pattern)
                for pattern in condition.path_regex_any_of
            ]
            candidates = {
                path: value
                for path, value in candidates.items()
                if any(pattern.search(path) for pattern in compiled_patterns)
            }
        if condition.not_path_regex_any_of:
            denied_patterns = [
                re.compile(pattern)
                for pattern in condition.not_path_regex_any_of
            ]
            candidates = {
                path: value
                for path, value in candidates.items()
                if not any(pattern.search(path) for pattern in denied_patterns)
            }
        if condition.path_contains_any_of:
            candidates = {
                path: value
                for path, value in candidates.items()
                if _contains_any(path, condition.path_contains_any_of)
            }
        if condition.not_path_contains_any_of:
            candidates = {
                path: value
                for path, value in candidates.items()
                if not _contains_any(path, condition.not_path_contains_any_of)
            }

        if not candidates:
            return None
        selected_path = sorted(candidates)[0]
        return selected_path, candidates[selected_path]

    def _resolve_object_arg_property_value(
        self,
        argument_node: Any,
        condition: (
            RegexObjectArgPropertyConditionSpec
            | ExactObjectArgPropertyConditionSpec
            | ContainsObjectArgPropertyConditionSpec
        ),
        constants: dict[str, str],
        function_returns: dict[str, dict[str, Any]],
    ) -> Optional[str]:
        """Resolve an object-argument property value only."""
        property_match = self._resolve_object_arg_property_match(
            argument_node,
            condition,
            constants,
            function_returns,
        )
        if property_match is None:
            return None
        return property_match[1]

    def _match_ast_condition(
        self,
        node: dict[str, Any],
        condition: SemanticAstConditionSpec,
        constants: dict[str, str],
    ) -> bool:
        """Match the supported AST condition subset."""
        if node.get("type") != condition.kind:
            return False
        if condition.kind == "AssignmentExpression":
            left_path = _resolve_member_path_expr(node.get("left"), constants) or ""
            if condition.left_matches.any_of and left_path not in condition.left_matches.any_of:
                return False
            if condition.left_matches.not_any_of and left_path in condition.left_matches.not_any_of:
                return False
            if condition.left_matches.contains_any_of and not _contains_any(
                left_path,
                condition.left_matches.contains_any_of,
            ):
                return False
            if condition.left_matches.not_contains_any_of and _contains_any(
                left_path,
                condition.left_matches.not_contains_any_of,
            ):
                return False
            if condition.left_matches.regex_any_of and not any(
                re.search(pattern, left_path)
                for pattern in condition.left_matches.regex_any_of
            ):
                return False
            if condition.left_matches.not_regex_any_of and any(
                re.search(pattern, left_path)
                for pattern in condition.left_matches.not_regex_any_of
            ):
                return False
        if condition.kind in {"CallExpression", "NewExpression"}:
            call_name = _get_call_expression_name(node.get("callee", {}))
            if condition.callee_any_of and not _call_name_matches(call_name, condition.callee_any_of):
                return False
            if condition.not_callee_any_of and _call_name_matches(call_name, condition.not_callee_any_of):
                return False
            if condition.callee_contains_any_of and not _call_name_contains(
                call_name,
                condition.callee_contains_any_of,
            ):
                return False
            if condition.not_callee_contains_any_of and _call_name_contains(
                call_name,
                condition.not_callee_contains_any_of,
            ):
                return False
            if condition.callee_regex_any_of and not any(
                re.search(pattern, call_name)
                for pattern in condition.callee_regex_any_of
            ):
                return False
            if condition.not_callee_regex_any_of and any(
                re.search(pattern, call_name)
                for pattern in condition.not_callee_regex_any_of
            ):
                return False
        if condition.kind == "VariableDeclarator":
            identifier = node.get("id", {})
            identifier_name = identifier.get("name", "") if isinstance(identifier, dict) else ""
            if condition.id_name_any_of and identifier_name not in condition.id_name_any_of:
                return False
            if condition.not_id_name_any_of and identifier_name in condition.not_id_name_any_of:
                return False
            if condition.id_name_contains_any_of and not _contains_any(
                identifier_name,
                condition.id_name_contains_any_of,
            ):
                return False
            if condition.not_id_name_contains_any_of and _contains_any(
                identifier_name,
                condition.not_id_name_contains_any_of,
            ):
                return False
            if condition.id_name_regex_any_of and not any(
                re.search(pattern, identifier_name)
                for pattern in condition.id_name_regex_any_of
            ):
                return False
            if condition.not_id_name_regex_any_of and any(
                re.search(pattern, identifier_name)
                for pattern in condition.not_id_name_regex_any_of
            ):
                return False
        if condition.kind == "Property":
            if (
                not condition.property_path_any_of
                and not condition.not_property_path_any_of
                and not condition.property_path_contains_any_of
                and not condition.not_property_path_contains_any_of
                and not condition.property_path_regex_any_of
                and not condition.not_property_path_regex_any_of
            ):
                return True
        return True

    def _capture_ast_condition(
        self,
        node: dict[str, Any],
        condition: SemanticAstConditionSpec,
        constants: dict[str, str],
        property_path: Optional[str] = None,
    ) -> dict[str, str]:
        """Capture AST-side match context for semantic rules."""
        captures: dict[str, str] = {}

        if condition.kind == "AssignmentExpression":
            left_path = _resolve_member_path_expr(node.get("left"), constants) or ""
            if condition.left_capture_as:
                captures[condition.left_capture_as] = left_path
        elif condition.kind in {"CallExpression", "NewExpression"}:
            call_name = _get_call_expression_name(node.get("callee", {}))
            if condition.callee_capture_as:
                captures[condition.callee_capture_as] = call_name
        elif condition.kind == "VariableDeclarator":
            identifier = node.get("id", {})
            identifier_name = identifier.get("name", "") if isinstance(identifier, dict) else ""
            if condition.id_name_capture_as:
                captures[condition.id_name_capture_as] = identifier_name
        elif condition.kind == "Property" and property_path and condition.property_path_capture_as:
            captures[condition.property_path_capture_as] = property_path

        return captures

    def _build_semantic_metadata(
        self,
        node: dict[str, Any],
        constants: dict[str, str],
        property_path: Optional[str] = None,
    ) -> dict[str, Any]:
        """Attach semantic-node metadata useful for debugging custom matches."""
        node_type = node.get("type")
        if node_type == "AssignmentExpression":
            left_path = _resolve_member_path_expr(node.get("left"), constants)
            return {"left_path": left_path}
        if node_type in {"CallExpression", "NewExpression"}:
            callee_path = _get_call_expression_name(node.get("callee", {}))
            return {"callee_path": callee_path}
        if node_type == "VariableDeclarator":
            identifier = node.get("id", {})
            return {"declarator_name": identifier.get("name")}
        if node_type == "Property":
            return {"property_path": property_path}
        return {}


def load_custom_rules(path: Path) -> list[BaseRule]:
    """Load custom rules from a JSON/YAML file, rules directory, or meta pack file."""
    rules: list[BaseRule] = []
    for data in _load_rule_documents(path):
        raw_rules = data if isinstance(data, list) else data.get("rules", [])
        rule_defaults = _extract_rule_defaults(data)

        for raw_rule in raw_rules:
            prepared_rule = _prepare_rule_payload(raw_rule, rule_defaults)
            matcher = prepared_rule.get("matcher", {})
            if isinstance(matcher, dict) and matcher.get("type") == "ast_pattern":
                rules.append(
                    CustomAstPatternRule(CustomDeclarativeRuleSpec.model_validate(prepared_rule))
                )
            elif isinstance(matcher, dict) and matcher.get("type") == "regex":
                rules.append(
                    CustomRegexMatcherRule(CustomDeclarativeRuleSpec.model_validate(prepared_rule))
                )
            elif isinstance(matcher, dict) and matcher.get("type") == "semantic":
                rules.append(
                    CustomSemanticRule(CustomDeclarativeRuleSpec.model_validate(prepared_rule))
                )
            else:
                rules.append(
                    CustomRegexRule(CustomRuleSpec.model_validate(prepared_rule))
                )
    return rules


def _load_rule_documents(path: Path) -> list[Any]:
    """Load one or more raw rule payloads from a file, rules directory, or meta pack file."""
    if path.is_dir():
        documents: list[Any] = []
        for child in sorted(path.iterdir(), key=lambda item: item.name.lower()):
            if not child.is_file() or child.suffix.lower() not in {".json", ".yaml", ".yml"}:
                continue
            documents.extend(_load_rule_documents(child))
        return documents

    data = _load_rule_data(path)
    if isinstance(data, dict) and "ruleset" in data and "rules" not in data:
        rules_dir = path.parent / "rules"
        if rules_dir.is_dir():
            return _load_rule_documents(rules_dir)
    return [data]


def _prepare_rule_payload(
    raw_rule: dict[str, Any],
    defaults: dict[str, Any],
) -> dict[str, Any]:
    """Apply top-level defaults and category aliases to a raw rule."""
    prepared = dict(raw_rule)
    for field_name in (
        "description",
        "value_type",
        "severity",
        "confidence",
        "enabled",
        "scope",
        "extract_group",
    ):
        if field_name not in prepared and defaults.get(field_name) is not None:
            prepared[field_name] = defaults[field_name]
    for field_name in ("matcher", "extract", "normalize", "evidence"):
        default_value = defaults.get(field_name)
        rule_value = prepared.get(field_name)
        if isinstance(default_value, dict) and isinstance(rule_value, dict):
            prepared[field_name] = _deep_merge_dicts(default_value, rule_value)
        elif field_name not in prepared and isinstance(default_value, dict):
            prepared[field_name] = deepcopy(default_value)

    default_tags = defaults.get("tags", [])
    rule_tags = prepared.get("tags", [])
    if isinstance(default_tags, list) and default_tags:
        if isinstance(rule_tags, list) and rule_tags:
            merged_tags: list[str] = []
            for tag in [*default_tags, *rule_tags]:
                if isinstance(tag, str) and tag and tag not in merged_tags:
                    merged_tags.append(tag)
            prepared["tags"] = merged_tags
        elif "tags" not in prepared:
            prepared["tags"] = [
                tag for tag in default_tags
                if isinstance(tag, str) and tag
            ]

    default_flags = defaults.get("flags", [])
    rule_flags = prepared.get("flags", [])
    if isinstance(default_flags, list) and default_flags:
        if isinstance(rule_flags, list) and rule_flags:
            merged_flags: list[str] = []
            for flag in [*default_flags, *rule_flags]:
                if isinstance(flag, str):
                    normalized_flag = flag.strip().lower()
                    if normalized_flag and normalized_flag not in merged_flags:
                        merged_flags.append(normalized_flag)
            prepared["flags"] = merged_flags
        elif "flags" not in prepared:
            prepared["flags"] = [
                flag.strip().lower()
                for flag in default_flags
                if isinstance(flag, str) and flag.strip()
            ]

    category = prepared.get("category", defaults.get("category"))
    if category is not None:
        prepared["category"] = _normalize_category_value(category)
    return prepared


def _extract_rule_defaults(data: Any) -> dict[str, Any]:
    """Extract top-level rule defaults from JSON/YAML payloads."""
    if not isinstance(data, dict):
        return {}

    defaults: dict[str, Any] = {}
    for field_name in (
        "category",
        "description",
        "value_type",
        "severity",
        "confidence",
        "enabled",
        "tags",
        "scope",
        "extract_group",
        "flags",
        "matcher",
        "extract",
        "normalize",
        "evidence",
    ):
        if data.get(field_name) is not None:
            defaults[field_name] = data.get(field_name)

    raw_defaults = data.get("defaults")
    if isinstance(raw_defaults, dict):
        for field_name in (
            "category",
            "description",
            "value_type",
            "severity",
            "confidence",
            "enabled",
            "tags",
            "scope",
            "extract_group",
            "flags",
            "matcher",
            "extract",
            "normalize",
            "evidence",
        ):
            if raw_defaults.get(field_name) is not None:
                defaults[field_name] = raw_defaults.get(field_name)

    if defaults.get("category") is not None:
        defaults["category"] = _normalize_category_value(defaults["category"])

    if isinstance(defaults.get("tags"), list):
        defaults["tags"] = [
            tag for tag in defaults["tags"]
            if isinstance(tag, str) and tag
        ]
    if isinstance(defaults.get("flags"), list):
        defaults["flags"] = [
            flag.strip().lower()
            for flag in defaults["flags"]
            if isinstance(flag, str) and flag.strip()
        ]

    return defaults


def _deep_merge_dicts(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Recursively merge two small JSON-like dictionaries with override precedence."""
    merged = deepcopy(base)
    for key, value in override.items():
        existing = merged.get(key)
        if isinstance(existing, dict) and isinstance(value, dict):
            merged[key] = _deep_merge_dicts(existing, value)
        else:
            merged[key] = deepcopy(value)
    return merged


def _normalize_category_value(value: Any) -> Category:
    """Normalize category aliases used by shipped YAML examples."""
    if isinstance(value, Category):
        return value

    normalized = str(value or "").strip().lower()
    if normalized in _CATEGORY_ALIASES:
        return _CATEGORY_ALIASES[normalized]
    return Category(normalized)


def _load_rule_data(path: Path) -> Any:
    """Load raw custom rule data from disk."""
    content = path.read_text(encoding="utf-8")
    if path.suffix.lower() in {".yaml", ".yml"}:
        return load_yaml(content)

    return json.loads(content)


def _compile_flags(flags: list[str]) -> int:
    """Convert textual regex flags into Python re flags."""
    flag_map = {
        "i": re.IGNORECASE,
        "m": re.MULTILINE,
        "s": re.DOTALL,
        "x": re.VERBOSE,
    }
    value = 0
    for flag in flags:
        value |= flag_map.get(flag.lower(), 0)
    return value


def _extract_match_value(match: re.Match[str], extract_group: int) -> str:
    """Extract the configured value from a regex match."""
    if extract_group > 0 and match.lastindex and match.lastindex >= extract_group:
        return match.group(extract_group)
    return match.group(0)


def _contains_any(value: str, candidates: list[str]) -> bool:
    """Check whether a resolved string contains any configured substring."""
    return any(candidate in value for candidate in candidates)


def _is_invocation_expression(node: Any) -> bool:
    """Check whether the AST node is a call-like invocation expression."""
    return isinstance(node, dict) and node.get("type") in {"CallExpression", "NewExpression"}


def _get_invocation_arguments(node: Any) -> list[Any]:
    """Extract arguments from a supported invocation expression."""
    if not _is_invocation_expression(node):
        return []
    arguments = node.get("arguments", [])
    return arguments if isinstance(arguments, list) else []


def _resolve_match_indices(spec: Any, arg_count: int) -> list[int]:
    """Resolve configured invocation-argument indices in matching order."""
    if arg_count <= 0:
        return []
    raw_indices = getattr(spec, "index_any_of", None) or [getattr(spec, "index", -1)]
    resolved: list[int] = []
    seen: set[int] = set()
    for index in raw_indices:
        if not isinstance(index, int) or index < 0 or index >= arg_count or index in seen:
            continue
        resolved.append(index)
        seen.add(index)
    return resolved


def _call_name_matches(
    call_name: str,
    allowed: list[str],
    regex_allowed: Optional[list[str]] = None,
    contains_allowed: Optional[list[str]] = None,
) -> bool:
    """Check whether a call-expression name matches a configured allowlist."""
    short_name = call_name.split(".")[-1] if call_name else ""
    if allowed and (short_name in allowed or call_name in allowed):
        return True
    if contains_allowed and _call_name_contains(call_name, contains_allowed):
        return True
    if regex_allowed and any(
        re.search(pattern, call_name) or re.search(pattern, short_name)
        for pattern in regex_allowed
    ):
        return True
    return not allowed and not regex_allowed and not contains_allowed


def _call_name_contains(call_name: str, fragments: list[str]) -> bool:
    """Check whether a call-expression name contains any configured substring."""
    short_name = call_name.split(".")[-1] if call_name else ""
    return _contains_any(call_name, fragments) or _contains_any(short_name, fragments)


def _match_ast_value(
    node: Any,
    spec: AstPatternArgSpec,
    constants: dict[str, str],
) -> Optional[str]:
    """Resolve and optionally regex-filter a supported AST value."""
    value = _extract_argument_value(node, spec.type, constants)
    if value is None:
        return None
    if spec.any_of and value not in spec.any_of:
        return None
    if spec.not_any_of and value in spec.not_any_of:
        return None
    if spec.contains_any_of and not _contains_any(value, spec.contains_any_of):
        return None
    if spec.not_contains_any_of and _contains_any(value, spec.not_contains_any_of):
        return None
    if spec.not_regex and re.search(spec.not_regex, value):
        return None
    if spec.regex:
        match = re.search(spec.regex, value)
        if not match:
            return None
        return _extract_match_value(match, spec.capture_group)
    return value


def _extract_argument_value(
    node: Any,
    arg_type: str,
    constants: dict[str, str],
) -> Optional[str]:
    """Extract a supported argument value from a raw AST node."""
    if arg_type == "LiteralString":
        return _extract_literal_string(node)
    if arg_type == "TemplateLiteral":
        return _extract_template_literal(node, constants)
    if arg_type == "IdentifierString":
        return _extract_identifier_string(node, constants)
    if arg_type == "IdentifierName":
        if isinstance(node, dict) and node.get("type") == "Identifier":
            return node.get("name")
        return None
    if arg_type == "MemberPath":
        return _extract_member_path(node) or _resolve_member_lookup_path(node, constants)
    if arg_type == "Any":
        return (
            _resolve_string_expr(node, constants)
            or _extract_member_path(node)
            or _resolve_member_lookup_path(node, constants)
        )
    return None


def _resolve_invocation_argument_value(
    node: Any,
    constants: dict[str, str],
    function_returns: Optional[dict[str, dict[str, Any]]] = None,
) -> Optional[str]:
    """Resolve a practical semantic invocation argument as a string or static member path."""
    return (
        _resolve_string_expr(node, constants, function_returns)
        or _extract_member_path(node)
        or _resolve_member_lookup_path(node, constants)
    )


def _resolve_semantic_value_expr(
    node: Any,
    constants: dict[str, str],
    function_returns: Optional[dict[str, dict[str, Any]]] = None,
) -> Optional[str]:
    """Resolve a practical semantic assignment/init/property value as a string or static member path."""
    return (
        _resolve_string_expr(node, constants, function_returns)
        or _extract_member_path(node)
        or _resolve_member_lookup_path(node, constants)
    )


def _extract_literal_string(node: Any) -> Optional[str]:
    """Extract a string literal value from a raw AST node."""
    if not isinstance(node, dict):
        return None

    node_type = node.get("type")
    if node_type == "Literal" and isinstance(node.get("value"), str):
        return node.get("value")
    return None


def _extract_template_literal(
    node: Any,
    constants: dict[str, str],
    function_returns: Optional[dict[str, dict[str, Any]]] = None,
    seen: Optional[set[str]] = None,
    bindings: Optional[dict[str, str]] = None,
) -> Optional[str]:
    """Extract a simple template literal string value."""
    if not isinstance(node, dict) or node.get("type") != "TemplateLiteral":
        return None

    quasis = node.get("quasis", [])
    expressions = node.get("expressions", [])
    if not expressions:
        if len(quasis) == 1:
            return quasis[0].get("value", {}).get("cooked")
        return ""

    if len(quasis) != len(expressions) + 1:
        return None

    parts: list[str] = []
    for index, quasi in enumerate(quasis):
        parts.append(quasi.get("value", {}).get("cooked", ""))
        if index < len(expressions):
            expr_value = _resolve_string_expr(
                expressions[index],
                constants,
                function_returns,
                seen,
                bindings,
            )
            if expr_value is None:
                return None
            parts.append(expr_value)
    return "".join(parts)


def _extract_identifier_string(
    node: Any,
    constants: dict[str, str],
) -> Optional[str]:
    """Extract a resolved string value from an identifier argument."""
    if not isinstance(node, dict) or node.get("type") != "Identifier":
        return None
    return constants.get(node.get("name", ""))


def _extract_member_path(node: Any) -> Optional[str]:
    """Extract a dotted member-expression path when statically known."""
    if not isinstance(node, dict):
        return None

    node_type = node.get("type")
    if node_type == "Identifier":
        return node.get("name")
    if node_type != "MemberExpression":
        return None

    object_path = _extract_member_path(node.get("object"))
    property_node = node.get("property", {})
    if node.get("computed"):
        if property_node.get("type") == "Literal" and isinstance(property_node.get("value"), (str, int)):
            property_name = str(property_node.get("value"))
        else:
            return None
    else:
        property_name = property_node.get("name")

    if object_path and property_name:
        return f"{object_path}.{property_name}"
    return property_name


def _resolve_member_path_expr(
    node: Any,
    constants: Optional[dict[str, str]] = None,
    bindings: Optional[dict[str, str]] = None,
) -> Optional[str]:
    """Resolve a member-expression path, including constant-key computed lookups."""
    resolved = _extract_member_path(node)
    if resolved is not None:
        return resolved
    if constants is None:
        return None
    return _resolve_member_lookup_path(node, constants, bindings)


def _get_call_expression_name(callee: Any) -> str:
    """Extract a comparable call-expression name from a callee node."""
    return _extract_member_path(callee) or ""


def _normalize_value(value: str, spec: NormalizeFieldSpec) -> str:
    """Apply supported normalization transforms to an extracted field."""
    result = value
    if spec.strip_query:
        parsed = urlsplit(result)
        result = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))
    if spec.lowercase:
        result = result.lower()
    return result


def _build_constant_table(
    ast: dict[str, Any],
    function_returns: Optional[dict[str, dict[str, Any]]] = None,
) -> dict[str, str]:
    """Build a simple constant table from top-level const/let assignments."""
    constants: dict[str, str] = {}
    for _ in range(5):
        changed = False
        for node in _iter_nodes(ast):
            if node.get("type") != "VariableDeclarator":
                continue
            identifier = node.get("id", {})
            init = node.get("init")
            if identifier.get("type") in {"ObjectPattern", "ArrayPattern"}:
                if _bind_pattern_alias_value(
                    identifier,
                    init,
                    constants,
                    function_returns,
                    bindings=constants,
                ):
                    changed = True
                continue
            if identifier.get("type") != "Identifier":
                continue
            name = identifier.get("name", "")
            if not name or not isinstance(init, dict):
                continue
            if init.get("type") == "ObjectExpression":
                object_values = _extract_object_string_values(name, init, constants, function_returns)
                for key, value in object_values.items():
                    if constants.get(key) != value:
                        constants[key] = value
                        changed = True
                continue
            if init.get("type") == "ArrayExpression":
                array_values = _extract_array_string_values(name, init, constants, function_returns)
                for key, value in array_values.items():
                    if constants.get(key) != value:
                        constants[key] = value
                        changed = True
                continue
            if init.get("type") == "Literal" and isinstance(init.get("value"), int):
                value = str(init.get("value"))
                if constants.get(name) != value:
                    constants[name] = value
                    changed = True
                continue
            value = _resolve_string_expr(init, constants, function_returns)
            if value is not None and constants.get(name) != value:
                constants[name] = value
                changed = True
        if not changed:
            break
    return constants


def _resolve_string_expr(
    node: Any,
    constants: dict[str, str],
    function_returns: Optional[dict[str, dict[str, Any]]] = None,
    seen: Optional[set[str]] = None,
    bindings: Optional[dict[str, str]] = None,
) -> Optional[str]:
    """Resolve a minimal string expression subset."""
    if not isinstance(node, dict):
        return None

    node_type = node.get("type")
    if node_type == "Literal" and isinstance(node.get("value"), str):
        return node.get("value")
    if node_type == "Identifier":
        name = node.get("name", "")
        if bindings and name in bindings:
            return bindings.get(name)
        return constants.get(name)
    if node_type == "MemberExpression":
        path = _extract_member_path(node) or _resolve_member_lookup_path(node, constants, bindings)
        if path:
            if bindings and path in bindings:
                return bindings.get(path)
            return constants.get(path)
        return None
    if node_type == "TemplateLiteral":
        return _extract_template_literal(node, constants, function_returns, seen, bindings)
    if node_type == "BinaryExpression" and node.get("operator") == "+":
        left = _resolve_string_expr(node.get("left"), constants, function_returns, seen, bindings)
        right = _resolve_string_expr(node.get("right"), constants, function_returns, seen, bindings)
        if left is not None and right is not None:
            return left + right
    if node_type == "CallExpression" and node.get("callee", {}).get("type") == "Identifier":
        return _resolve_function_call(
            node.get("callee", {}).get("name", ""),
            node.get("arguments", []),
            constants,
            function_returns or {},
            seen=seen,
            bindings=bindings,
        )
    if node_type == "CallExpression" and node.get("callee", {}).get("type") == "MemberExpression":
        return _resolve_function_call(
            _extract_member_path(node.get("callee", {})) or "",
            node.get("arguments", []),
            constants,
            function_returns or {},
            seen=seen,
            bindings=bindings,
        )
    return None


def _resolve_object_property_expr(
    node: Any,
    path: str,
    constants: dict[str, str],
    function_returns: Optional[dict[str, dict[str, Any]]] = None,
    seen: Optional[set[str]] = None,
    bindings: Optional[dict[str, str]] = None,
) -> Optional[str]:
    """Resolve a string-valued property from an object expression or object identifier."""
    if not isinstance(node, dict) or not path:
        return None

    node_type = node.get("type")
    if node_type == "ObjectExpression":
        return _resolve_object_expression_path(
            node,
            path,
            constants,
            function_returns,
            seen,
            bindings,
        )
    if node_type == "CallExpression" and node.get("callee", {}).get("type") == "Identifier":
        return _resolve_function_object_property_call(
            node.get("callee", {}).get("name", ""),
            node.get("arguments", []),
            path,
            constants,
            function_returns or {},
            seen=seen,
            bindings=bindings,
        )
    if node_type == "CallExpression" and node.get("callee", {}).get("type") == "MemberExpression":
        return _resolve_function_object_property_call(
            _extract_member_path(node.get("callee", {})) or "",
            node.get("arguments", []),
            path,
            constants,
            function_returns or {},
            seen=seen,
            bindings=bindings,
        )

    base_path = _extract_member_path(node) or _resolve_member_lookup_path(node, constants, bindings)
    if base_path:
        if bindings and f"{base_path}.{path}" in bindings:
            return bindings.get(f"{base_path}.{path}")
        return constants.get(f"{base_path}.{path}")
    return None


def _resolve_object_expression_path(
    node: dict[str, Any],
    path: str,
    constants: dict[str, str],
    function_returns: Optional[dict[str, dict[str, Any]]] = None,
    seen: Optional[set[str]] = None,
    bindings: Optional[dict[str, str]] = None,
) -> Optional[str]:
    """Resolve a dotted property path from an object expression."""
    if not path:
        return None

    return _extract_object_string_values(
        "",
        node,
        constants,
        function_returns,
        seen=seen,
        bindings=bindings,
    ).get(path)


def _extract_object_string_values(
    prefix: str,
    node: dict[str, Any],
    constants: dict[str, str],
    function_returns: Optional[dict[str, dict[str, Any]]] = None,
    seen: Optional[set[str]] = None,
    bindings: Optional[dict[str, str]] = None,
) -> dict[str, str]:
    """Flatten string-valued object properties into dotted constant paths."""
    values: dict[str, str] = {}
    if node.get("type") != "ObjectExpression":
        return values

    for prop in node.get("properties", []):
        if not isinstance(prop, dict):
            continue
        if prop.get("type") == "SpreadElement":
            spread_values = _resolve_object_property_candidates_expr(
                prop.get("argument"),
                constants,
                function_returns,
                seen=seen,
                bindings=bindings,
            )
            for spread_path, spread_value in spread_values.items():
                if not spread_path:
                    continue
                path = f"{prefix}.{spread_path}" if prefix else spread_path
                values[path] = spread_value
            continue
        key_name = _extract_property_name_with_lookup(prop, constants, bindings)
        if not key_name:
            continue
        path = f"{prefix}.{key_name}" if prefix else key_name
        value_node = prop.get("value")
        if isinstance(value_node, dict) and value_node.get("type") == "ObjectExpression":
            values.update(
                _extract_object_string_values(
                    path,
                    value_node,
                    constants,
                    function_returns,
                    seen=seen,
                    bindings=bindings,
                )
            )
            continue
        if isinstance(value_node, dict) and value_node.get("type") == "ArrayExpression":
            values.update(
                _extract_array_string_values(
                    path,
                    value_node,
                    constants,
                    function_returns,
                    seen=seen,
                    bindings=bindings,
                )
            )
            continue
        nested_values = _resolve_object_property_candidates_expr(
            value_node,
            constants,
            function_returns,
            seen=seen,
            bindings=bindings,
        ) if isinstance(value_node, dict) else {}
        if nested_values:
            for nested_path, nested_value in nested_values.items():
                nested_key = f"{path}.{nested_path}" if nested_path else path
                values[nested_key] = nested_value
            continue
        value = _resolve_string_expr(
            value_node,
            constants,
            function_returns,
            seen=seen,
            bindings=bindings,
        )
        if value is None and isinstance(value_node, dict):
            value = _extract_member_path(value_node) or _resolve_member_lookup_path(
                value_node,
                constants,
                bindings,
            )
        if value is not None:
            values[path] = value
    return values


def _extract_array_string_values(
    prefix: str,
    node: dict[str, Any],
    constants: dict[str, str],
    function_returns: Optional[dict[str, dict[str, Any]]] = None,
    seen: Optional[set[str]] = None,
    bindings: Optional[dict[str, str]] = None,
) -> dict[str, str]:
    """Flatten array string members into dotted constant-table keys."""
    values: dict[str, str] = {}
    if node.get("type") != "ArrayExpression":
        return values

    for index, element in enumerate(node.get("elements", [])):
        if not isinstance(element, dict):
            continue
        path = f"{prefix}.{index}" if prefix else str(index)
        if element.get("type") == "ObjectExpression":
            values.update(
                _extract_object_string_values(
                    path,
                    element,
                    constants,
                    function_returns,
                    seen=seen,
                    bindings=bindings,
                )
            )
            continue
        if element.get("type") == "ArrayExpression":
            values.update(
                _extract_array_string_values(
                    path,
                    element,
                    constants,
                    function_returns,
                    seen=seen,
                    bindings=bindings,
                )
            )
            continue
        value = _resolve_string_expr(
            element,
            constants,
            function_returns,
            seen=seen,
            bindings=bindings,
        )
        if value is None:
            value = _extract_member_path(element) or _resolve_member_lookup_path(
                element,
                constants,
                bindings,
            )
        if value is not None:
            values[path] = value
    return values


def _resolve_member_lookup_path(
    node: Any,
    constants: dict[str, str],
    bindings: Optional[dict[str, str]] = None,
) -> Optional[str]:
    """Resolve computed member lookups such as CONFIGS[idx] into dotted paths."""
    if not isinstance(node, dict) or node.get("type") != "MemberExpression":
        return None

    object_node = node.get("object", {})
    object_path = _extract_member_path(object_node) or _resolve_member_lookup_path(
        object_node,
        constants,
        bindings,
    )
    if not object_path:
        return None

    if node.get("computed"):
        property_name = _resolve_scalar_expr(node.get("property"), constants, bindings)
    else:
        property_name = node.get("property", {}).get("name")

    if not property_name:
        return None
    return f"{object_path}.{property_name}"


def _resolve_scalar_expr(
    node: Any,
    constants: dict[str, str],
    bindings: Optional[dict[str, str]] = None,
) -> Optional[str]:
    """Resolve a minimal scalar value used in computed member lookups."""
    if not isinstance(node, dict):
        return None
    if node.get("type") == "Literal":
        value = node.get("value")
        if isinstance(value, (str, int)):
            return str(value)
        return None
    if node.get("type") == "Identifier":
        name = node.get("name", "")
        if bindings and name in bindings:
            return bindings.get(name)
        return constants.get(name)
    if node.get("type") == "MemberExpression":
        path = _extract_member_path(node) or _resolve_member_lookup_path(node, constants, bindings)
        if not path:
            return None
        if bindings and path in bindings:
            return bindings.get(path)
        return constants.get(path)
    return None


def _build_function_return_table(ast: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Build a minimal helper-return table for declarative semantic matching."""
    function_returns: dict[str, dict[str, Any]] = {}
    for node in _iter_nodes(ast):
        name, params, body_node = _extract_function_body_node(node)
        if not name or body_node is None:
            if node.get("type") == "VariableDeclarator":
                object_name = node.get("id", {}).get("name", "")
                init = node.get("init", {})
                if object_name and isinstance(init, dict):
                    function_returns.update(_extract_object_method_bodies(object_name, init))
            continue
        function_returns[name] = {
            "params": params,
            "body": body_node,
        }
    return function_returns


def _extract_function_body_node(
    node: dict[str, Any],
) -> tuple[str, list[dict[str, Any]], Optional[dict[str, Any]]]:
    """Extract a simple named helper function body."""
    node_type = node.get("type")
    if node_type == "FunctionDeclaration":
        identifier = node.get("id", {})
        name = identifier.get("name", "")
        params = _extract_param_specs(node.get("params", []))
        if name and params is not None:
            return name, params, node.get("body", {})
        return "", [], None

    if node_type != "VariableDeclarator":
        return "", [], None

    identifier = node.get("id", {})
    name = identifier.get("name", "")
    init = node.get("init", {})
    if not name or not isinstance(init, dict):
        return "", [], None

    init_type = init.get("type")
    if init_type not in {"ArrowFunctionExpression", "FunctionExpression"}:
        return "", [], None

    params = _extract_param_specs(init.get("params", []))
    if params is None:
        return "", [], None

    body_node = init.get("body", {})
    if init_type == "ArrowFunctionExpression" and body_node.get("type") != "BlockStatement":
        return name, params, body_node
    return name, params, body_node


def _extract_object_method_bodies(
    prefix: str,
    node: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    """Collect object-literal helper methods under dotted member paths."""
    if node.get("type") != "ObjectExpression" or not prefix:
        return {}

    function_returns: dict[str, dict[str, Any]] = {}
    for prop in node.get("properties", []):
        if not isinstance(prop, dict) or prop.get("type") != "Property":
            continue

        key_name = _extract_property_name(prop.get("key"))
        if not key_name:
            continue

        value = prop.get("value", {})
        path = f"{prefix}.{key_name}"
        params, body_node = _extract_callable_body_node(value)
        if body_node is not None:
            function_returns[path] = {
                "params": params,
                "body": body_node,
            }
            continue

        if isinstance(value, dict) and value.get("type") == "ObjectExpression":
            function_returns.update(_extract_object_method_bodies(path, value))

    return function_returns


def _extract_callable_body_node(
    node: dict[str, Any],
) -> tuple[list[dict[str, Any]], Optional[dict[str, Any]]]:
    """Extract params/body from a function expression or arrow function."""
    if not isinstance(node, dict):
        return [], None

    node_type = node.get("type")
    if node_type not in {"ArrowFunctionExpression", "FunctionExpression"}:
        return [], None

    params = _extract_param_specs(node.get("params", []))
    if params is None:
        return [], None

    body_node = node.get("body", {})
    if node_type == "ArrowFunctionExpression" and body_node.get("type") != "BlockStatement":
        return params, body_node
    return params, body_node


def _extract_param_specs(params: list[Any]) -> Optional[list[dict[str, Any]]]:
    """Extract supported parameter names and defaults for helper resolution."""
    specs: list[dict[str, Any]] = []
    for param in params:
        if not isinstance(param, dict):
            return None
        if param.get("type") == "Identifier":
            specs.append({
                "name": param.get("name", ""),
                "default": None,
            })
            continue
        if param.get("type") == "ObjectPattern":
            specs.append({
                "pattern": param,
                "default": None,
            })
            continue
        if param.get("type") == "ArrayPattern":
            specs.append({
                "pattern": param,
                "default": None,
            })
            continue
        if param.get("type") == "AssignmentPattern":
            left = param.get("left", {})
            right = param.get("right")
            if not isinstance(right, dict):
                return None
            if left.get("type") == "Identifier":
                specs.append({
                    "name": left.get("name", ""),
                    "default": right,
                })
                continue
            if left.get("type") == "ObjectPattern":
                specs.append({
                    "pattern": left,
                    "default": right,
                })
                continue
            if left.get("type") == "ArrayPattern":
                specs.append({
                    "pattern": left,
                    "default": right,
                })
                continue
            return None
            continue
        return None
    return specs


def _extract_return_expression(body_node: dict[str, Any]) -> Optional[dict[str, Any]]:
    """Extract the first returned expression from a block-bodied helper."""
    if body_node.get("type") != "BlockStatement":
        return None
    for statement in body_node.get("body", []):
        if statement.get("type") != "ReturnStatement":
            continue
        argument = statement.get("argument")
        if isinstance(argument, dict):
            return argument
    return None


def _resolve_function_call(
    name: str,
    arguments: list[Any],
    constants: dict[str, str],
    function_returns: dict[str, dict[str, Any]],
    seen: Optional[set[str]] = None,
    bindings: Optional[dict[str, str]] = None,
) -> Optional[str]:
    """Resolve a simple helper call by substituting static string arguments."""
    if not name:
        return None

    function_spec = function_returns.get(name)
    if not function_spec:
        return None

    if seen is None:
        seen = set()
    if name in seen:
        return None

    local_bindings = dict(bindings or {})
    for index, param_spec in enumerate(function_spec.get("params", [])):
        if not _bind_helper_param_spec(
            param_spec,
            arguments[index] if index < len(arguments) else None,
            constants,
            function_returns,
            seen=set(seen),
            bindings=local_bindings,
        ):
            return None

    next_seen = set(seen)
    next_seen.add(name)
    body_node = function_spec.get("body", {})
    if isinstance(body_node, dict) and body_node.get("type") == "BlockStatement":
        return _resolve_block_string_body(
            body_node,
            constants,
            function_returns,
            seen=next_seen,
            bindings=local_bindings,
        )
    return _resolve_string_expr(
        body_node,
        constants,
        function_returns,
        seen=next_seen,
        bindings=local_bindings,
    )


def _resolve_function_object_property_call(
    name: str,
    arguments: list[Any],
    path: str,
    constants: dict[str, str],
    function_returns: dict[str, dict[str, Any]],
    seen: Optional[set[str]] = None,
    bindings: Optional[dict[str, str]] = None,
) -> Optional[str]:
    """Resolve a helper call that returns an object carrying a string-valued property."""
    if not name:
        return None

    function_spec = function_returns.get(name)
    if not function_spec:
        return None

    if seen is None:
        seen = set()
    if name in seen:
        return None

    local_bindings = dict(bindings or {})
    for index, param_spec in enumerate(function_spec.get("params", [])):
        if not _bind_helper_param_spec(
            param_spec,
            arguments[index] if index < len(arguments) else None,
            constants,
            function_returns,
            seen=set(seen),
            bindings=local_bindings,
        ):
            return None

    next_seen = set(seen)
    next_seen.add(name)
    body_node = function_spec.get("body", {})
    if isinstance(body_node, dict) and body_node.get("type") == "BlockStatement":
        return _resolve_block_object_property_body(
            body_node,
            path,
            constants,
            function_returns,
            seen=next_seen,
            bindings=local_bindings,
        )
    return _resolve_object_property_expr(
        body_node,
        path,
        constants,
        function_returns,
        seen=next_seen,
        bindings=local_bindings,
    )


def _resolve_function_object_property_candidates_call(
    name: str,
    arguments: list[Any],
    constants: dict[str, str],
    function_returns: dict[str, dict[str, Any]],
    seen: Optional[set[str]] = None,
    bindings: Optional[dict[str, str]] = None,
) -> dict[str, str]:
    """Resolve a helper call that returns an object carrying string-valued properties."""
    if not name:
        return {}

    function_spec = function_returns.get(name)
    if not function_spec:
        return {}

    if seen is None:
        seen = set()
    if name in seen:
        return {}

    local_bindings = dict(bindings or {})
    for index, param_spec in enumerate(function_spec.get("params", [])):
        if not _bind_helper_param_spec(
            param_spec,
            arguments[index] if index < len(arguments) else None,
            constants,
            function_returns,
            seen=set(seen),
            bindings=local_bindings,
        ):
            return {}

    next_seen = set(seen)
    next_seen.add(name)
    body_node = function_spec.get("body", {})
    if isinstance(body_node, dict) and body_node.get("type") == "BlockStatement":
        return _resolve_block_object_candidates_body(
            body_node,
            constants,
            function_returns,
            seen=next_seen,
            bindings=local_bindings,
        )
    return _resolve_object_property_candidates_expr(
        body_node,
        constants,
        function_returns,
        seen=next_seen,
        bindings=local_bindings,
    )


def _bind_helper_param_spec(
    param_spec: Any,
    argument_node: Any,
    constants: dict[str, str],
    function_returns: dict[str, dict[str, Any]],
    seen: Optional[set[str]] = None,
    bindings: Optional[dict[str, str]] = None,
) -> bool:
    """Bind a supported helper parameter spec into local helper bindings."""
    local_bindings = bindings if bindings is not None else {}
    if not isinstance(param_spec, dict):
        return True

    pattern_node = param_spec.get("pattern")
    default_node = param_spec.get("default")
    effective_node = argument_node if isinstance(argument_node, dict) else default_node

    if isinstance(pattern_node, dict) and pattern_node.get("type") in {"ObjectPattern", "ArrayPattern"}:
        if not isinstance(effective_node, dict):
            return False
        return _bind_pattern_alias_value(
            pattern_node,
            effective_node,
            constants,
            function_returns,
            seen=seen,
            bindings=local_bindings,
        )

    param_name = str(param_spec.get("name") or "").strip()
    if not param_name:
        return True
    if isinstance(argument_node, dict):
        arg_value = _resolve_local_binding_value(
            argument_node,
            constants,
            function_returns,
            seen=seen,
            bindings=local_bindings,
        )
        if arg_value is not None:
            local_bindings[param_name] = arg_value
            return True
    elif isinstance(default_node, dict):
        default_value = _resolve_local_binding_value(
            default_node,
            constants,
            function_returns,
            seen=seen,
            bindings=local_bindings,
        )
        if default_value is not None:
            local_bindings[param_name] = default_value
            return True
    return False


def _resolve_block_string_body(
    body_node: dict[str, Any],
    constants: dict[str, str],
    function_returns: dict[str, dict[str, Any]],
    seen: Optional[set[str]] = None,
    bindings: Optional[dict[str, str]] = None,
) -> Optional[str]:
    """Resolve straight-line block-bodied helpers with local bindings."""
    local_bindings = dict(bindings or {})
    result, did_return = _process_block_statements(
        body_node.get("body", []),
        constants,
        function_returns,
        seen=seen,
        bindings=local_bindings,
    )
    return result if did_return else None


def _resolve_block_object_property_body(
    body_node: dict[str, Any],
    path: str,
    constants: dict[str, str],
    function_returns: dict[str, dict[str, Any]],
    seen: Optional[set[str]] = None,
    bindings: Optional[dict[str, str]] = None,
) -> Optional[str]:
    """Resolve straight-line block-bodied object-return helpers with local bindings."""
    local_bindings = dict(bindings or {})
    result, did_return = _process_block_statements(
        body_node.get("body", []),
        constants,
        function_returns,
        return_path=path,
        seen=seen,
        bindings=local_bindings,
    )
    return result if did_return else None


def _resolve_block_object_candidates_body(
    body_node: dict[str, Any],
    constants: dict[str, str],
    function_returns: dict[str, dict[str, Any]],
    seen: Optional[set[str]] = None,
    bindings: Optional[dict[str, str]] = None,
) -> dict[str, str]:
    """Resolve straight-line block-bodied object-return helpers into dotted property candidates."""
    local_bindings = dict(bindings or {})
    result, did_return = _process_block_object_candidate_statements(
        body_node.get("body", []),
        constants,
        function_returns,
        seen=seen,
        bindings=local_bindings,
    )
    return result if did_return else {}


def _process_block_statements(
    statements: list[Any],
    constants: dict[str, str],
    function_returns: dict[str, dict[str, Any]],
    return_path: Optional[str] = None,
    seen: Optional[set[str]] = None,
    bindings: Optional[dict[str, str]] = None,
) -> tuple[Optional[str], bool]:
    """Process a conservative straight-line subset of helper block statements."""
    local_bindings = bindings if bindings is not None else {}

    for statement in statements:
        if not isinstance(statement, dict):
            continue
        statement_type = statement.get("type")

        if statement_type == "VariableDeclaration":
            for declarator in statement.get("declarations", []):
                _bind_local_declarator(
                    declarator,
                    constants,
                    function_returns,
                    seen=seen,
                    bindings=local_bindings,
                )
            continue

        if statement_type == "ExpressionStatement":
            expression = statement.get("expression", {})
            if expression.get("type") == "AssignmentExpression":
                _apply_local_assignment(
                    expression,
                    constants,
                    function_returns,
                    seen=seen,
                    bindings=local_bindings,
                )
            continue

        if statement_type == "BlockStatement":
            result, did_return = _process_block_statements(
                statement.get("body", []),
                constants,
                function_returns,
                return_path=return_path,
                seen=seen,
                bindings=local_bindings,
            )
            if did_return:
                return result, True
            continue

        if statement_type == "ReturnStatement":
            argument = statement.get("argument")
            if not isinstance(argument, dict):
                return None, True
            if return_path:
                return (
                    _resolve_object_property_expr(
                        argument,
                        return_path,
                        constants,
                        function_returns,
                        seen=seen,
                        bindings=local_bindings,
                    ),
                    True,
                )
            return (
                _resolve_string_expr(
                    argument,
                    constants,
                    function_returns,
                    seen=seen,
                    bindings=local_bindings,
                ),
                True,
            )

    return None, False


def _process_block_object_candidate_statements(
    statements: list[Any],
    constants: dict[str, str],
    function_returns: dict[str, dict[str, Any]],
    seen: Optional[set[str]] = None,
    bindings: Optional[dict[str, str]] = None,
) -> tuple[dict[str, str], bool]:
    """Process a conservative straight-line helper block and return flattened object candidates."""
    local_bindings = bindings if bindings is not None else {}

    for statement in statements:
        if not isinstance(statement, dict):
            continue
        statement_type = statement.get("type")

        if statement_type == "VariableDeclaration":
            for declarator in statement.get("declarations", []):
                _bind_local_declarator(
                    declarator,
                    constants,
                    function_returns,
                    seen=seen,
                    bindings=local_bindings,
                )
            continue

        if statement_type == "ExpressionStatement":
            expression = statement.get("expression", {})
            if expression.get("type") == "AssignmentExpression":
                _apply_local_assignment(
                    expression,
                    constants,
                    function_returns,
                    seen=seen,
                    bindings=local_bindings,
                )
            continue

        if statement_type == "BlockStatement":
            result, did_return = _process_block_object_candidate_statements(
                statement.get("body", []),
                constants,
                function_returns,
                seen=seen,
                bindings=local_bindings,
            )
            if did_return:
                return result, True
            continue

        if statement_type == "ReturnStatement":
            argument = statement.get("argument")
            if not isinstance(argument, dict):
                return {}, True
            return (
                _resolve_object_property_candidates_expr(
                    argument,
                    constants,
                    function_returns,
                    seen=seen,
                    bindings=local_bindings,
                ),
                True,
            )

    return {}, False


def _bind_local_declarator(
    declarator: dict[str, Any],
    constants: dict[str, str],
    function_returns: dict[str, dict[str, Any]],
    seen: Optional[set[str]] = None,
    bindings: Optional[dict[str, str]] = None,
) -> None:
    """Bind supported local declarations into helper-scope bindings."""
    local_bindings = bindings if bindings is not None else {}
    identifier = declarator.get("id", {})
    init = declarator.get("init", {})
    if identifier.get("type") in {"ObjectPattern", "ArrayPattern"}:
        _bind_pattern_alias_value(
            identifier,
            init,
            constants,
            function_returns,
            seen=seen,
            bindings=local_bindings,
        )
        return
    if identifier.get("type") != "Identifier":
        return
    name = identifier.get("name", "")
    if not name or not isinstance(init, dict):
        return

    if init.get("type") == "ObjectExpression":
        _bind_local_object(
            name,
            init,
            constants,
            function_returns,
            seen=seen,
            bindings=local_bindings,
        )
        return
    if init.get("type") == "ArrayExpression":
        _bind_local_array(
            name,
            init,
            constants,
            function_returns,
            seen=seen,
            bindings=local_bindings,
        )
        return
    if _clone_local_object_binding(
        name,
        init,
        constants,
        function_returns,
        seen=seen,
        bindings=local_bindings,
    ):
        return

    value = _resolve_local_binding_value(
        init,
        constants,
        function_returns,
        seen=seen,
        bindings=local_bindings,
    )
    if value is not None:
        local_bindings[name] = value


def _apply_local_assignment(
    assignment: dict[str, Any],
    constants: dict[str, str],
    function_returns: dict[str, dict[str, Any]],
    seen: Optional[set[str]] = None,
    bindings: Optional[dict[str, str]] = None,
) -> None:
    """Apply a supported local assignment into helper-scope bindings."""
    local_bindings = bindings if bindings is not None else {}
    left = assignment.get("left", {})
    if left.get("type") not in {"Identifier", "MemberExpression"}:
        return
    target = (
        left.get("name", "")
        if left.get("type") == "Identifier"
        else _extract_member_path(left) or _resolve_member_lookup_path(left, constants, local_bindings)
    )
    if not target:
        return
    right = assignment.get("right", {})
    if _clone_local_object_binding(
        target,
        right,
        constants,
        function_returns,
        seen=seen,
        bindings=local_bindings,
    ):
        return

    if isinstance(right, dict) and right.get("type") == "ObjectExpression":
        _bind_local_object(
            target,
            right,
            constants,
            function_returns,
            seen=seen,
            bindings=local_bindings,
        )
        return
    if isinstance(right, dict) and right.get("type") == "ArrayExpression":
        _bind_local_array(
            target,
            right,
            constants,
            function_returns,
            seen=seen,
            bindings=local_bindings,
        )
        return

    value = _resolve_local_binding_value(
        right,
        constants,
        function_returns,
        seen=seen,
        bindings=local_bindings,
    )
    if value is not None:
        local_bindings[target] = value


def _bind_local_object(
    prefix: str,
    node: dict[str, Any],
    constants: dict[str, str],
    function_returns: dict[str, dict[str, Any]],
    seen: Optional[set[str]] = None,
    bindings: Optional[dict[str, str]] = None,
) -> None:
    """Flatten a local object literal into helper-scope dotted bindings."""
    local_bindings = bindings if bindings is not None else {}
    if node.get("type") != "ObjectExpression":
        return

    for prop in node.get("properties", []):
        if not isinstance(prop, dict):
            continue
        key_name = _extract_property_name_with_lookup(prop, constants, local_bindings)
        if not key_name:
            continue
        path = f"{prefix}.{key_name}"
        value_node = prop.get("value")
        if isinstance(value_node, dict) and value_node.get("type") == "ObjectExpression":
            _bind_local_object(
                path,
                value_node,
                constants,
                function_returns,
                seen=seen,
                bindings=local_bindings,
            )
            continue
        if isinstance(value_node, dict) and value_node.get("type") == "ArrayExpression":
            _bind_local_array(
                path,
                value_node,
                constants,
                function_returns,
                seen=seen,
                bindings=local_bindings,
            )
            continue
        value = _resolve_local_binding_value(
            value_node,
            constants,
            function_returns,
            seen=seen,
            bindings=local_bindings,
        )
        if value is not None:
            local_bindings[path] = value


def _bind_local_array(
    prefix: str,
    node: dict[str, Any],
    constants: dict[str, str],
    function_returns: dict[str, dict[str, Any]],
    seen: Optional[set[str]] = None,
    bindings: Optional[dict[str, str]] = None,
) -> None:
    """Flatten a local array literal into helper-scope dotted bindings."""
    local_bindings = bindings if bindings is not None else {}
    if node.get("type") != "ArrayExpression":
        return

    for index, element in enumerate(node.get("elements", [])):
        if not isinstance(element, dict):
            continue
        path = f"{prefix}.{index}"
        if element.get("type") == "ObjectExpression":
            _bind_local_object(
                path,
                element,
                constants,
                function_returns,
                seen=seen,
                bindings=local_bindings,
            )
            continue
        if element.get("type") == "ArrayExpression":
            _bind_local_array(
                path,
                element,
                constants,
                function_returns,
                seen=seen,
                bindings=local_bindings,
            )
            continue
        value = _resolve_local_binding_value(
            element,
            constants,
            function_returns,
            seen=seen,
            bindings=local_bindings,
        )
        if value is not None:
            local_bindings[path] = value


def _resolve_local_binding_value(
    node: Any,
    constants: dict[str, str],
    function_returns: dict[str, dict[str, Any]],
    seen: Optional[set[str]] = None,
    bindings: Optional[dict[str, str]] = None,
) -> Optional[str]:
    """Resolve a helper-scope local binding value used for straight-line blocks."""
    if not isinstance(node, dict):
        return None
    if node.get("type") == "Literal" and isinstance(node.get("value"), int):
        return str(node.get("value"))
    return _resolve_string_expr(
        node,
        constants,
        function_returns,
        seen=seen,
        bindings=bindings,
    )


def _resolve_object_property_candidates_expr(
    node: Any,
    constants: dict[str, str],
    function_returns: Optional[dict[str, dict[str, Any]]] = None,
    seen: Optional[set[str]] = None,
    bindings: Optional[dict[str, str]] = None,
) -> dict[str, str]:
    """Resolve all string-valued dotted properties from an object-like expression."""
    if not isinstance(node, dict):
        return {}

    node_type = node.get("type")
    if node_type == "ObjectExpression":
        return _extract_object_string_values(
            "",
            node,
            constants,
            function_returns,
            seen=seen,
            bindings=bindings,
        )
    if node_type == "ArrayExpression":
        return _extract_array_string_values(
            "",
            node,
            constants,
            function_returns,
            seen=seen,
            bindings=bindings,
        )
    if node_type == "CallExpression" and node.get("callee", {}).get("type") == "Identifier":
        return _resolve_function_object_property_candidates_call(
            node.get("callee", {}).get("name", ""),
            node.get("arguments", []),
            constants,
            function_returns or {},
            seen=seen,
            bindings=bindings,
        )
    if node_type == "CallExpression" and node.get("callee", {}).get("type") == "MemberExpression":
        return _resolve_function_object_property_candidates_call(
            _extract_member_path(node.get("callee", {})) or "",
            node.get("arguments", []),
            constants,
            function_returns or {},
            seen=seen,
            bindings=bindings,
        )

    base_path = _extract_member_path(node) or _resolve_member_lookup_path(node, constants, bindings)
    if not base_path:
        return {}

    flattened = {**constants, **(bindings or {})}
    prefix = f"{base_path}."
    candidates: dict[str, str] = {}
    for key, value in flattened.items():
        if not isinstance(key, str) or not key.startswith(prefix) or value in {None, ""}:
            continue
        candidates[key[len(prefix):]] = value
    return candidates


def _clone_local_object_binding(
    target: str,
    value_node: Any,
    constants: dict[str, str],
    function_returns: dict[str, dict[str, Any]],
    seen: Optional[set[str]] = None,
    bindings: Optional[dict[str, str]] = None,
) -> bool:
    """Clone flattened object-property bindings into a helper-local alias when possible."""
    if not target or not isinstance(value_node, dict):
        return False

    source_path = _extract_member_path(value_node) or _resolve_member_lookup_path(
        value_node,
        constants,
        bindings,
    )
    if not source_path:
        return False

    local_bindings = bindings if bindings is not None else {}
    cloned = False
    prefix = f"{source_path}."
    for key, value in {**constants, **local_bindings}.items():
        if not isinstance(key, str) or not key.startswith(prefix) or value in {None, ""}:
            continue
        suffix = key[len(source_path):]
        local_bindings[f"{target}{suffix}"] = value
        cloned = True
    return cloned


def _bind_object_pattern_aliases(
    pattern: Any,
    init: Any,
    constants: dict[str, str],
    function_returns: Optional[dict[str, dict[str, Any]]] = None,
    seen: Optional[set[str]] = None,
    bindings: Optional[dict[str, str]] = None,
) -> bool:
    """Bind object-destructuring aliases into constant or helper bindings."""
    local_bindings = bindings if bindings is not None else {}
    if not isinstance(pattern, dict) or pattern.get("type") != "ObjectPattern":
        return False
    if not isinstance(init, dict):
        return False

    bound_any = False
    if init.get("type") == "ObjectExpression":
        flattened_init_values = _resolve_object_property_candidates_expr(
            init,
            constants,
            function_returns or {},
            seen=seen,
            bindings=local_bindings,
        )
        for prop in pattern.get("properties", []):
            if not isinstance(prop, dict) or prop.get("type") != "Property":
                continue
            key_name = _extract_property_name(prop.get("key"))
            if not key_name:
                continue
            value_node = _find_object_property_value(
                init,
                key_name,
                constants=constants,
                bindings=local_bindings,
            )
            if _bind_pattern_alias_value(
                prop.get("value"),
                value_node,
                constants,
                function_returns or {},
                seen=seen,
                bindings=local_bindings,
            ):
                bound_any = True
                continue
            if _bind_pattern_alias_path(
                prop.get("value"),
                key_name,
                flattened_init_values,
                local_bindings,
                function_returns=function_returns,
                seen=seen,
            ):
                bound_any = True
        return bound_any

    source_path = _extract_member_path(init) or _resolve_member_lookup_path(
        init,
        constants,
        local_bindings,
    )
    if not source_path:
        return False

    for prop in pattern.get("properties", []):
        if not isinstance(prop, dict) or prop.get("type") != "Property":
            continue
        key_name = _extract_property_name(prop.get("key"))
        if not key_name:
            continue
        property_path = f"{source_path}.{key_name}"
        if _bind_pattern_alias_path(
            prop.get("value"),
            property_path,
            constants,
            local_bindings,
            function_returns=function_returns,
            seen=seen,
        ):
            bound_any = True

    return bound_any


def _bind_array_pattern_aliases(
    pattern: Any,
    init: Any,
    constants: dict[str, str],
    function_returns: Optional[dict[str, dict[str, Any]]] = None,
    seen: Optional[set[str]] = None,
    bindings: Optional[dict[str, str]] = None,
) -> bool:
    """Bind array-destructuring aliases into constant or helper bindings."""
    local_bindings = bindings if bindings is not None else {}
    if not isinstance(pattern, dict) or pattern.get("type") != "ArrayPattern":
        return False
    if not isinstance(init, dict):
        return False

    bound_any = False
    if init.get("type") == "ArrayExpression":
        elements = init.get("elements", [])
        for index, element_pattern in enumerate(pattern.get("elements", [])):
            if not isinstance(element_pattern, dict):
                continue
            if _bind_pattern_alias_value(
                element_pattern,
                elements[index] if index < len(elements) else None,
                constants,
                function_returns or {},
                seen=seen,
                bindings=local_bindings,
            ):
                bound_any = True
        return bound_any

    source_path = _extract_member_path(init) or _resolve_member_lookup_path(
        init,
        constants,
        local_bindings,
    )
    if not source_path:
        return False

    for index, element_pattern in enumerate(pattern.get("elements", [])):
        if not isinstance(element_pattern, dict):
            continue
        property_path = f"{source_path}.{index}"
        if _bind_pattern_alias_path(
            element_pattern,
            property_path,
            constants,
            local_bindings,
            function_returns=function_returns,
            seen=seen,
        ):
            bound_any = True
    return bound_any


def _normalize_pattern_node(node: Any) -> Optional[dict[str, Any]]:
    """Unwrap destructuring-assignment nodes to the effective binding pattern."""
    if not isinstance(node, dict):
        return None
    if node.get("type") == "AssignmentPattern":
        left = node.get("left")
        return left if isinstance(left, dict) else None
    return node


def _extract_pattern_default_node(node: Any) -> Optional[dict[str, Any]]:
    """Extract a destructuring default value when one is present."""
    if not isinstance(node, dict):
        return None
    if node.get("type") != "AssignmentPattern":
        return None
    right = node.get("right")
    return right if isinstance(right, dict) else None


def _bind_pattern_alias_value(
    pattern_node: Any,
    value_node: Any,
    constants: dict[str, str],
    function_returns: dict[str, dict[str, Any]],
    seen: Optional[set[str]] = None,
    bindings: Optional[dict[str, str]] = None,
) -> bool:
    """Bind an identifier or nested object-pattern from a concrete AST value node."""
    local_bindings = bindings if bindings is not None else {}
    default_node = _extract_pattern_default_node(pattern_node)
    if not isinstance(value_node, dict):
        value_node = default_node
    if not isinstance(value_node, dict):
        return False
    pattern = _normalize_pattern_node(pattern_node)
    if not isinstance(pattern, dict):
        return False

    if pattern.get("type") == "ObjectPattern":
        return _bind_object_pattern_aliases(
            pattern,
            value_node,
            constants,
            function_returns,
            seen=seen,
            bindings=local_bindings,
        )
    if pattern.get("type") == "ArrayPattern":
        return _bind_array_pattern_aliases(
            pattern,
            value_node,
            constants,
            function_returns,
            seen=seen,
            bindings=local_bindings,
        )

    target_name = _extract_pattern_target_name(pattern)
    if not target_name:
        return False

    if value_node.get("type") == "ObjectExpression":
        _bind_local_object(
            target_name,
            value_node,
            constants,
            function_returns,
            seen=seen,
            bindings=local_bindings,
        )
        return True
    if value_node.get("type") == "ArrayExpression":
        _bind_local_array(
            target_name,
            value_node,
            constants,
            function_returns,
            seen=seen,
            bindings=local_bindings,
        )
        return True

    source_path = _extract_member_path(value_node) or _resolve_member_lookup_path(
        value_node,
        constants,
        local_bindings,
    )
    if source_path:
        return _bind_pattern_alias_path(
            pattern,
            source_path,
            constants,
            local_bindings,
            function_returns=function_returns,
            seen=seen,
        )

    value = _resolve_string_expr(
        value_node,
        constants,
        function_returns,
        seen=seen,
        bindings=local_bindings,
    )
    if value is None:
        return False
    local_bindings[target_name] = value
    return True


def _bind_pattern_alias_path(
    pattern_node: Any,
    source_path: str,
    constants: dict[str, str],
    bindings: dict[str, str],
    function_returns: Optional[dict[str, dict[str, Any]]] = None,
    seen: Optional[set[str]] = None,
) -> bool:
    """Bind an identifier or nested object-pattern from a flattened dotted source path."""
    default_node = _extract_pattern_default_node(pattern_node)
    pattern = _normalize_pattern_node(pattern_node)
    if not isinstance(pattern, dict) or not source_path:
        return False

    if pattern.get("type") == "ObjectPattern":
        bound_any = False
        for prop in pattern.get("properties", []):
            if not isinstance(prop, dict) or prop.get("type") != "Property":
                continue
            key_name = _extract_property_name(prop.get("key"))
            if not key_name:
                continue
            property_path = f"{source_path}.{key_name}"
            if _bind_pattern_alias_path(
                prop.get("value"),
                property_path,
                constants,
                bindings,
                function_returns=function_returns,
                seen=seen,
            ):
                bound_any = True
        return bound_any
    if pattern.get("type") == "ArrayPattern":
        bound_any = False
        for index, element_pattern in enumerate(pattern.get("elements", [])):
            if not isinstance(element_pattern, dict):
                continue
            property_path = f"{source_path}.{index}"
            if _bind_pattern_alias_path(
                element_pattern,
                property_path,
                constants,
                bindings,
                function_returns=function_returns,
                seen=seen,
            ):
                bound_any = True
        return bound_any

    target_name = _extract_pattern_target_name(pattern)
    if not target_name:
        return False
    bound_any = _clone_flattened_binding_prefix(target_name, source_path, constants, bindings)
    value = bindings.get(source_path)
    if value is None:
        value = constants.get(source_path)
    if value is None:
        if isinstance(default_node, dict) and _bind_pattern_alias_value(
            pattern,
            default_node,
            constants,
            function_returns or {},
            seen=seen,
            bindings=bindings,
        ):
            return True
        return bound_any
    bindings[target_name] = value
    return True


def _clone_flattened_binding_prefix(
    target: str,
    source_path: str,
    constants: dict[str, str],
    bindings: dict[str, str],
) -> bool:
    """Clone flattened dotted bindings from one prefix to another."""
    if not target or not source_path:
        return False
    merged = {**constants, **bindings}
    prefix = f"{source_path}."
    cloned = False
    for key, value in merged.items():
        if not isinstance(key, str) or not key.startswith(prefix) or value in {None, ""}:
            continue
        suffix = key[len(source_path):]
        bindings[f"{target}{suffix}"] = value
        cloned = True
    return cloned


def _find_object_property_value(
    node: Any,
    key_name: str,
    constants: Optional[dict[str, str]] = None,
    bindings: Optional[dict[str, str]] = None,
) -> Optional[dict[str, Any]]:
    """Find a direct object-literal property value by key name."""
    if not isinstance(node, dict) or node.get("type") != "ObjectExpression":
        return None
    for prop in reversed(node.get("properties", [])):
        if not isinstance(prop, dict):
            continue
        if prop.get("type") == "SpreadElement":
            argument = prop.get("argument")
            spread_value = _find_object_property_value(
                argument,
                key_name,
                constants=constants,
                bindings=bindings,
            )
            if isinstance(spread_value, dict):
                return spread_value
            continue
        if _extract_property_name_with_lookup(prop, constants, bindings) != key_name:
            continue
        value = prop.get("value")
        return value if isinstance(value, dict) else None
    return None


def _extract_pattern_target_name(node: Any) -> str:
    """Extract a simple local target name from a destructuring pattern node."""
    if not isinstance(node, dict):
        return ""
    node_type = node.get("type")
    if node_type == "Identifier":
        return str(node.get("name") or "").strip()
    if node_type == "AssignmentPattern":
        return _extract_pattern_target_name(node.get("left"))
    return ""


def _extract_property_name(node: Any) -> Optional[str]:
    """Extract a static property name from an object-property key node."""
    if not isinstance(node, dict):
        return None
    if node.get("type") == "Identifier":
        return node.get("name")
    if node.get("type") == "Literal" and isinstance(node.get("value"), (str, int)):
        return str(node.get("value"))
    return None


def _extract_property_name_with_lookup(
    prop: Any,
    constants: Optional[dict[str, str]] = None,
    bindings: Optional[dict[str, str]] = None,
) -> Optional[str]:
    """Extract a property name, including constant-key computed object literals."""
    if not isinstance(prop, dict) or prop.get("type") != "Property":
        return None
    if prop.get("computed"):
        if constants is None:
            return None
        return _resolve_scalar_expr(prop.get("key"), constants, bindings)
    return _extract_property_name(prop.get("key"))


def _iter_object_properties_with_path(
    node: Any,
    ast_path: str,
    prefix: str = "",
    constants: Optional[dict[str, str]] = None,
    bindings: Optional[dict[str, str]] = None,
) -> Iterator[tuple[dict[str, Any], str, str]]:
    """Yield nested object-literal properties with stable AST and property paths."""
    if not isinstance(node, dict) or node.get("type") != "ObjectExpression":
        return

    for index, prop in enumerate(node.get("properties", [])):
        if not isinstance(prop, dict) or prop.get("type") != "Property":
            continue
        key_name = _extract_property_name_with_lookup(prop, constants, bindings)
        if not key_name:
            continue
        property_path = f"{prefix}.{key_name}" if prefix else key_name
        property_ast_path = f"{ast_path}.properties[{index}]"
        yield prop, property_path, property_ast_path

        value = prop.get("value")
        if isinstance(value, dict) and value.get("type") == "ObjectExpression":
            yield from _iter_object_properties_with_path(
                value,
                f"{property_ast_path}.value",
                property_path,
                constants=constants,
                bindings=bindings,
            )


def _build_property_path_map(
    node: Any,
    constants: Optional[dict[str, str]] = None,
    bindings: Optional[dict[str, str]] = None,
) -> dict[int, str]:
    """Build a lookup from Property node identity to its nested object-literal path."""
    paths: dict[int, str] = {}
    root_path = node.get("type", "root") if isinstance(node, dict) else "root"
    for object_node, object_ast_path in _iter_nodes_with_path(node, root_path):
        if object_node.get("type") != "ObjectExpression":
            continue
        for prop, property_path, _ in _iter_object_properties_with_path(
            object_node,
            object_ast_path,
            constants=constants,
            bindings=bindings,
        ):
            paths.setdefault(id(prop), property_path)
    return paths


def _iter_nodes(node: Any) -> Iterator[dict[str, Any]]:
    """Yield all AST nodes depth-first."""
    if not isinstance(node, dict):
        return
    yield node
    for value in node.values():
        if isinstance(value, dict):
            yield from _iter_nodes(value)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    yield from _iter_nodes(item)


def _iter_nodes_with_path(
    node: Any,
    path: str,
) -> Iterator[tuple[dict[str, Any], str]]:
    """Yield AST nodes depth-first along with a stable path string."""
    if not isinstance(node, dict):
        return
    yield node, path
    for key, value in node.items():
        if isinstance(value, dict):
            yield from _iter_nodes_with_path(value, f"{path}.{key}")
        elif isinstance(value, list):
            for index, item in enumerate(value):
                if isinstance(item, dict):
                    yield from _iter_nodes_with_path(item, f"{path}.{key}[{index}]")


def _get_node_position(node: dict[str, Any]) -> tuple[int, int]:
    """Extract a 1-based line and 0-based column from an AST node."""
    loc = node.get("loc", {})
    start = loc.get("start", {})
    return start.get("line", 0), start.get("column", 0)


def _mask_value(value: str, mask_spec: str) -> str:
    """Apply a declarative mask spec to a field value."""
    pattern = re.fullmatch(r"keep_prefix_(\d+)_suffix_(\d+)", mask_spec or "")
    if pattern:
        prefix = int(pattern.group(1))
        suffix = int(pattern.group(2))
        if len(value) <= prefix + suffix:
            return "*" * len(value)
        return value[:prefix] + "*" * (len(value) - prefix - suffix) + value[-suffix:]
    if mask_spec == "full":
        return "*" * len(value)
    return value


def _offset_to_line_column(source: str, offset: int) -> tuple[int, int]:
    """Convert a source offset to 1-based line and 0-based column."""
    line = source.count("\n", 0, offset) + 1
    last_newline = source.rfind("\n", 0, offset)
    column = offset if last_newline == -1 else offset - last_newline - 1
    return line, column

