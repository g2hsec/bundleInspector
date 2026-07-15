"""
SARIF (Static Analysis Results Interchange Format) reporter.

Generates SARIF v2.1.0 compliant output for integration with
GitHub Code Scanning, Azure DevOps, and other CI/CD tools.
"""

from __future__ import annotations

import json
import re
from typing import Any

from bundleInspector import __version__
from bundleInspector.reporter.base import BaseReporter
from bundleInspector.reporter.redaction import sanitize_report_copy
from bundleInspector.storage.models import (
    Category,
    Finding,
    Report,
    Severity,
)


class SARIFReporter(BaseReporter):
    """
    Generate SARIF v2.1.0 format reports.

    SARIF is the standard format for static analysis results,
    supported by GitHub Code Scanning, Azure DevOps, and many other tools.
    """

    name = "sarif"
    extension = ".sarif"

    # SARIF schema version
    SARIF_VERSION = "2.1.0"
    SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

    # Tool information
    TOOL_NAME = "BundleInspector"
    TOOL_FULL_NAME = "BundleInspector JavaScript Security Analyzer"
    TOOL_INFO_URI = "https://github.com/g2hsec/bundleInspector"

    def __init__(self, mask_secrets: bool = True, secret_visible_chars: int = 4):
        self.mask_secrets = mask_secrets
        self.secret_visible_chars = secret_visible_chars

    def generate(self, report: Report) -> str:
        """Generate SARIF report."""
        fingerprints = {
            finding.id: self._stable_fingerprint(
                finding,
                self._result_rule_id(finding),
            )
            for finding in report.findings
        }
        # DQ-O15: mask on a deep copy so masking never mutates the caller's shared Report in place.
        if self.mask_secrets:
            report = sanitize_report_copy(
                report,
                visible_chars=self.secret_visible_chars,
                honor_existing_mask=False,
            )
        sarif = {
            "$schema": self.SARIF_SCHEMA,
            "version": self.SARIF_VERSION,
            "runs": [self._generate_run(report, fingerprints)],
        }

        return json.dumps(sarif, indent=2, ensure_ascii=False)

    def _generate_run(
        self,
        report: Report,
        fingerprints: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Generate a SARIF run object."""
        return {
            "tool": self._generate_tool(report),
            "invocations": [self._generate_invocation(report)],
            "artifacts": self._generate_artifacts(report),
            "results": self._generate_results(report, fingerprints or {}),
            "taxonomies": self._generate_taxonomies(),
        }

    def _generate_tool(self, report: Report | None = None) -> dict[str, Any]:
        """Generate tool information."""
        return {
            "driver": {
                "name": self.TOOL_NAME,
                "fullName": self.TOOL_FULL_NAME,
                "version": __version__,
                "informationUri": self.TOOL_INFO_URI,
                "rules": self._generate_rules(report),
            }
        }

    def _generate_rules(self, report: Report | None = None) -> list[dict[str, Any]]:
        """Generate rule definitions."""
        rules = [
            {
                "id": "JSFINDER001",
                "name": "HardcodedSecret",
                "shortDescription": {"text": "Hardcoded secret detected"},
                "fullDescription": {
                    "text": "A hardcoded secret such as an API key, password, or token was detected in the JavaScript code."
                },
                "helpUri": f"{self.TOOL_INFO_URI}/docs/rules/secrets",
                "defaultConfiguration": {"level": "error"},
                "properties": {"category": "Security", "tags": ["secret", "credential"]},
            },
            {
                "id": "JSFINDER002",
                "name": "InternalEndpoint",
                "shortDescription": {"text": "Internal endpoint exposed"},
                "fullDescription": {
                    "text": "An internal or debug API endpoint was detected in the JavaScript code."
                },
                "helpUri": f"{self.TOOL_INFO_URI}/docs/rules/endpoints",
                "defaultConfiguration": {"level": "warning"},
                "properties": {"category": "Security", "tags": ["endpoint", "api"]},
            },
            {
                "id": "JSFINDER003",
                "name": "InternalDomain",
                "shortDescription": {"text": "Internal domain reference"},
                "fullDescription": {
                    "text": "A reference to an internal or staging domain was detected."
                },
                "helpUri": f"{self.TOOL_INFO_URI}/docs/rules/domains",
                "defaultConfiguration": {"level": "warning"},
                "properties": {"category": "Security", "tags": ["domain", "infrastructure"]},
            },
            {
                "id": "JSFINDER004",
                "name": "FeatureFlag",
                "shortDescription": {"text": "Feature flag detected"},
                "fullDescription": {
                    "text": "A feature flag or configuration toggle was detected."
                },
                "helpUri": f"{self.TOOL_INFO_URI}/docs/rules/flags",
                "defaultConfiguration": {"level": "note"},
                "properties": {"category": "Information", "tags": ["feature-flag", "config"]},
            },
            {
                "id": "JSFINDER005",
                "name": "DebugCode",
                "shortDescription": {"text": "Debug code detected"},
                "fullDescription": {
                    "text": "Debug code such as console.log or debugger statements was detected."
                },
                "helpUri": f"{self.TOOL_INFO_URI}/docs/rules/debug",
                "defaultConfiguration": {"level": "note"},
                "properties": {"category": "Information", "tags": ["debug", "logging"]},
            },
            {
                "id": "JSFINDER006",
                "name": "DomXssSink",
                "shortDescription": {"text": "DOM-XSS / code-injection sink"},
                "fullDescription": {
                    "text": "A dangerous DOM or code-execution sink (e.g. innerHTML, .html(), document.write, "
                            "eval, new Function) receives a dynamic or attacker-influenced value, enabling DOM-based "
                            "cross-site scripting or code injection."
                },
                "helpUri": f"{self.TOOL_INFO_URI}/docs/rules/sinks",
                "defaultConfiguration": {"level": "error"},
                "properties": {"category": "Security", "tags": ["sink", "xss", "CWE-79"]},
            },
            {
                "id": "JSFINDER007",
                "name": "InsecureFileUpload",
                "shortDescription": {"text": "Client-side file-upload surface"},
                "fullDescription": {
                    "text": "A file-upload surface was detected whose validation is enforced only on the client "
                            "(e.g. an allow-listed extension/MIME check). Such checks are bypassable, so the server "
                            "must re-validate uploaded files to prevent unrestricted file upload."
                },
                "helpUri": f"{self.TOOL_INFO_URI}/docs/rules/uploads",
                "defaultConfiguration": {"level": "warning"},
                "properties": {"category": "Security", "tags": ["upload", "file-upload", "CWE-434"]},
            },
        ]
        defined = {rule["id"] for rule in rules}
        for finding in report.findings if report is not None else []:
            rule_id = self._result_rule_id(finding)
            if rule_id in defined:
                continue
            rules.append({
                "id": rule_id,
                "name": self._custom_rule_name(finding.rule_id),
                "shortDescription": {"text": finding.title or finding.rule_id},
                "fullDescription": {
                    "text": finding.description or f"Finding emitted by rule {finding.rule_id}."
                },
                "defaultConfiguration": {"level": self._severity_to_level(finding.severity)},
                "properties": {
                    "category": finding.category.value,
                    "tags": ["custom-rule", finding.category.value],
                    "sourceRuleId": finding.rule_id,
                },
            })
            defined.add(rule_id)
        return rules

    @staticmethod
    def _custom_rule_name(rule_id: str) -> str:
        parts = re.split(r"[^A-Za-z0-9]+", rule_id)
        return "".join(part[:1].upper() + part[1:] for part in parts if part) or "CustomRule"

    @staticmethod
    def _stable_fingerprint(finding: Any, rule_id: str) -> str:
        """Deterministic per-finding fingerprint from stable content (DQ-O16)."""
        import hashlib
        ev = getattr(finding, "evidence", None)
        key = "|".join(str(x) for x in (
            rule_id,
            getattr(ev, "file_url", "") or "",
            getattr(ev, "file_hash", "") or "",
            getattr(ev, "line", 0) or 0,
            getattr(ev, "column", 0) or 0,
            getattr(finding, "value_type", "") or "",
            getattr(finding, "extracted_value", "") or "",
        ))
        return hashlib.sha256(key.encode("utf-8")).hexdigest()[:32]

    def _generate_invocation(self, report: Report) -> dict[str, Any]:
        """Generate invocation information."""
        errors = [str(e) for e in (getattr(report, "errors", None) or [])]
        warnings = [str(w) for w in (getattr(report, "warnings", None) or [])]
        # DQ-O16: reflect REAL completeness (not unconditionally True) and surface report
        # errors/warnings as execution notifications instead of an empty list.
        completeness = getattr(report, "completeness", None)
        completeness_issues = list(getattr(completeness, "issues", None) or [])
        invocation: dict[str, Any] = {
            "executionSuccessful": not errors and bool(
                getattr(completeness, "is_complete", True)
            ),
            "toolExecutionNotifications": [
                {"level": "error", "message": {"text": e}} for e in errors
            ] + [
                {"level": "warning", "message": {"text": w}} for w in warnings
            ] + [
                {
                    "level": "warning" if issue.retryable else "error",
                    "message": {
                        "text": f"[{issue.stage}:{issue.code}] {issue.message}",
                    },
                    "properties": {"details": issue.details},
                }
                for issue in completeness_issues
            ],
        }
        if report.created_at:
            invocation["startTimeUtc"] = report.created_at.isoformat()
        if report.completed_at:
            invocation["endTimeUtc"] = report.completed_at.isoformat()
        return invocation

    def _generate_artifacts(self, report: Report) -> list[dict[str, Any]]:
        """Generate artifacts (analyzed files)."""
        artifacts = []

        for i, asset in enumerate(report.assets):
            artifact = {
                "location": {
                    "uri": asset.url,
                    "index": i,
                },
                "length": asset.size,
                "mimeType": "application/javascript",
                "hashes": {
                    "sha-256": asset.content_hash,
                },
            }
            artifacts.append(artifact)

        return artifacts

    def _generate_results(
        self,
        report: Report,
        fingerprints: dict[str, str] | None = None,
    ) -> list[dict[str, Any]]:
        """Generate results (findings)."""
        results = []

        for finding in report.findings:
            result = self._finding_to_result(finding, report, fingerprints or {})
            results.append(result)

        return results

    def _finding_to_result(
        self,
        finding: Finding,
        report: Report,
        fingerprints: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Convert a Finding to a SARIF result."""
        # Map finding type to rule ID
        rule_id = self._result_rule_id(finding)

        # Map severity to SARIF level
        level = self._severity_to_level(finding.severity)

        # Build the result
        result = {
            "ruleId": rule_id,
            "level": level,
            "message": {
                "text": finding.title,
            },
            "locations": self._generate_locations(finding, report),
            "fingerprints": {
                # DQ-O16: derive from STABLE content, not the per-run uuid finding.id, so SARIF
                # baselining/dedup is deterministic across runs.
                "primaryLocationLineHash": (fingerprints or {}).get(
                    finding.id,
                    self._stable_fingerprint(finding, rule_id),
                ),
            },
            "properties": {
                "confidence": finding.confidence.value if finding.confidence else "medium",
                "riskTier": finding.risk_tier.value if finding.risk_tier else "P3",
                "riskScore": finding.risk_score,
                "category": finding.category.value if finding.category else "unknown",
                "valueType": finding.value_type,
            },
        }

        related_locations = self._generate_related_locations(finding, report)
        if related_locations:
            result["relatedLocations"] = related_locations

        # Add code flow if snippet is available
        if finding.evidence and (finding.metadata.get("original_snippet") or finding.evidence.snippet):
            code_flows = self._generate_code_flows(finding)
            if code_flows:
                result["codeFlows"] = code_flows

        return result

    def _generate_locations(
        self,
        finding: Finding,
        report: Report,
    ) -> list[dict[str, Any]]:
        """Generate location information for a finding."""
        locations: list[dict[str, Any]] = []

        if not finding.evidence:
            return locations

        # Get artifact index
        artifact_index = None
        for i, asset in enumerate(report.assets):
            if asset.url == finding.evidence.file_url:
                artifact_index = i
                break

        location_uri = finding.evidence.original_file_url or finding.evidence.file_url
        start_line = (
            finding.evidence.original_line
            if finding.evidence.original_line is not None and finding.evidence.original_line > 0
            else finding.evidence.line if finding.evidence.line > 0
            else 1
        )
        original_column = finding.evidence.original_column
        start_column = ((original_column if original_column is not None else finding.evidence.column or 0) + 1)
        snippet_text = finding.metadata.get("original_snippet") or finding.evidence.snippet

        location: dict[str, Any] = {
            "physicalLocation": {
                "artifactLocation": {
                    "uri": location_uri,
                },
                "region": {
                    "startLine": start_line,
                    "startColumn": start_column,
                },
            },
            "message": {
                "text": finding.description or finding.title,
            },
        }

        if artifact_index is not None and location_uri == finding.evidence.file_url:
            location["physicalLocation"]["artifactLocation"]["index"] = artifact_index

        # Add snippet if available
        if snippet_text:
            location["physicalLocation"]["region"]["snippet"] = {
                "text": snippet_text,
            }

        locations.append(location)

        return locations

    def _generate_code_flows(self, finding: Finding) -> list[dict[str, Any]]:
        """Generate code flow for a finding using snippet."""
        snippet = finding.metadata.get("original_snippet") or (finding.evidence.snippet if finding.evidence else "")
        if not finding.evidence or not snippet:
            return []

        # Split snippet into lines
        snippet_lines = snippet.split('\n')
        if not snippet_lines:
            return []

        thread_flow_locations = []
        snippet_start = finding.metadata.get("original_snippet_lines", [0])[0] if finding.metadata.get("original_snippet_lines") else 0
        if not snippet_start:
            snippet_start = finding.evidence.snippet_lines[0] if finding.evidence.snippet_lines else 0
        # Fall back to the finding's own line when snippet_lines is unset (0,0)
        if snippet_start < 1:
            snippet_start = (
                finding.evidence.original_line
                if finding.evidence.original_line is not None and finding.evidence.original_line > 0
                else finding.evidence.line if finding.evidence.line > 0
                else 1
            )
        start_line = snippet_start
        snippet_uri = finding.evidence.original_file_url or finding.evidence.file_url

        for i, line in enumerate(snippet_lines):
            if not line.strip():
                continue

            thread_flow_locations.append({
                "location": {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": snippet_uri,
                        },
                        "region": {
                            "startLine": start_line + i,
                            "snippet": {"text": line},
                        },
                    },
                },
            })

        if not thread_flow_locations:
            return []

        return [{
            "threadFlows": [{
                "locations": thread_flow_locations,
            }],
        }]

    def _generate_related_locations(
        self,
        finding: Finding,
        report: Report,
    ) -> list[dict[str, Any]]:
        """Generate related locations for normalized bundle positions when source maps exist."""
        if not finding.evidence:
            return []
        if not (finding.evidence.original_file_url or finding.evidence.original_line):
            return []

        artifact_index = None
        for i, asset in enumerate(report.assets):
            if asset.url == finding.evidence.file_url:
                artifact_index = i
                break

        related: dict[str, Any] = {
            "id": 1,
            "physicalLocation": {
                "artifactLocation": {
                    "uri": finding.evidence.file_url,
                },
                "region": {
                    "startLine": finding.evidence.line or 1,
                    "startColumn": (finding.evidence.column or 0) + 1,
                },
            },
            "message": {
                "text": "Normalized bundle location",
            },
        }
        if artifact_index is not None:
            related["physicalLocation"]["artifactLocation"]["index"] = artifact_index
        if finding.evidence.snippet:
            related["physicalLocation"]["region"]["snippet"] = {
                "text": finding.evidence.snippet,
            }
        return [related]

    def _generate_taxonomies(self) -> list[dict[str, Any]]:
        """Generate taxonomies (CWE mappings)."""
        return [{
            "name": "CWE",
            "version": "4.9",
            "informationUri": "https://cwe.mitre.org/",
            "taxa": [
                {
                    "id": "CWE-798",
                    "name": "Use of Hard-coded Credentials",
                    "shortDescription": {"text": "Hard-coded credentials in source code"},
                },
                {
                    "id": "CWE-200",
                    "name": "Exposure of Sensitive Information",
                    "shortDescription": {"text": "Information exposure through various means"},
                },
                {
                    "id": "CWE-489",
                    "name": "Active Debug Code",
                    "shortDescription": {"text": "Debug code left in production"},
                },
            ],
        }]

    def _get_rule_id(self, finding: Finding) -> str:
        """Map finding category to rule ID."""
        category_map = {
            Category.SECRET: "JSFINDER001",
            Category.ENDPOINT: "JSFINDER002",
            Category.DOMAIN: "JSFINDER003",
            Category.FLAG: "JSFINDER004",
            Category.DEBUG: "JSFINDER005",
            Category.SINK: "JSFINDER006",
            Category.UPLOAD: "JSFINDER007",
        }

        return category_map.get(finding.category, "JSFINDER002")

    def _result_rule_id(self, finding: Finding) -> str:
        """Preserve built-ins while giving custom rules a distinct, stable SARIF identity."""
        builtin_ids = {
            "secret-detector", "endpoint-detector", "domain-detector", "flag-detector",
            "debug-detector", "sink-detector", "taint", "upload-detector",
        }
        if finding.rule_id in builtin_ids:
            return self._get_rule_id(finding)
        normalized = re.sub(r"[^A-Z0-9._-]+", "-", finding.rule_id.upper()).strip("-._")
        return f"BUNDLEINSPECTOR-{normalized or 'CUSTOM'}"

    def _severity_to_level(self, severity: Severity) -> str:
        """Map BundleInspector severity to SARIF level."""
        severity_map = {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "note",
            Severity.INFO: "note",
        }

        return severity_map.get(severity, "warning")
