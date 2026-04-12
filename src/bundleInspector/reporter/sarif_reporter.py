"""
SARIF (Static Analysis Results Interchange Format) reporter.

Generates SARIF v2.1.0 compliant output for integration with
GitHub Code Scanning, Azure DevOps, and other CI/CD tools.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any
from urllib.parse import urlparse

from bundleInspector import __version__
from bundleInspector.reporter.base import BaseReporter
from bundleInspector.storage.models import (
    Category,
    Report,
    Finding,
    Severity,
    Confidence,
    RiskTier,
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

    def generate(self, report: Report) -> str:
        """Generate SARIF report."""
        sarif = {
            "$schema": self.SARIF_SCHEMA,
            "version": self.SARIF_VERSION,
            "runs": [self._generate_run(report)],
        }

        return json.dumps(sarif, indent=2, ensure_ascii=False)

    def _generate_run(self, report: Report) -> dict[str, Any]:
        """Generate a SARIF run object."""
        return {
            "tool": self._generate_tool(),
            "invocations": [self._generate_invocation(report)],
            "artifacts": self._generate_artifacts(report),
            "results": self._generate_results(report),
            "taxonomies": self._generate_taxonomies(),
        }

    def _generate_tool(self) -> dict[str, Any]:
        """Generate tool information."""
        return {
            "driver": {
                "name": self.TOOL_NAME,
                "fullName": self.TOOL_FULL_NAME,
                "version": __version__,
                "informationUri": self.TOOL_INFO_URI,
                "rules": self._generate_rules(),
            }
        }

    def _generate_rules(self) -> list[dict[str, Any]]:
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
        ]
        return rules

    def _generate_invocation(self, report: Report) -> dict[str, Any]:
        """Generate invocation information."""
        invocation: dict[str, Any] = {
            "executionSuccessful": True,
            "toolExecutionNotifications": [],
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

    def _generate_results(self, report: Report) -> list[dict[str, Any]]:
        """Generate results (findings)."""
        results = []

        for finding in report.findings:
            result = self._finding_to_result(finding, report)
            results.append(result)

        return results

    def _finding_to_result(
        self,
        finding: Finding,
        report: Report,
    ) -> dict[str, Any]:
        """Convert a Finding to a SARIF result."""
        # Map finding type to rule ID
        rule_id = self._get_rule_id(finding)

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
                "primaryLocationLineHash": finding.id[:32],
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
        locations = []

        if not finding.evidence:
            return locations

        # Get artifact index
        artifact_index = None
        for i, asset in enumerate(report.assets):
            if asset.url == finding.evidence.file_url:
                artifact_index = i
                break

        location_uri = finding.evidence.original_file_url or finding.evidence.file_url
        start_line = finding.evidence.original_line or finding.evidence.line or 1
        original_column = finding.evidence.original_column
        start_column = ((original_column if original_column is not None else finding.evidence.column or 0) + 1)
        snippet_text = finding.metadata.get("original_snippet") or finding.evidence.snippet

        location = {
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
            snippet_start = finding.evidence.original_line or finding.evidence.line or 1
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

        related = {
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
        }

        return category_map.get(finding.category, "JSFINDER002")

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

