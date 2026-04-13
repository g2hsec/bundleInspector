"""
API map reconstruction.

Reconstructs full API structure from discovered endpoints,
building a tree of routes with methods, parameters, and domains.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urlparse, parse_qs

from bundleInspector.storage.models import Category, Finding, Report


@dataclass
class APIParameter:
    """An API parameter."""
    name: str
    location: str  # path, query, header, body
    example: str = ""


@dataclass
class APIRoute:
    """A single API route."""
    path: str
    methods: set[str] = field(default_factory=set)
    parameters: list[APIParameter] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)  # file URLs
    children: dict[str, "APIRoute"] = field(default_factory=dict)
    finding_count: int = 0

    def add_method(self, method: str) -> None:
        self.methods.add(method.upper())

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {}
        if self.methods:
            result["methods"] = sorted(self.methods)
        if self.parameters:
            result["parameters"] = [
                {"name": p.name, "in": p.location, **({"example": p.example} if p.example else {})}
                for p in self.parameters
            ]
        if self.sources:
            result["sources"] = sorted(set(self.sources))[:5]
        if self.children:
            result["children"] = {
                k: v.to_dict() for k, v in sorted(self.children.items())
            }
        return result


@dataclass
class APIDomain:
    """API endpoints grouped by domain."""
    domain: str
    base_url: str = ""
    routes: dict[str, APIRoute] = field(default_factory=dict)
    total_endpoints: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "base_url": self.base_url,
            "total_endpoints": self.total_endpoints,
            "routes": {
                k: v.to_dict() for k, v in sorted(self.routes.items())
            },
        }


class APIMapBuilder:
    """
    Build API map from endpoint findings.

    Reconstructs the API structure as a tree:
    domain → path segments → methods/parameters
    """

    def __init__(self):
        self.domains: dict[str, APIDomain] = {}

    def build(self, report: Report) -> dict[str, APIDomain]:
        """Build API map from report findings."""
        self.domains.clear()
        endpoint_findings = [
            f for f in report.findings
            if f.category == Category.ENDPOINT
        ]

        for finding in endpoint_findings:
            self._process_finding(finding)

        # Count totals
        for domain in self.domains.values():
            domain.total_endpoints = self._count_routes(domain.routes)

        return self.domains

    def _process_finding(self, finding: Finding) -> None:
        """Process a single endpoint finding into the API map."""
        value = finding.extracted_value
        if not value:
            return

        # Parse the URL/path
        domain, path, query = self._parse_endpoint(value)
        if not path:
            return

        # Get or create domain
        if domain not in self.domains:
            self.domains[domain] = APIDomain(
                domain=domain,
                base_url=f"https://{domain}" if domain != "(relative)" else "",
            )
        api_domain = self.domains[domain]

        # Extract method from finding metadata
        method = (finding.metadata or {}).get("method", "GET")

        # Normalize path: /api/v1/users/{id} pattern
        normalized_path = self._normalize_path(path)

        # Build route tree
        segments = [s for s in normalized_path.split("/") if s]
        if not segments:
            return
        current_routes = api_domain.routes
        full_path = ""

        for i, segment in enumerate(segments):
            full_path += f"/{segment}"

            if segment not in current_routes:
                current_routes[segment] = APIRoute(path=full_path)

            route = current_routes[segment]

            # Last segment → add method and source info
            if i == len(segments) - 1:
                route.add_method(method)
                route.finding_count += 1
                route.sources.append(finding.evidence.file_url)

                # Extract parameters from normalized path (has {id}, {uuid} placeholders)
                self._extract_parameters(route, normalized_path, query, finding)

            current_routes = route.children

    def _parse_endpoint(self, value: str) -> tuple[str, str, str]:
        """Parse endpoint into (domain, path, query)."""
        # Template literals
        value = re.sub(r'\$\{[^}]*\}', '{param}', value)

        if value.startswith(("http://", "https://", "//")):
            parsed = urlparse(value)
            domain = parsed.netloc or "(relative)"
            return domain, parsed.path or "/", parsed.query
        elif value.startswith("/"):
            # Split path and query string for relative paths
            if "?" in value:
                path, query = value.split("?", 1)
            else:
                path, query = value, ""
            return "(relative)", path, query
        else:
            if "?" in value:
                path, query = value.split("?", 1)
            else:
                path, query = value, ""
            return "(relative)", f"/{path}", query

    def _normalize_path(self, path: str) -> str:
        """Normalize path by replacing IDs with parameter placeholders."""
        segments = path.split("/")
        normalized = []

        for segment in segments:
            if not segment:
                continue

            # Dollar-sign template placeholder
            if segment.startswith("$"):
                normalized.append("{id}")
                continue

            # Already a curly-brace parameter placeholder → preserve it
            if segment.startswith("{"):
                normalized.append(segment)
                continue

            # Pure numeric → likely an ID
            if segment.isdigit():
                normalized.append("{id}")
                continue

            # UUID pattern
            if re.match(
                r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
                segment, re.IGNORECASE
            ):
                normalized.append("{uuid}")
                continue

            # Hex string that looks like an ID (24+ chars)
            if re.match(r'^[0-9a-f]{24,}$', segment, re.IGNORECASE):
                normalized.append("{id}")
                continue

            # FUZZ placeholder
            if segment == "FUZZ":
                normalized.append("{param}")
                continue

            normalized.append(segment)

        return "/" + "/".join(normalized)

    def _extract_parameters(
        self,
        route: APIRoute,
        path: str,
        query: str,
        finding: Finding,
    ) -> None:
        """Extract parameters from endpoint."""
        existing_names = {p.name for p in route.parameters}

        # Path parameters
        for match in re.finditer(r'\{(\w+)\}', path):
            name = match.group(1)
            if name not in existing_names:
                route.parameters.append(APIParameter(
                    name=name, location="path"
                ))
                existing_names.add(name)

        # Query parameters
        if query:
            try:
                params = parse_qs(query)
                for name in params:
                    if name not in existing_names:
                        route.parameters.append(APIParameter(
                            name=name,
                            location="query",
                            example=params[name][0] if params[name] else "",
                        ))
                        existing_names.add(name)
            except Exception:
                pass

    def _count_routes(self, routes: dict[str, APIRoute]) -> int:
        """Count total routes recursively."""
        count = 0
        for route in routes.values():
            if route.methods:
                count += 1
            count += self._count_routes(route.children)
        return count

    def to_tree_string(self) -> str:
        """Generate ASCII tree representation of API map."""
        lines = []

        for domain_name, domain in sorted(self.domains.items()):
            lines.append(f"{domain_name} ({domain.total_endpoints} endpoints)")
            self._tree_routes(domain.routes, lines, prefix="")
            lines.append("")

        return "\n".join(lines)

    def _tree_routes(
        self,
        routes: dict[str, APIRoute],
        lines: list[str],
        prefix: str,
    ) -> None:
        """Build tree lines recursively."""
        items = sorted(routes.items())

        for i, (name, route) in enumerate(items):
            is_last = i == len(items) - 1
            connector = "└── " if is_last else "├── "
            extension = "    " if is_last else "│   "

            # Format: segment [METHODS] (N findings)
            methods_str = ""
            if route.methods:
                methods_str = f" [{', '.join(sorted(route.methods))}]"

            params_str = ""
            if route.parameters:
                param_names = [p.name for p in route.parameters]
                params_str = f" ?{', '.join(param_names)}"

            lines.append(
                f"{prefix}{connector}/{name}{methods_str}{params_str}"
            )

            if route.children:
                self._tree_routes(
                    route.children, lines, prefix + extension
                )

    def to_json(self) -> str:
        """Generate JSON representation."""
        data = {
            name: domain.to_dict()
            for name, domain in sorted(self.domains.items())
        }
        return json.dumps(data, indent=2, ensure_ascii=False)


def build_api_map(report: Report) -> APIMapBuilder:
    """Build API map from report."""
    builder = APIMapBuilder()
    builder.build(report)
    return builder

