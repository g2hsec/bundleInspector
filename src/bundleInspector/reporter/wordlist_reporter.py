"""
Wordlist generator for fuzzing tools.

Extracts endpoints, paths, parameters, and domains into
wordlists compatible with ffuf, dirsearch, feroxbuster, etc.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse, parse_qs

from bundleInspector.reporter.base import BaseReporter
from bundleInspector.storage.models import Category, Finding, Report


class WordlistReporter(BaseReporter):
    """Generate fuzzing wordlists from findings."""

    name = "wordlist"
    extension = ".txt"

    def __init__(self, mode: str = "all"):
        """
        Args:
            mode: Wordlist mode - 'endpoints', 'paths', 'params',
                  'domains', 'dirs', or 'all'
        """
        self.mode = mode

    def generate(self, report: Report) -> str:
        """Generate wordlist from report."""
        generators = {
            "endpoints": self._extract_endpoints,
            "paths": self._extract_paths,
            "params": self._extract_params,
            "domains": self._extract_domains,
            "dirs": self._extract_dirs,
            "all": self._extract_all,
        }

        generator = generators.get(self.mode, self._extract_all)
        words = generator(report)

        # Sort and deduplicate
        unique = sorted(set(words))
        return "\n".join(unique) + "\n"

    def _extract_all(self, report: Report) -> list[str]:
        """Extract all wordlist items."""
        words = []
        words.extend(self._extract_endpoints(report))
        words.extend(self._extract_paths(report))
        words.extend(self._extract_params(report))
        words.extend(self._extract_domains(report))
        words.extend(self._extract_dirs(report))
        return words

    def _extract_endpoints(self, report: Report) -> list[str]:
        """Extract full endpoint paths."""
        endpoints = []

        for finding in report.findings:
            if finding.category != Category.ENDPOINT:
                continue

            value = finding.extracted_value
            if not value:
                continue

            # Full URLs ??extract path
            if value.startswith(("http://", "https://", "//")):
                parsed = urlparse(value)
                path = parsed.path
                if path and path != "/":
                    # Replace template variables with FUZZ
                    if "${" in path:
                        path = re.sub(r'\$\{[^}]*\}', 'FUZZ', path)
                    endpoints.append(path)
                # Also add with query string if present
                if parsed.query:
                    query_path = path if path else "/"
                    endpoints.append(f"{query_path}?{parsed.query}")
            elif value.startswith("/"):
                if "${" in value:
                    value = re.sub(r'\$\{[^}]*\}', 'FUZZ', value)
                # Add path-only entry if query string present
                if "?" in value:
                    path_only = value.split("?", 1)[0]
                    if path_only and path_only != "/":
                        endpoints.append(path_only)
                endpoints.append(value)
            elif "${" in value:
                # Template literal: /api/v1/${id} ??/api/v1/FUZZ
                cleaned = re.sub(r'\$\{[^}]*\}', 'FUZZ', value)
                if cleaned.startswith("/"):
                    endpoints.append(cleaned)

        return endpoints

    def _extract_paths(self, report: Report) -> list[str]:
        """Extract unique path segments for path fuzzing."""
        paths = set()

        for finding in report.findings:
            if finding.category != Category.ENDPOINT:
                continue

            value = finding.extracted_value
            if not value:
                continue

            # Extract path from URL
            path = value
            if value.startswith(("http://", "https://", "//")):
                parsed = urlparse(value)
                path = parsed.path
            elif "?" in value:
                path = value.split("?", 1)[0]

            if not path or path == "/":
                continue

            # Split into segments
            segments = [s for s in path.split("/") if s]
            for segment in segments:
                # Skip template variables
                if "${" in segment or "{" in segment:
                    continue
                # Skip pure numbers (IDs)
                if segment.isdigit():
                    continue
                # Skip file extensions
                if "." in segment and segment.split(".")[-1] in (
                    "js", "css", "html", "map", "json", "xml", "png", "jpg",
                    "svg", "ico", "woff", "woff2", "ttf", "eot"
                ):
                    continue
                paths.add(segment)

            # Also add progressive path prefixes
            # /api/v1/users ??/api, /api/v1, /api/v1/users
            accumulated = ""
            for segment in segments:
                if "${" in segment or "{" in segment:
                    break
                accumulated += f"/{segment}"
                paths.add(accumulated)

        return list(paths)

    def _extract_params(self, report: Report) -> list[str]:
        """Extract query parameter names and header names."""
        params = set()

        for finding in report.findings:
            if finding.category != Category.ENDPOINT:
                continue
            value = finding.extracted_value
            if not value:
                continue

            # Extract query parameters from URLs
            if "?" in value:
                try:
                    parsed = urlparse(value)
                    query_params = parse_qs(parsed.query)
                    params.update(query_params.keys())
                except Exception:
                    pass

            # Extract parameter names from metadata
            meta = finding.metadata or {}
            if "parameters" in meta:
                params.update(meta["parameters"])

        # Also look for common API parameter patterns in source
        for finding in report.findings:
            if finding.category != Category.ENDPOINT:
                continue
            if finding.evidence.snippet:
                # Match object property patterns: { key: value }
                prop_matches = re.findall(
                    r'["\']?(\w{2,30})["\']?\s*:', finding.evidence.snippet
                )
                for prop in prop_matches:
                    if prop.lower() not in (
                        "type", "value", "function", "return", "const",
                        "let", "var", "if", "else", "for", "while",
                        "method", "headers", "body", "mode", "cache",
                        "credentials", "redirect",
                        "http", "https", "ftp",
                    ):
                        params.add(prop)

        return list(params)

    def _extract_domains(self, report: Report) -> list[str]:
        """Extract discovered domains and subdomains."""
        domains = set()

        for finding in report.findings:
            value = finding.extracted_value
            if not value:
                continue

            # From domain findings
            if finding.category == Category.DOMAIN:
                # Extract domain from value
                domain = self._extract_domain(value)
                if domain:
                    domains.add(domain)

            # From endpoint findings with full URLs
            if finding.category == Category.ENDPOINT:
                if value.startswith(("http://", "https://", "//")):
                    parsed = urlparse(value)
                    if parsed.netloc:
                        # Add full domain
                        domains.add(parsed.netloc)
                        # Add without port
                        host = parsed.netloc.split(":")[0]
                        domains.add(host)

            # From metadata
            meta = finding.metadata or {}
            if "domain" in meta:
                domain = self._extract_domain(meta["domain"])
                if domain:
                    domains.add(domain)

        # Remove empty strings
        domains.discard("")
        return list(domains)

    def _extract_dirs(self, report: Report) -> list[str]:
        """Extract directory paths for directory brute-forcing."""
        dirs = set()

        for finding in report.findings:
            if finding.category != Category.ENDPOINT:
                continue

            value = finding.extracted_value
            if not value:
                continue

            path = value
            if value.startswith(("http://", "https://", "//")):
                parsed = urlparse(value)
                path = parsed.path
            elif "?" in value:
                path = value.split("?", 1)[0]

            if not path or not path.startswith("/"):
                continue

            # Remove trailing filename-like segments
            parts = path.rstrip("/").split("/")
            for i in range(1, len(parts)):
                segment = parts[i]
                # Skip template vars
                if "${" in segment or "{" in segment:
                    break
                dir_path = "/".join(parts[:i + 1])
                if dir_path:
                    dirs.add(dir_path)
                    # Also add without leading slash for relative fuzzing
                    dirs.add(dir_path.lstrip("/"))

        return list(dirs)

    def _extract_domain(self, value: str) -> str:
        """Extract domain from various formats."""
        if value.startswith(("http://", "https://", "//")):
            parsed = urlparse(value)
            return parsed.netloc.split(":")[0]

        # Check if it looks like a domain
        if re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]*\.)+[a-zA-Z]{2,}$', value):
            return value

        return ""


def generate_wordlists(report: Report) -> dict[str, str]:
    """
    Generate all wordlist types from a report.

    Returns:
        Dict mapping wordlist name to content
    """
    wordlists = {}

    modes = ["endpoints", "paths", "params", "domains", "dirs"]
    for mode in modes:
        reporter = WordlistReporter(mode=mode)
        content = reporter.generate(report)
        if content.strip():
            wordlists[mode] = content

    return wordlists

