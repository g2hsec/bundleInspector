"""
Local file collector.

Collects JavaScript files from local filesystem without network traffic.
"""

from __future__ import annotations

import hashlib
import logging
from collections.abc import AsyncIterator
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlsplit

from bundleInspector.core.security import is_path_safe
from bundleInspector.core.text_decode import decode_js_bytes
from bundleInspector.normalizer.sourcemap import SourceMapResolver
from bundleInspector.parser.language import LanguageHint, language_hint_from_path
from bundleInspector.storage.models import AssetProvenance, AssetSource, JSAsset, LoadMethod

logger = logging.getLogger(__name__)


@dataclass
class LocalCollectionDiagnostic:
    """Bounded coverage diagnostic emitted while extracting local source artifacts."""

    code: str
    reason: str
    affected_count: int = 1


@dataclass(frozen=True)
class _ComponentScript:
    content: str
    attributes: dict[str, str]
    start_line: int
    closed: bool
    truncated: bool


class _BoundedScriptParser(HTMLParser):
    """Extract inline script bodies without retaining the surrounding component markup."""

    def __init__(self, *, max_scripts: int, max_content_chars: int) -> None:
        super().__init__(convert_charrefs=False)
        self.max_scripts = max_scripts
        self.max_content_chars = max_content_chars
        self.scripts: list[_ComponentScript] = []
        self.script_cap_hit = False
        self._active: dict[str, object] | None = None
        self._ignored_script = False
        self._captured_chars = 0

    @staticmethod
    def _attributes(attrs: list[tuple[str, str | None]]) -> dict[str, str]:
        return {
            key.lower(): value or ""
            for key, value in attrs
            if key
        }

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "script" or self._active is not None or self._ignored_script:
            return
        if len(self.scripts) >= self.max_scripts:
            self.script_cap_hit = True
            self._ignored_script = True
            return
        self._active = {
            "attributes": self._attributes(attrs),
            "start_line": self.getpos()[0],
            "chunks": [],
            "truncated": False,
        }

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "script":
            return
        if len(self.scripts) >= self.max_scripts:
            self.script_cap_hit = True
            return
        self.scripts.append(
            _ComponentScript("", self._attributes(attrs), self.getpos()[0], True, False)
        )

    def handle_data(self, data: str) -> None:
        if self._active is None or not data:
            return
        remaining = max(self.max_content_chars - self._captured_chars, 0)
        chunk = data[:remaining]
        chunks = self._active["chunks"]
        if isinstance(chunks, list) and chunk:
            chunks.append(chunk)
        self._captured_chars += len(chunk)
        if len(chunk) < len(data):
            self._active["truncated"] = True

    def handle_entityref(self, name: str) -> None:
        self.handle_data(f"&{name};")

    def handle_charref(self, name: str) -> None:
        self.handle_data(f"&#{name};")

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() != "script":
            return
        if self._ignored_script:
            self._ignored_script = False
            return
        self._finish_active(closed=True)

    def finish(self) -> None:
        self.close()
        self._finish_active(closed=False)

    def _finish_active(self, *, closed: bool) -> None:
        if self._active is None:
            return
        chunks = self._active["chunks"]
        attributes = self._active["attributes"]
        start_line = self._active["start_line"]
        truncated = self._active["truncated"]
        if (
            isinstance(chunks, list)
            and isinstance(attributes, dict)
            and isinstance(start_line, int)
            and isinstance(truncated, bool)
        ):
            self.scripts.append(
                _ComponentScript(
                    "".join(str(chunk) for chunk in chunks),
                    {str(key): str(value) for key, value in attributes.items()},
                    start_line,
                    closed,
                    truncated,
                )
            )
        self._active = None


class LocalCollector:
    """
    Collect JS files from local filesystem.

    Supports single files, directories, and glob patterns.
    """

    JS_EXTENSIONS = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts"}
    COMPONENT_EXTENSIONS = {".vue", ".svelte", ".astro"}
    RELATED_EXTENSIONS = {".map", ".json"}

    MAX_COMPONENT_SCRIPTS = 256
    MAX_COMPONENT_LINE_PADDING = 100_000
    MAX_DIAGNOSTICS = 64

    def __init__(
        self,
        include_source_maps: bool = True,
        include_json: bool = False,
        recursive: bool = True,
        max_file_size_mb: float = 10.0,
        allowed_bases: list[Path] | None = None,
        allow_symlinks: bool = False,
    ):
        """
        Initialize local collector.

        Args:
            include_source_maps: Include .map files
            include_json: Include .json files (for configs)
            recursive: Recursively scan directories
            max_file_size_mb: Maximum file size to process
            allowed_bases: Base directories allowed for traversal (security)
            allow_symlinks: Whether to allow following symlinks
        """
        self.include_source_maps = include_source_maps
        self.include_json = include_json
        self.recursive = recursive
        self.max_file_size = int(max_file_size_mb * 1024 * 1024)
        self.allowed_bases = allowed_bases or []
        self.allow_symlinks = allow_symlinks
        self.diagnostics: list[LocalCollectionDiagnostic] = []

    def _record_diagnostic(self, code: str, reason: str, *, affected_count: int = 1) -> None:
        """Aggregate diagnostics by stable reason while bounding unique diagnostic cardinality."""
        for diagnostic in self.diagnostics:
            if diagnostic.code == code and diagnostic.reason == reason:
                diagnostic.affected_count += affected_count
                return

        if len(self.diagnostics) < self.MAX_DIAGNOSTICS - 1:
            self.diagnostics.append(LocalCollectionDiagnostic(code, reason, affected_count))
            return

        for diagnostic in self.diagnostics:
            if diagnostic.code == "local_diagnostic_cap":
                diagnostic.affected_count += affected_count
                return
        self.diagnostics.append(
            LocalCollectionDiagnostic("local_diagnostic_cap", "unique_diagnostic_cap", affected_count)
        )

    def _validate_path(self, path: Path) -> bool:
        """
        Validate path against allowed bases (path traversal protection).

        Args:
            path: Path to validate

        Returns:
            True if path is safe, False otherwise
        """
        # If no allowed bases configured, allow any path (backwards compat)
        if not self.allowed_bases:
            return True

        is_safe, reason = is_path_safe(
            path,
            self.allowed_bases,
            allow_symlinks=self.allow_symlinks,
        )

        if not is_safe:
            logger.warning(
                f"Path traversal blocked: {path} - {reason}"
            )

        return is_safe

    def _should_include(self, path: Path) -> bool:
        """Check if file should be included."""
        suffix = path.suffix.lower()

        if suffix in self.JS_EXTENSIONS or suffix in self.COMPONENT_EXTENSIONS:
            return True
        if suffix == ".json" and self.include_json:
            return True

        return False

    def _compute_hash(self, content: bytes) -> str:
        """Compute SHA-256 hash of content."""
        return hashlib.sha256(content).hexdigest()

    @staticmethod
    def _script_language(attributes: dict[str, str]) -> tuple[LanguageHint | None, str | None]:
        if attributes.get("src", "").strip():
            return None, "external_script"

        lang = attributes.get("lang", "").strip().lower()
        lang_hints: dict[str, LanguageHint] = {
            "js": "javascript",
            "javascript": "javascript",
            "jsx": "jsx",
            "ts": "typescript",
            "typescript": "typescript",
            "tsx": "tsx",
        }
        if lang:
            hint = lang_hints.get(lang)
            return (hint, None) if hint else (None, "unsupported_script_language")

        media_type = attributes.get("type", "").partition(";")[0].strip().lower()
        type_hints: dict[str, LanguageHint] = {
            "": "javascript",
            "application/ecmascript": "javascript",
            "application/javascript": "javascript",
            "module": "javascript",
            "text/ecmascript": "javascript",
            "text/javascript": "javascript",
            "text/jsx": "jsx",
            "text/typescript": "typescript",
            "text/tsx": "tsx",
        }
        hint = type_hints.get(media_type)
        return (hint, None) if hint else (None, "non_javascript_script_type")

    @staticmethod
    def _hint_extension(hint: LanguageHint) -> str:
        return {
            "javascript": "js",
            "jsx": "jsx",
            "typescript": "ts",
            "tsx": "tsx",
        }[hint]

    def _make_asset(
        self,
        *,
        content: bytes,
        url: str,
        language_hint: LanguageHint | None,
        initiator: str,
        load_context: str,
        provenance_url: str,
        parse_errors: list[str] | None = None,
    ) -> JSAsset:
        content_hash = self._compute_hash(content)
        url_hash = hashlib.sha256(url.encode("utf-8")).hexdigest()[:16]
        return JSAsset(
            id=f"local_{content_hash[:12]}_{url_hash}",
            url=url,
            content=content,
            content_hash=content_hash,
            size=len(content),
            language_hint=language_hint,
            source=AssetSource.LOCAL,
            load_method=LoadMethod.LOCAL_FILE,
            initiator=initiator,
            load_context=load_context,
            is_first_party=True,
            provenance=[
                AssetProvenance(
                    url=provenance_url,
                    initiator=initiator,
                    load_context=load_context,
                    method=LoadMethod.LOCAL_FILE,
                )
            ],
            parse_errors=list(parse_errors or []),
        )

    def _resolve_local_sourcemap_path(
        self,
        reference: str,
        *,
        file_path: Path,
        discovery_root: Path,
    ) -> Path | None:
        try:
            parsed = urlsplit(reference)
        except ValueError:
            return None
        if parsed.scheme or parsed.netloc:
            return None

        relative_text = unquote(parsed.path).replace("\\", "/")
        relative_path = Path(relative_text)
        if not relative_text or relative_path.is_absolute() or relative_path.drive:
            return None
        target = file_path.parent / relative_path
        safe, _ = is_path_safe(target, [discovery_root], allow_symlinks=False)
        if not safe or not self._validate_path(target):
            return None
        try:
            resolved = target.resolve()
        except OSError:
            return None
        if resolved.suffix.lower() != ".map":
            return None
        return resolved

    def _attach_local_sourcemap(
        self,
        asset: JSAsset,
        *,
        source_text: str,
        file_path: Path,
        discovery_root: Path,
        conventional: bool,
    ) -> None:
        if not self.include_source_maps:
            return

        resolver = SourceMapResolver()
        reference = resolver.find_sourcemap_url(source_text)
        if reference and reference.lower().startswith("data:"):
            return

        explicit = bool(reference)
        if reference:
            map_path = self._resolve_local_sourcemap_path(
                reference,
                file_path=file_path,
                discovery_root=discovery_root,
            )
            if map_path is None:
                self._record_diagnostic(
                    "local_sourcemap_blocked",
                    "unsafe_or_unsupported_reference",
                )
                return
        elif conventional:
            candidate = Path(f"{file_path}.map")
            safe, _ = is_path_safe(candidate, [discovery_root], allow_symlinks=False)
            try:
                map_path = candidate.resolve() if safe and self._validate_path(candidate) else None
            except OSError:
                map_path = None
        else:
            map_path = None

        if map_path is None or not map_path.is_file():
            if explicit:
                self._record_diagnostic("local_sourcemap_missing", "referenced_map_missing")
            return

        try:
            map_size = map_path.stat().st_size
            max_map_size = min(self.max_file_size, SourceMapResolver.MAX_SOURCEMAP_BYTES)
            if map_size > max_map_size:
                self._record_diagnostic("local_sourcemap_oversized", "map_size_limit")
                return
            map_content = map_path.read_bytes()
            if len(map_content) > max_map_size:
                self._record_diagnostic("local_sourcemap_oversized", "map_size_limit")
                return
        except (OSError, PermissionError):
            self._record_diagnostic("local_sourcemap_unreadable", "map_read_failed")
            return

        asset.has_sourcemap = True
        asset.sourcemap_url = map_path.as_uri()
        asset.sourcemap_content = map_content
        asset.sourcemap_hash = self._compute_hash(map_content)

    def _bounded_virtual_content(
        self,
        content: str,
        *,
        start_line: int,
        remaining_bytes: int,
    ) -> tuple[bytes, bool]:
        padding_lines = max(start_line - 1, 0)
        padding_truncated = padding_lines > self.MAX_COMPONENT_LINE_PADDING
        padding = "\n" * min(padding_lines, self.MAX_COMPONENT_LINE_PADDING)
        encoded = f"{padding}{content}".encode()
        if len(encoded) <= remaining_bytes:
            return encoded, padding_truncated
        bounded = encoded[:max(remaining_bytes, 0)].decode("utf-8", "ignore").encode()
        return bounded, True

    def _astro_frontmatter(self, source: str) -> tuple[str, int] | None:
        lines = source.splitlines(keepends=True)
        if not lines or lines[0].lstrip("\ufeff").strip() != "---":
            return None
        for index in range(1, len(lines)):
            if lines[index].strip() == "---":
                return "".join(lines[1:index]), 2
        self._record_diagnostic("local_component_malformed", "unclosed_astro_frontmatter")
        return None

    def _collect_component_assets(
        self,
        file_path: Path,
        content_bytes: bytes,
        *,
        discovery_root: Path,
    ) -> list[JSAsset]:
        source = decode_js_bytes(content_bytes)
        file_url = file_path.absolute().as_uri()
        candidates: list[tuple[str, int, LanguageHint, list[str]]] = []

        if file_path.suffix.lower() == ".astro":
            frontmatter = self._astro_frontmatter(source)
            if frontmatter is not None and frontmatter[0].strip():
                candidates.append((frontmatter[0], frontmatter[1], "typescript", []))

        parser = _BoundedScriptParser(
            max_scripts=self.MAX_COMPONENT_SCRIPTS,
            max_content_chars=self.max_file_size,
        )
        try:
            parser.feed(source)
            parser.finish()
        except Exception:
            self._record_diagnostic("local_component_malformed", "html_parser_failed")

        if parser.script_cap_hit:
            self._record_diagnostic("local_component_truncated", "script_count_cap")

        for script in parser.scripts:
            hint, skip_reason = self._script_language(script.attributes)
            if skip_reason:
                self._record_diagnostic("local_component_unsupported", skip_reason)
                continue
            if hint is None or not script.content.strip():
                continue
            errors: list[str] = []
            if not script.closed:
                errors.append("local_component:unclosed_script")
                self._record_diagnostic("local_component_malformed", "unclosed_script")
            if script.truncated:
                errors.append("local_component:script_content_cap")
                self._record_diagnostic("local_component_truncated", "script_content_cap")
            candidates.append((script.content, script.start_line, hint, errors))

        assets: list[JSAsset] = []
        remaining_bytes = self.max_file_size
        for index, (content, start_line, hint, errors) in enumerate(candidates, start=1):
            bounded, truncated = self._bounded_virtual_content(
                content,
                start_line=start_line,
                remaining_bytes=remaining_bytes,
            )
            if truncated:
                if "local_component:virtual_content_cap" not in errors:
                    errors.append("local_component:virtual_content_cap")
                self._record_diagnostic("local_component_truncated", "virtual_content_cap")
            if not bounded.strip():
                continue
            remaining_bytes -= len(bounded)
            extension = self._hint_extension(hint)
            virtual_url = f"{file_url}#bundleinspector-script-{index}.{extension}"
            asset = self._make_asset(
                content=bounded,
                url=virtual_url,
                language_hint=hint,
                initiator=file_url,
                load_context=file_url,
                provenance_url=file_url,
                parse_errors=errors,
            )
            self._attach_local_sourcemap(
                asset,
                source_text=content,
                file_path=file_path,
                discovery_root=discovery_root,
                conventional=False,
            )
            assets.append(asset)
            if remaining_bytes <= 0:
                if index < len(candidates):
                    self._record_diagnostic("local_component_truncated", "virtual_total_cap")
                break
        return assets

    async def _collect_file_assets(
        self,
        file_path: Path,
        *,
        discovery_root: Path | None = None,
    ) -> list[JSAsset]:
        root = discovery_root or file_path.parent
        try:
            if not file_path.exists() or not file_path.is_file():
                return []
            within_root, _ = is_path_safe(
                file_path,
                [root],
                allow_symlinks=self.allow_symlinks,
            )
            if not within_root:
                self._record_diagnostic("local_path_blocked", "discovery_root_escape")
                return []
            file_size = file_path.stat().st_size
            if not self._should_include(file_path):
                return []
            if file_size > self.max_file_size:
                self._record_diagnostic("local_file_oversized", "file_size_limit")
                return []
            content_bytes = file_path.read_bytes()
            if len(content_bytes) > self.max_file_size:
                self._record_diagnostic("local_file_oversized", "file_size_limit")
                return []

            if file_path.suffix.lower() in self.COMPONENT_EXTENSIONS:
                return self._collect_component_assets(
                    file_path,
                    content_bytes,
                    discovery_root=root,
                )

            file_url = file_path.absolute().as_uri()
            asset = self._make_asset(
                content=content_bytes,
                url=file_url,
                language_hint=language_hint_from_path(file_url),
                initiator=str(file_path.parent),
                load_context=file_url,
                provenance_url=file_url,
            )
            self._attach_local_sourcemap(
                asset,
                source_text=decode_js_bytes(content_bytes),
                file_path=file_path,
                discovery_root=root,
                conventional=True,
            )
            return [asset]
        except PermissionError as exc:
            logger.warning("Permission denied reading %s: %s", file_path, exc)
            self._record_diagnostic("local_file_unreadable", "permission_denied")
            return []
        except OSError as exc:
            logger.warning("OS error reading %s: %s", file_path, exc)
            self._record_diagnostic("local_file_unreadable", "filesystem_error")
            return []
        except Exception as exc:
            logger.error("Unexpected error reading %s: %s", file_path, exc)
            self._record_diagnostic("local_file_unreadable", "unexpected_read_failure")
            return []

    async def collect_file(self, file_path: Path) -> JSAsset | None:
        """
        Collect a single JS file.

        Args:
            file_path: Path to the file

        Returns:
            JSAsset or None if file should be skipped
        """
        assets = await self._collect_file_assets(file_path, discovery_root=file_path.parent)
        return assets[0] if assets else None

    async def collect_directory(
        self,
        dir_path: Path,
    ) -> AsyncIterator[JSAsset]:
        """
        Collect JS files from a directory.

        Args:
            dir_path: Path to directory

        Yields:
            JSAsset for each JS file found
        """
        if not dir_path.exists() or not dir_path.is_dir():
            return

        # Validate directory path
        if not self._validate_path(dir_path):
            return

        pattern = "**/*" if self.recursive else "*"

        file_paths = sorted(
            dir_path.glob(pattern),
            key=lambda candidate: candidate.as_posix().casefold(),
        )
        for file_path in file_paths:
            # Validate each file path (protection against symlink attacks)
            if file_path.is_file() and self._validate_path(file_path):
                assets = await self._collect_file_assets(
                    file_path,
                    discovery_root=dir_path,
                )
                for asset in assets:
                    yield asset

    async def collect(
        self,
        paths: list[str | Path],
    ) -> AsyncIterator[JSAsset]:
        """
        Collect JS files from multiple paths.

        Args:
            paths: List of file or directory paths

        Yields:
            JSAsset for each JS file found
        """
        self.diagnostics.clear()
        seen_assets: dict[tuple[str, str, str, str, str], JSAsset] = {}

        def semantic_identity(asset: JSAsset) -> tuple[str, str, str, str, str]:
            """Identity for analysis-equivalent local assets.

            Content alone is insufficient: parser grammar and source-map identity/base change
            findings and original-source attribution. Component virtual sources also retain their
            own URL because their line padding and parent provenance are source-specific.
            """
            inline_map_base = ""
            try:
                reference = SourceMapResolver().find_sourcemap_url(
                    decode_js_bytes(asset.content)
                )
                if reference and reference.lower().startswith("data:"):
                    inline_map_base = asset.url
            except (UnicodeError, ValueError):
                inline_map_base = asset.url

            provenance_urls = {item.url for item in asset.provenance if item.url}
            virtual_source_url = asset.url if asset.url not in provenance_urls else ""
            return (
                asset.content_hash,
                asset.language_hint or "",
                asset.sourcemap_hash or "",
                asset.sourcemap_url or inline_map_base,
                virtual_source_url,
            )

        def register(asset: JSAsset) -> bool:
            identity = semantic_identity(asset)
            existing = seen_assets.get(identity)
            if existing is None:
                seen_assets[identity] = asset
                return True

            provenance = {
                (item.url, item.initiator, item.load_context, item.method.value): item
                for item in (*existing.provenance, *asset.provenance)
            }
            existing.provenance = [provenance[key] for key in sorted(provenance)]
            return False

        for path in paths:
            path = Path(path)

            # Path traversal protection
            if not self._validate_path(path):
                continue

            if path.is_file():
                assets = await self._collect_file_assets(path, discovery_root=path.parent)
                for asset in assets:
                    if register(asset):
                        yield asset

            elif path.is_dir():
                async for asset in self.collect_directory(path):
                    if register(asset):
                        yield asset

            elif "*" in str(path):
                # Handle glob patterns
                path_str = str(path)
                prefix = path_str.split("*")[0]
                # Anchor the glob at the PARENT DIRECTORY of the wildcard, not the raw prefix: a
                # wildcard INSIDE a filename (`dist/vendor*.js`) makes the prefix a partial filename
                # (`dist/vendor`) that is not a real directory, so base_path.exists() was False and
                # NOTHING was collected. Split on the last separator so `dist` is the glob base.
                sep = max(prefix.rfind("/"), prefix.rfind("\\"))
                if sep >= 0:
                    base_path = Path(prefix[:sep] or path_str[0])
                    glob_pattern = path_str[sep + 1:]
                else:
                    base_path = Path(".")
                    glob_pattern = path_str

                # Validate base path of glob pattern
                if not self._validate_path(base_path):
                    continue

                if base_path.exists():
                    file_paths = sorted(
                        base_path.glob(glob_pattern),
                        key=lambda candidate: candidate.as_posix().casefold(),
                    )
                    for file_path in file_paths:
                        # Validate each matched file
                        if file_path.is_file() and self._validate_path(file_path):
                            assets = await self._collect_file_assets(
                                file_path,
                                discovery_root=base_path,
                            )
                            for asset in assets:
                                if register(asset):
                                    yield asset

            else:
                logger.warning("Path does not exist or is not accessible: %s", path)


def is_local_path(path: str) -> bool:
    """
    Check if a path is a local filesystem path (not a URL).

    Args:
        path: Path or URL string

    Returns:
        True if local path, False if URL
    """
    # Check for URL schemes
    if path.startswith(('http://', 'https://', 'file://')):
        return path.startswith('file://')

    # Check if it looks like a path
    p = Path(path)

    # Windows absolute path (C:\...)
    if len(path) > 1 and path[1] == ':':
        return True

    # Unix absolute path (/...)
    if path.startswith('/'):
        return True

    # Relative path that exists
    if p.exists():
        return True

    # Contains path separators and no dots in first segment (likely not a domain)
    if ('/' in path or '\\' in path):
        first_segment = path.split('/')[0].split('\\')[0]
        if '.' not in first_segment:
            return True

    return False
