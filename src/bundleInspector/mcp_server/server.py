"""FastMCP v1 adapter for BundleInspector public report access."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from bundleInspector.config import Config
from bundleInspector.mcp_server.service import MCPService
from bundleInspector.reporter.public_view import PublicPageKind
from bundleInspector.storage.job_repository import JobRepository


def create_server(service: MCPService | None = None) -> Any:
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as exc:
        raise RuntimeError("MCP support requires: pip install 'bundleInspector[mcp]'") from exc

    if service is None:
        config = Config()
        service = MCPService(JobRepository(config.cache_dir))
    mcp = FastMCP("BundleInspector")

    @mcp.tool()
    async def list_jobs(limit: int = 50, cursor: str | None = None) -> dict[str, Any]:
        """List accessible analysis jobs using a revision-bound opaque cursor."""
        return await service.list_jobs(limit=limit, cursor=cursor)

    @mcp.tool()
    async def get_report_page(
        job_id: str,
        page_kind: PublicPageKind = "findings",
        limit: int = 50,
        cursor: str | None = None,
        report_id: str | None = None,
    ) -> dict[str, Any]:
        """Read one allowlisted, redacted, revision-bound report page."""
        return await service.get_report_page(
            job_id,
            report_id=report_id,
            page_kind=page_kind,
            limit=limit,
            cursor=cursor,
        )

    @mcp.tool()
    async def get_job_status(job_id: str) -> dict[str, Any]:
        """Read public lifecycle state for an accessible job."""
        return await service.get_job_status(job_id)

    @mcp.resource(
        "bundleinspector://jobs/{job_id}",
        mime_type="application/json",
    )
    async def job_status_resource(job_id: str) -> str:
        return json.dumps(
            await service.get_job_status(job_id),
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )

    return mcp


def main() -> None:
    parser = argparse.ArgumentParser(description="BundleInspector MCP server")
    parser.add_argument("--cache-dir", type=Path)
    parser.add_argument("--transport", choices=("stdio",), default="stdio")
    args = parser.parse_args()
    repository = JobRepository(args.cache_dir or Config().cache_dir)
    server = create_server(MCPService(repository))
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
