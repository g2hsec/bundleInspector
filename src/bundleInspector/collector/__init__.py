"""JS collection module - crawlers and network capture."""

from bundleInspector.collector.base import BaseCollector, JSReference
from bundleInspector.collector.headless import HeadlessCollector
from bundleInspector.collector.local import LocalCollector, is_local_path
from bundleInspector.collector.manifest import ManifestCollector
from bundleInspector.collector.scope import ScopePolicy
from bundleInspector.collector.static import StaticCollector

__all__ = [
    "BaseCollector",
    "JSReference",
    "StaticCollector",
    "HeadlessCollector",
    "ManifestCollector",
    "ScopePolicy",
    "LocalCollector",
    "is_local_path",
]
