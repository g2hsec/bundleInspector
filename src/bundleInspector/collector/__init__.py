"""JS collection module - crawlers and network capture."""

from bundleInspector.collector.base import BaseCollector, JSReference
from bundleInspector.collector.static import StaticCollector
from bundleInspector.collector.headless import HeadlessCollector
from bundleInspector.collector.manifest import ManifestCollector
from bundleInspector.collector.scope import ScopePolicy
from bundleInspector.collector.local import LocalCollector, is_local_path

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

