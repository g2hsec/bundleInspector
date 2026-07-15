"""Schema-load gate for every shipped user configuration profile."""

from pathlib import Path

import pytest

from bundleInspector.config import Config

REPO_ROOT = Path(__file__).resolve().parents[2]
CONFIG_PATHS = (
    REPO_ROOT / "examples" / "yaml-configs" / "default.yml",
    *sorted((REPO_ROOT / "examples" / "scan-profiles").glob("*.yml")),
)


@pytest.mark.parametrize("path", CONFIG_PATHS, ids=lambda path: path.name)
def test_every_shipped_config_profile_loads_under_current_schema(path: Path) -> None:
    config = Config.from_file(path)

    assert isinstance(config, Config)
