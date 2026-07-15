"""Explicit performance baseline writer contracts."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts import update_performance_baselines as writer


def _source_result(path: Path, scenarios: object, benchmark: str) -> Path:
    path.write_text(json.dumps({
        "benchmark": benchmark,
        "passed": True,
        "gate_failures": [],
        "measurement_environment": {"source": benchmark},
        "scenarios": scenarios,
    }), encoding="utf-8")
    return path


def _stub_result_validators(monkeypatch: pytest.MonkeyPatch) -> None:
    def validate(payload: dict[str, object], expected: str) -> dict[str, object]:
        if payload.get("benchmark") != expected:
            raise ValueError("benchmark role mismatch")
        if payload.get("passed") is not True or payload.get("gate_failures") != []:
            raise ValueError(f"{expected} source result is not a clean benchmark payload")
        return payload

    monkeypatch.setattr(
        writer,
        "validate_correlator_result",
        lambda payload, **_kwargs: validate(payload, "correlator"),
    )
    monkeypatch.setattr(
        writer,
        "validate_detection_result",
        lambda payload, **_kwargs: validate(payload, "detection"),
    )


def test_writer_uses_only_validated_payload_builders_and_fixed_names(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_result_validators(monkeypatch)
    correlator_result = _source_result(
        tmp_path / "correlator-result.json",
        [{"modules": 80}],
        "correlator",
    )
    detection_result = _source_result(
        tmp_path / "detection-result.json",
        {"modern_parse": {}},
        "detection",
    )
    seen: dict[str, object] = {}

    def correlator_builder(scenarios: object, environment: object) -> dict[str, object]:
        seen["correlator"] = (scenarios, environment)
        return {"validated": "correlator"}

    def detection_builder(scenarios: object, environment: object) -> dict[str, object]:
        seen["detection"] = (scenarios, environment)
        return {"validated": "detection"}

    monkeypatch.setattr(writer, "create_correlator_baseline", correlator_builder)
    monkeypatch.setattr(writer, "create_detection_baseline", detection_builder)

    paths = writer.write_baselines(
        correlator_result,
        detection_result,
        tmp_path / "baselines",
    )

    assert [path.name for path in paths] == ["correlator.json", "detection.json"]
    assert json.loads(paths[0].read_text(encoding="utf-8")) == {"validated": "correlator"}
    assert json.loads(paths[1].read_text(encoding="utf-8")) == {"validated": "detection"}
    assert seen == {
        "correlator": ([{"modules": 80}], {"source": "correlator"}),
        "detection": ({"modern_parse": {}}, {"source": "detection"}),
    }


def test_writer_refuses_existing_pair_without_explicit_replace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_result_validators(monkeypatch)
    correlator_result = _source_result(tmp_path / "correlator-result.json", [], "correlator")
    detection_result = _source_result(tmp_path / "detection-result.json", {}, "detection")
    output_dir = tmp_path / "baselines"
    output_dir.mkdir()
    existing = output_dir / "detection.json"
    existing.write_text('{"reviewed":true}\n', encoding="utf-8")
    monkeypatch.setattr(writer, "create_correlator_baseline", lambda *_args: {})
    monkeypatch.setattr(writer, "create_detection_baseline", lambda *_args: {})

    with pytest.raises(FileExistsError, match="incomplete pair"):
        writer.write_baselines(correlator_result, detection_result, output_dir)

    assert existing.read_text(encoding="utf-8") == '{"reviewed":true}\n'
    assert not (output_dir / "correlator.json").exists()


def test_writer_restores_complete_existing_pair_when_second_promotion_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_result_validators(monkeypatch)
    correlator_result = _source_result(tmp_path / "correlator-result.json", [], "correlator")
    detection_result = _source_result(tmp_path / "detection-result.json", {}, "detection")
    output_dir = tmp_path / "baselines"
    output_dir.mkdir()
    correlator_path = output_dir / "correlator.json"
    detection_path = output_dir / "detection.json"
    correlator_path.write_text('{"old":"correlator"}\n', encoding="utf-8")
    detection_path.write_text('{"old":"detection"}\n', encoding="utf-8")
    monkeypatch.setattr(writer, "create_correlator_baseline", lambda *_args: {"new": "correlator"})
    monkeypatch.setattr(writer, "create_detection_baseline", lambda *_args: {"new": "detection"})
    original_replace = writer.os.replace
    failed = False

    def fail_second_promotion(source: str | Path, destination: str | Path) -> None:
        nonlocal failed
        source_path = Path(source)
        if not failed and source_path.suffix == ".stage" and Path(destination) == detection_path:
            failed = True
            raise OSError("injected second-promotion failure")
        original_replace(source, destination)

    monkeypatch.setattr(writer.os, "replace", fail_second_promotion)

    with pytest.raises(OSError, match="injected"):
        writer.write_baselines(
            correlator_result,
            detection_result,
            output_dir,
            replace=True,
        )

    assert correlator_path.read_text(encoding="utf-8") == '{"old":"correlator"}\n'
    assert detection_path.read_text(encoding="utf-8") == '{"old":"detection"}\n'
    assert list(output_dir.glob(".*.stage")) == []
    assert list(output_dir.glob(".*.backup")) == []


@pytest.mark.parametrize(
    "content",
    [
        '{"passed":true,"passed":true}',
        '{"passed":true,"gate_failures":[],"scenarios":NaN}',
        "[]",
    ],
)
def test_writer_rejects_duplicate_nonfinite_and_nonobject_json(
    tmp_path: Path,
    content: str,
) -> None:
    source = tmp_path / "invalid.json"
    source.write_text(content, encoding="utf-8")

    with pytest.raises(ValueError):
        writer._strict_json(source)


def test_writer_rejects_failed_or_diagnostic_source_payload(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_result_validators(monkeypatch)
    source = tmp_path / "failed.json"
    source.write_text(json.dumps({
        "benchmark": "detection",
        "passed": False,
        "gate_failures": ["PRIVATE_FAILURE_CANARY"],
        "measurement_environment": {"source": "detection"},
        "scenarios": {},
    }), encoding="utf-8")

    with pytest.raises(ValueError, match="not a clean benchmark payload"):
        writer._validated_source(writer._strict_json(source), "detection")


def test_writer_rejects_misrouted_benchmark_role(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_result_validators(monkeypatch)
    source = _source_result(tmp_path / "detection.json", {}, "detection")

    with pytest.raises(ValueError, match="benchmark role mismatch"):
        writer._validated_source(writer._strict_json(source), "correlator")
