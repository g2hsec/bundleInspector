"""The resume signature must reflect the custom-rules CONTENT, not just the file path -- otherwise an
in-place edit of a rules file leaves the signature unchanged and --resume silently reuses a stale
report (the edited/added rules never run)."""

from pathlib import Path

import pytest

from bundleInspector.config import Config
from bundleInspector.core.resume_policy import (
    RESUME_SIGNATURE_KEY,
    RESUME_SIGNATURE_SCHEMA,
    _analysis_engine_fingerprint,
    build_local_resume_signature,
    build_remote_resume_signature,
    checkpoint_matches_resume_signature,
    report_matches_resume_signature,
)
from bundleInspector.storage.models import PipelineCheckpoint, Report


def _cfg_with_rules(path):
    cfg = Config()
    cfg.rules.custom_rules_file = path
    return cfg


def test_local_resume_signature_changes_when_rules_edited_in_place(tmp_path):
    rules = tmp_path / "rules.yml"
    rules.write_text("category: secret\nrules: []\n", encoding="utf-8")
    cfg = _cfg_with_rules(rules)
    sig1 = build_local_resume_signature(cfg, recursive=True, include_json=False)
    rules.write_text("category: secret\nrules:\n  - id: X\n", encoding="utf-8")  # edit, SAME path
    sig2 = build_local_resume_signature(cfg, recursive=True, include_json=False)
    assert sig1 != sig2


def test_local_resume_signature_stable_when_rules_unchanged(tmp_path):
    rules = tmp_path / "rules.yml"
    rules.write_text("category: secret\nrules: []\n", encoding="utf-8")
    cfg = _cfg_with_rules(rules)
    assert (build_local_resume_signature(cfg, recursive=True, include_json=False)
            == build_local_resume_signature(cfg, recursive=True, include_json=False))


def test_remote_resume_signature_reflects_rules_edit(tmp_path):
    rules = tmp_path / "rules.yml"
    rules.write_text("category: secret\nrules: []\n", encoding="utf-8")
    cfg = _cfg_with_rules(rules)
    before = build_remote_resume_signature(cfg)
    rules.write_text("category: secret\nrules:\n  - id: Y\n", encoding="utf-8")
    assert build_remote_resume_signature(cfg) != before


def test_resume_signature_without_custom_rules_is_stable():
    cfg = Config()  # no custom rules -> fingerprint is None, signature deterministic
    assert (build_local_resume_signature(cfg, recursive=True, include_json=False)
            == build_local_resume_signature(cfg, recursive=True, include_json=False))


def test_local_resume_signature_tracks_effective_collection_size_limit():
    config = Config()
    before = build_local_resume_signature(config, recursive=True, include_json=False)

    config.crawler.max_file_size -= 1

    assert build_local_resume_signature(config, recursive=True, include_json=False) != before


def test_local_resume_signature_ignores_unrelated_network_concurrency():
    config = Config()
    before = build_local_resume_signature(config, recursive=True, include_json=False)

    config.crawler.max_concurrent += 1

    assert build_local_resume_signature(config, recursive=True, include_json=False) == before


@pytest.mark.parametrize(
    "analysis_path",
    [
        "collector/local.py",
        "normalizer/sourcemap.py",
        "core/text_decode.py",
        "core/orchestrator.py",
        "storage/models.py",
        "cli.py",
    ],
)
def test_engine_fingerprint_covers_collection_and_local_pipeline(monkeypatch, analysis_path):
    original_read_bytes = Path.read_bytes
    baseline = _analysis_engine_fingerprint()

    def changed_read_bytes(path):
        content = original_read_bytes(path)
        if path.as_posix().endswith(analysis_path):
            return content + b"\n# fingerprint probe"
        return content

    monkeypatch.setattr("pathlib.Path.read_bytes", changed_read_bytes)

    assert _analysis_engine_fingerprint() != baseline


def test_resume_signature_schema_rejects_pre_remediation_generation():
    assert RESUME_SIGNATURE_SCHEMA == 3


def test_report_resume_signature_is_bound_to_expected_job_id():
    report = Report(
        job_id="job-a",
        seed_urls=["https://example.test"],
        config={RESUME_SIGNATURE_KEY: "signature"},
    )

    assert report_matches_resume_signature(
        report,
        expected_job_id="job-a",
        seed_urls=["https://example.test"],
        expected_signature="signature",
    )
    assert not report_matches_resume_signature(
        report,
        expected_job_id="job-b",
        seed_urls=["https://example.test"],
        expected_signature="signature",
    )


def test_checkpoint_resume_signature_is_bound_to_expected_job_id():
    checkpoint = PipelineCheckpoint(
        job_id="job-a",
        seed_urls=["https://example.test"],
        stage="crawl",
        stage_state={RESUME_SIGNATURE_KEY: "signature"},
    )

    assert checkpoint_matches_resume_signature(
        checkpoint,
        expected_job_id="job-a",
        seed_urls=["https://example.test"],
        expected_signature="signature",
    )
    assert not checkpoint_matches_resume_signature(
        checkpoint,
        expected_job_id="job-b",
        seed_urls=["https://example.test"],
        expected_signature="signature",
    )


@pytest.mark.parametrize("suffix", [".mts", ".vue", ".svelte", ".astro", ".map"])
def test_local_resume_signature_tracks_all_local_source_artifacts(tmp_path, suffix):
    config = Config()
    artifact = tmp_path / f"input{suffix}"
    before = build_local_resume_signature(
        config,
        recursive=True,
        include_json=False,
        input_paths=[str(tmp_path)],
    )
    artifact.write_text("first", encoding="utf-8")
    added = build_local_resume_signature(
        config,
        recursive=True,
        include_json=False,
        input_paths=[str(tmp_path)],
    )
    artifact.write_text("second", encoding="utf-8")
    edited = build_local_resume_signature(
        config,
        recursive=True,
        include_json=False,
        input_paths=[str(tmp_path)],
    )
    artifact.unlink()
    removed = build_local_resume_signature(
        config,
        recursive=True,
        include_json=False,
        input_paths=[str(tmp_path)],
    )

    assert before != added
    assert added != edited
    assert removed == before
