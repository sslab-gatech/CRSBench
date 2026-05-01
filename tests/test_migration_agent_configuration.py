"""Regression tests for migration agent configuration after artifact trimming."""

import asyncio
from pathlib import Path
from types import SimpleNamespace

import pytest
from crsbench.migration.test_sh.generator import ShTestGenerator
from crsbench.migration.vuln_yaml.generator import VulnYamlGenerator


def _path_set(values: object) -> set[Path]:
    return {Path(value) for value in values if value is not None}


def _make_fake_query(reply_text: str, sink: dict[str, object]):
    async def _fake_query(*, prompt, options):
        sink["prompt"] = prompt
        sink["options"] = options
        yield SimpleNamespace(role="assistant", content=reply_text)

    return _fake_query


def test_vuln_yaml_analysis_scopes_access_to_project_and_cpv_dirs(
    monkeypatch, tmp_path: Path
):
    captured: dict[str, object] = {}
    monkeypatch.setattr(
        "crsbench.migration.vuln_yaml.generator.query",
        _make_fake_query(
            "# Vulnerability Analysis for cpv_0\n\n## Summary\n- ok\n",
            captured,
        ),
    )

    project_dir = tmp_path / "project"
    cpv_dir = tmp_path / "cpv"
    project_dir.mkdir()
    cpv_dir.mkdir()

    generator = VulnYamlGenerator(
        litellm_base_url="http://example.test",
        litellm_api_key="test-key",
    )

    analysis, _ = asyncio.run(
        generator.analyze_vulnerability(
            str(project_dir),
            str(cpv_dir),
            "cpv_0",
            "Harness",
        )
    )

    options = captured["options"]
    assert analysis.startswith("# Vulnerability Analysis for cpv_0")
    assert options.allowed_tools == [
        "Read",
        "Grep",
        "Glob",
        "Bash",
        "WebSearch",
        "WebFetch",
    ]
    assert options.setting_sources == []
    assert Path(options.cwd) == project_dir
    assert _path_set(options.add_dirs) == {cpv_dir}
    assert "vuln-yaml-analyzer" not in captured["prompt"]


def test_vuln_yaml_generation_avoids_project_local_settings(monkeypatch):
    captured: dict[str, object] = {}
    monkeypatch.setattr(
        "crsbench.migration.vuln_yaml.generator.query",
        _make_fake_query("id: cpv_0\norigin: synthetic\n", captured),
    )

    generator = VulnYamlGenerator(
        litellm_base_url="http://example.test",
        litellm_api_key="test-key",
    )

    yaml_text, _ = asyncio.run(
        generator.generate_vuln_yaml("# Vulnerability Analysis for cpv_0", "cpv_0", "H")
    )

    options = captured["options"]
    assert yaml_text.startswith("id: cpv_0")
    assert options.allowed_tools == ["Read"]
    assert options.setting_sources == []
    assert options.cwd is None
    assert options.add_dirs == []
    assert "vuln-yaml-generator" not in captured["prompt"]


def test_find_unit_tests_scopes_access_to_project_and_benchmark_dirs(
    monkeypatch, tmp_path: Path
):
    captured: dict[str, object] = {}
    monkeypatch.setattr(
        "crsbench.migration.test_sh.generator.query",
        _make_fake_query("# Unit Test Analysis\n", captured),
    )

    project_dir = tmp_path / "project"
    benchmark_dir = tmp_path / "benchmark"
    project_dir.mkdir()
    benchmark_dir.mkdir()

    generator = ShTestGenerator(
        litellm_base_url="http://example.test",
        litellm_api_key="test-key",
    )

    analysis, _ = asyncio.run(
        generator.find_unit_tests(str(project_dir), str(benchmark_dir))
    )

    options = captured["options"]
    assert analysis.startswith("# Unit Test Analysis")
    assert "Skill" not in options.allowed_tools
    assert options.setting_sources == []
    assert Path(options.cwd) == project_dir
    assert _path_set(options.add_dirs) == {benchmark_dir}
    assert "appropriate skill" not in captured["prompt"]


@pytest.mark.parametrize("with_docker_testing", [False, True])
def test_test_sh_generation_avoids_project_local_settings(
    monkeypatch, tmp_path: Path, with_docker_testing: bool
):
    captured: dict[str, object] = {}
    monkeypatch.setattr(
        "crsbench.migration.test_sh.generator.query",
        _make_fake_query("#!/bin/bash\necho ok\n", captured),
    )

    benchmark_dir = tmp_path / "benchmark"
    benchmark_dir.mkdir()

    generator = ShTestGenerator(
        litellm_base_url="http://example.test",
        litellm_api_key="test-key",
    )

    script, _, _ = asyncio.run(
        generator.generate_test_sh_script(
            "# Unit Test Analysis\n",
            "bench",
            str(benchmark_dir),
            with_docker_testing=with_docker_testing,
        )
    )

    options = captured["options"]
    assert script.startswith("#!/bin/bash")
    assert "Skill" not in options.allowed_tools
    assert options.setting_sources == []
    assert Path(options.cwd) == benchmark_dir
    assert options.add_dirs == []
    assert "appropriate skills" not in captured["prompt"]
    if with_docker_testing:
        assert options.mcp_servers
    else:
        assert not options.mcp_servers


def test_bad_patch_generation_scopes_access_to_project_and_benchmark_dirs(
    monkeypatch, tmp_path: Path
):
    captured: dict[str, object] = {}
    monkeypatch.setattr(
        "crsbench.migration.test_sh.generator.query",
        _make_fake_query("--- a/file\n+++ b/file\n", captured),
    )

    project_dir = tmp_path / "project"
    benchmark_dir = tmp_path / "benchmark"
    project_dir.mkdir()
    benchmark_dir.mkdir()

    generator = ShTestGenerator(
        litellm_base_url="http://example.test",
        litellm_api_key="test-key",
    )

    patch_text, _, _ = asyncio.run(
        generator.generate_bad_patch(
            "# Unit Test Analysis\n",
            str(project_dir),
            str(benchmark_dir),
        )
    )

    options = captured["options"]
    assert patch_text.startswith("--- a/file")
    assert "Skill" not in options.allowed_tools
    assert options.setting_sources == []
    assert Path(options.cwd) == project_dir
    assert _path_set(options.add_dirs) == {benchmark_dir}
    assert "appropriate skill" not in captured["prompt"]
