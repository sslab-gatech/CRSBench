"""Create temporary CRS registry variants for each CRS/model pair."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from framework.cleanup import Manifest
from framework.config import RunnerConfig, load_crs_env
from framework.errors import FrameworkError


@dataclass(frozen=True)
class CRSVariant:
    name: str
    compose: dict[str, Any]


def slug(value: str) -> str:
    result = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    if not result:
        raise FrameworkError(f"cannot derive a safe name from model {value!r}")
    return result


def _render(
    value: Any,
    *,
    model: str,
    host: str,
    repo_root: Path,
    run_timeout: int,
) -> Any:
    """Resolve the small, explicit placeholder set supported by CRS config."""
    if isinstance(value, str):
        return (
            value.replace("{model}", model)
            .replace("{host}", host)
            .replace("{repo_root}", str(repo_root))
            .replace("{run_timeout}", str(run_timeout))
        )
    if isinstance(value, dict):
        return {
            key: _render(
                item,
                model=model,
                host=host,
                repo_root=repo_root,
                run_timeout=run_timeout,
            )
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [
            _render(
                item,
                model=model,
                host=host,
                repo_root=repo_root,
                run_timeout=run_timeout,
            )
            for item in value
        ]
    return value


def prepare_variants(
    cfg: RunnerConfig,
    repo_root: Path,
    manifest: Manifest,
    *,
    run_timeout: int,
) -> list[CRSVariant]:
    """Create registry/compose variants with values resolved for this run."""
    settings = load_crs_env(cfg.crs_env_file)
    variants: list[CRSVariant] = []
    seen: set[str] = set()
    for crs_name in cfg.crs_names:
        source_path = cfg.registry_dir / f"{crs_name}.yaml"
        if not source_path.is_file():
            raise FrameworkError(f"CRS is not in the registry: {crs_name}")
        try:
            source = yaml.safe_load(source_path.read_text(encoding="utf-8")) or {}
        except (OSError, yaml.YAMLError) as exc:
            raise FrameworkError(
                f"cannot read CRS registry entry {source_path}: {exc}"
            ) from exc
        if not isinstance(source, dict):
            raise FrameworkError(
                f"CRS registry entry must contain a mapping: {source_path}"
            )
        crs_settings = settings.get(crs_name)
        if not isinstance(crs_settings, dict):
            raise FrameworkError(f"no cfg_crs_env entry for CRS: {crs_name}")

        for model in cfg.llm_models:
            variant_name = f"{crs_name}-{slug(model)}"
            if variant_name in seen:
                raise FrameworkError(f"duplicate generated CRS name: {variant_name}")
            seen.add(variant_name)
            target = cfg.registry_dir / f"{variant_name}.yaml"
            if target.exists():
                raise FrameworkError(
                    f"refusing to overwrite CRS registry entry: {target}"
                )
            registry_data = dict(source)
            registry_data["name"] = variant_name
            target.write_text(
                yaml.safe_dump(registry_data, sort_keys=False), encoding="utf-8"
            )
            manifest.add(target)

            compose = {
                key: _render(
                    value,
                    model=model,
                    host=cfg.llm_host,
                    repo_root=repo_root,
                    run_timeout=run_timeout,
                )
                for key, value in crs_settings.items()
                if key not in {"model_env", "url_env"}
            }
            compose.setdefault("num_cores", 8)
            configured_env = compose.get("additional_env") or {}
            if not isinstance(configured_env, dict):
                raise FrameworkError(
                    f"additional_env for CRS {crs_name} must be a mapping"
                )
            additional = dict(configured_env)
            model_env = crs_settings.get("model_env")
            url_env = crs_settings.get("url_env")
            if model_env:
                additional[str(model_env)] = model
            if url_env:
                additional[str(url_env)] = f"{cfg.llm_host}/v1"
            if additional:
                compose["additional_env"] = additional
            variants.append(CRSVariant(variant_name, compose))
    return variants
