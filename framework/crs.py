"""Create temporary CRS registry variants for each selected CRS/model pair."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

import yaml

from framework.config import load_crs_env
from framework.errors import FrameworkError

if TYPE_CHECKING:
    from pathlib import Path

    from framework.cleanup import Manifest
    from framework.config import RunnerConfig

PLACEHOLDER = re.compile(r"\{([^{}]+)\}")


@dataclass(frozen=True)
class CRSVariant:
    name: str
    base_name: str
    additional_env: dict[str, str]


def slug(value: str) -> str:
    result = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    if not result:
        raise FrameworkError(f"cannot derive a safe name from model {value!r}")
    return result


def _render(value: str, *, model: str, host: str, repo_root: Path) -> str:
    replacements = {"model": model, "llm_host": host, "repo_root": str(repo_root)}
    unknown = sorted(set(PLACEHOLDER.findall(value)) - set(replacements))
    if unknown:
        raise FrameworkError(
            f"unknown CRS environment placeholder(s): {', '.join(unknown)}"
        )
    for key, replacement in replacements.items():
        value = value.replace(f"{{{key}}}", replacement)
    if "{" in value or "}" in value:
        raise FrameworkError(f"malformed CRS environment placeholder in {value!r}")
    return value


def prepare_variants(
    cfg: RunnerConfig, repo_root: Path, manifest: Manifest
) -> list[CRSVariant]:
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
        if not isinstance(crs_settings, dict) or set(crs_settings) != {
            "additional_env"
        }:
            raise FrameworkError(
                f"cfg_crs_env entry for {crs_name} must contain only additional_env"
            )
        raw_env = crs_settings["additional_env"]
        if not isinstance(raw_env, dict) or not all(
            isinstance(key, str) and isinstance(value, str)
            for key, value in raw_env.items()
        ):
            raise FrameworkError(
                f"additional_env for CRS {crs_name} must map strings to strings"
            )

        for model in cfg.llm_models:
            variant_name = f"{crs_name}-{slug(model)}"
            if variant_name in seen:
                raise FrameworkError(f"duplicate generated CRS name: {variant_name}")
            seen.add(variant_name)
            target = cfg.registry_dir / f"{variant_name}.yaml"
            registry_data = dict(source)
            registry_data["name"] = variant_name
            rendered_registry = yaml.safe_dump(registry_data, sort_keys=False)
            if target.exists():
                try:
                    existing = target.read_text(encoding="utf-8")
                    existing_data = yaml.safe_load(existing)
                except (OSError, yaml.YAMLError) as exc:
                    raise FrameworkError(
                        f"cannot read existing CRS registry entry {target}: {exc}"
                    ) from exc
                if existing_data != registry_data:
                    raise FrameworkError(
                        f"refusing to overwrite CRS registry entry: {target}"
                    )
            else:
                target.write_text(rendered_registry, encoding="utf-8")
                manifest.add(target)
            rendered_env = {
                key: _render(value, model=model, host=cfg.llm_host, repo_root=repo_root)
                for key, value in raw_env.items()
            }
            variants.append(CRSVariant(variant_name, crs_name, rendered_env))
    return variants
