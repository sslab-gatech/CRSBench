"""Stage 2: authenticate to and validate the configured LLM endpoint."""

from __future__ import annotations

import json
import logging  # noqa: TID251 - standalone wrapper uses stdlib logging
import os
import subprocess
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Mapping

from framework.config import RunnerConfig, normalize_host
from framework.errors import FrameworkError

if TYPE_CHECKING:
    from pathlib import Path

log = logging.getLogger(__name__)

HOST_ENV_VAR = "CRSBENCH_LLM_UPSTREAM_BASE_URL"
KEY_ENV_VARS = (
    "CRSBENCH_LLM_UPSTREAM_API_KEY",
    "CRSBENCH_LLM_UPSTREAM_MASTER_KEY",
)
LIST_TIMEOUT = 30.0
PROBE_TIMEOUT = 180.0
PROBE_MAX_TOKENS = 8


@dataclass(frozen=True)
class ProbeResult:
    model: str
    status: int | None
    latency: float
    detail: str = ""

    @property
    def ok(self) -> bool:
        return self.status == 200


def _excerpt(text: str, limit: int = 200) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[:limit] + "..."


def _curl(args: list[str], url: str, timeout: float) -> tuple[int, str]:
    """Run curl and return (http status, body). Raises FrameworkError if unreachable."""
    cmd = [
        "curl",
        "--silent",
        "--show-error",
        "--max-time",
        str(timeout),
        "--write-out",
        "\n%{http_code}",
        *args,
        url,
    ]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout + 10, check=False
        )
    except FileNotFoundError as exc:
        raise FrameworkError("curl is not installed or not on PATH") from exc
    except subprocess.TimeoutExpired as exc:
        raise FrameworkError(f"curl {url} timed out after {timeout}s") from exc
    if proc.returncode != 0:
        raise FrameworkError(
            f"cannot reach {url}: curl exit {proc.returncode}: {_excerpt(proc.stderr)}"
        )
    body, separator, code = proc.stdout.rpartition("\n")
    if not separator:
        raise FrameworkError(f"curl returned no HTTP status for {url}")
    try:
        return int(code), body
    except ValueError as exc:
        raise FrameworkError(f"curl returned an invalid HTTP status for {url}") from exc


def list_models(host: str, api_key: str, timeout: float = LIST_TIMEOUT) -> list[str]:
    """curl {host}/v1/models and return the model ids."""
    url = f"{host}/v1/models"
    status, body = _curl(["-H", f"Authorization: Bearer {api_key}"], url, timeout)
    if status != 200:
        raise FrameworkError(f"curl /v1/models returned {status}: {_excerpt(body)}")
    try:
        entries = json.loads(body)["data"]
        if not isinstance(entries, list):
            raise TypeError("data must be a list")
        models = [entry["id"] for entry in entries]
        if not all(isinstance(model, str) and model for model in models):
            raise TypeError("model ids must be non-empty strings")
        return models
    except (ValueError, KeyError, TypeError) as exc:
        raise FrameworkError(
            f"curl /v1/models returned an unexpected body: {_excerpt(body)}"
        ) from exc


def check_models_available(wanted: tuple[str, ...], available: list[str]) -> None:
    """Exact-match every wanted model against the served ids."""
    served = set(available)
    missing = [model for model in wanted if model not in served]
    if missing:
        raise FrameworkError(
            f"models not served by the endpoint: {missing}; available: {sorted(served)}"
        )


def probe_model(
    host: str, model: str, api_key: str, timeout: float = PROBE_TIMEOUT
) -> ProbeResult:
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": "ping"}],
        "max_tokens": PROBE_MAX_TOKENS,
    }
    start = time.monotonic()
    try:
        status, body = _curl(
            [
                "-H",
                "Content-Type: application/json",
                "-H",
                f"Authorization: Bearer {api_key}",
                "-d",
                json.dumps(payload),
            ],
            f"{host}/v1/chat/completions",
            timeout,
        )
    except FrameworkError as exc:
        return ProbeResult(model, None, time.monotonic() - start, str(exc))
    detail = "" if status == 200 else _excerpt(body)
    return ProbeResult(model, status, time.monotonic() - start, detail)


def probe_models(
    host: str,
    models: tuple[str, ...],
    api_key: str,
    timeout: float = PROBE_TIMEOUT,
) -> list[ProbeResult]:
    """Probe every model (no early exit) and require a 200 from each."""
    results = [probe_model(host, model, api_key, timeout) for model in models]
    for result in results:
        log.info(
            "probe %s: status=%s latency=%.1fs",
            result.model,
            result.status,
            result.latency,
        )
    failed = [r for r in results if not r.ok]
    if failed:
        lines = [f"{r.model}: status={r.status} {r.detail}" for r in failed]
        raise FrameworkError("model probes failed: " + "; ".join(lines))
    return results


def read_dotenv(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise FrameworkError(f"cannot read environment file {path}: {exc}") from exc
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.removeprefix("export ").strip()
        values[key] = value.strip().strip("'\"")
    return values


def effective_environment(
    repo_root: Path, environ: Mapping[str, str] | None = None
) -> dict[str, str]:
    """Mirror CRSBench's final load_dotenv(override=True) precedence."""
    effective = dict(os.environ if environ is None else environ)
    effective.update(read_dotenv(repo_root / ".env"))
    return effective


def check_host_not_overridden(
    host: str, repo_root: Path, environ: Mapping[str, str] | None = None
) -> None:
    """Reject an existing value that would override the configured host."""
    actual = effective_environment(repo_root, environ).get(HOST_ENV_VAR)
    if actual and normalize_host(actual) != host:
        raise FrameworkError(
            f"cfg llm_host ({host}) differs from {HOST_ENV_VAR} ({actual}); "
            "CRSBench would use the latter"
        )


def runtime_credential(
    repo_root: Path, environ: Mapping[str, str] | None = None
) -> str:
    """Resolve the credential CRSBench will hand to OSS-CRS at runtime."""
    effective = effective_environment(repo_root, environ)
    for name in KEY_ENV_VARS:
        value = (effective.get(name) or "").strip()
        if value:
            return value
    names = " or ".join(KEY_ENV_VARS)
    raise FrameworkError(
        f"external LiteLLM mode requires {names} in .env or the environment"
    )


def run_caddy_checks(
    cfg: RunnerConfig,
    repo_root: Path,
) -> None:
    check_host_not_overridden(cfg.llm_host, repo_root)
    api_key = runtime_credential(repo_root)
    available = list_models(cfg.llm_host, api_key)
    check_models_available(cfg.llm_models, available)
    probe_models(cfg.llm_host, cfg.llm_models, api_key)
