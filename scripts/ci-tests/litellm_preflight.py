#!/usr/bin/env python3
"""LiteLLM preflight checks for CI smoke runs.

Validates runtime env contract for external mode, then checks:
1) liveness endpoint reachability
2) key-management auth (generate -> info -> delete)
3) runtime auth against /models using runtime key
"""

from __future__ import annotations

import argparse

import requests
from crsbench.utils.litellm_env import (
    required_env_errors_for_mode,
    resolve_litellm_runtime_env,
)
from crsbench.utils.litellm_preflight import (
    CheckResult,
    check_tracking_auth as _tracking_auth_check,
)
from crsbench.utils.logger import get_logger

logger = get_logger(__name__)


def _health_check(base_url: str) -> CheckResult:
    try:
        response = requests.get(f"{base_url.rstrip('/')}/health/liveness", timeout=10)
        if response.status_code == 200:
            return CheckResult(ok=True, message="health/liveness returned 200")
        return CheckResult(
            ok=False,
            message=f"health/liveness returned {response.status_code}: {response.text[:200]}",
        )
    except Exception as exc:
        return CheckResult(ok=False, message=f"health/liveness request failed: {exc}")


def _runtime_auth_check(base_url: str, runtime_key: str) -> CheckResult:
    try:
        response = requests.get(
            f"{base_url.rstrip('/')}/models",
            headers={"Authorization": f"Bearer {runtime_key}"},
            timeout=15,
        )
        if response.status_code == 200:
            return CheckResult(
                ok=True, message="runtime auth succeeded against /models"
            )
        return CheckResult(
            ok=False,
            message=f"runtime auth failed on /models ({response.status_code}): {response.text[:200]}",
        )
    except Exception as exc:
        return CheckResult(ok=False, message=f"runtime auth request failed: {exc}")


def main() -> int:
    parser = argparse.ArgumentParser(description="LiteLLM health/auth preflight for CI")
    parser.add_argument("--mode", default="external", choices=["external"])
    parser.add_argument(
        "--require-tracking",
        action="store_true",
        help="Require tracking-control auth check with upstream master key.",
    )
    args = parser.parse_args()

    runtime_env = resolve_litellm_runtime_env(args.mode)
    errors = required_env_errors_for_mode(
        runtime_env, tracking_enabled=args.require_tracking
    )
    if errors:
        logger.error("[litellm-preflight] missing/invalid env contract:")
        for error in errors:
            logger.error(f"  - {error}")
        return 2

    base_url = runtime_env.tracking_base_url
    if not base_url:
        logger.error("[litellm-preflight] no LiteLLM base URL resolved")
        return 2

    results = [_health_check(base_url)]

    runtime_key = runtime_env.api_key or runtime_env.master_key
    if runtime_key:
        results.append(
            _runtime_auth_check(runtime_env.direct_base_url or base_url, runtime_key)
        )
    else:
        results.append(CheckResult(ok=False, message="no runtime key resolved"))

    if args.require_tracking:
        if not runtime_env.master_key:
            results.append(
                CheckResult(ok=False, message="no upstream master key resolved")
            )
        else:
            results.append(_tracking_auth_check(base_url, runtime_env.master_key))

    failed = [result for result in results if not result.ok]
    for result in results:
        status = "PASS" if result.ok else "FAIL"
        log_fn = logger.info if result.ok else logger.error
        log_fn(f"[litellm-preflight] {status}: {result.message}")

    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
