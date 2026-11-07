"""Bounded LiteLLM key-management probes with secret-free diagnostics."""

from __future__ import annotations

import math
import uuid
from dataclasses import dataclass

import requests

_REQUEST_TIMEOUT = (5, 20)


@dataclass(frozen=True)
class CheckResult:
    ok: bool
    message: str


class _ProbeError(Exception):
    """A probe error whose message is safe to include in reports."""


def _response_data(response: requests.Response, operation: str) -> dict:
    # Response bodies and request URLs can contain keys; never report them.
    status = response.status_code
    if status is None or not 200 <= status < 300:
        raise _ProbeError(f"{operation} returned HTTP {status}")
    data = response.json()
    if not isinstance(data, dict):
        raise _ProbeError(f"{operation} returned a non-object response")
    return data


def check_tracking_auth(
    base_url: str,
    master_key: str,
    *,
    max_budget: float | None = None,
) -> CheckResult:
    """Create, inspect, and delete a temporary key without calling a model.

    A short expiry bounds key lifetime if a response is lost or cleanup fails.
    Failed cleanup makes the probe fail even if key creation succeeded.
    """
    budget = 0.0 if max_budget is None else max_budget
    if not math.isfinite(budget) or budget < 0:
        return CheckResult(
            ok=False, message="LiteLLM probe requires a finite non-negative budget"
        )

    base_url = base_url.rstrip("/")
    headers = {"Authorization": f"Bearer {master_key}"}
    alias = f"crsbench-preflight-{uuid.uuid4().hex}"
    api_key = None
    cleanup_needed = False
    result = CheckResult(
        ok=False, message="LiteLLM key-management probe did not complete"
    )
    operation = "POST /key/generate"
    try:
        # A lost response may still have created the key. Cleanup then uses the
        # unique alias instead of an unknown key value.
        cleanup_needed = True
        response = requests.post(
            f"{base_url}/key/generate",
            headers=headers,
            json={
                "key_alias": alias,
                "key_type": "llm_api",
                "models": [],
                "max_budget": budget,
                "duration": "5m",
                "metadata": {"created_by": "crsbench", "purpose": "preflight"},
            },
            timeout=_REQUEST_TIMEOUT,
            allow_redirects=False,
        )
        cleanup_needed = (
            200 <= response.status_code < 300 or response.status_code >= 500
        )
        data = _response_data(response, operation)
        api_key = data.get("key")
        if not isinstance(api_key, str) or not api_key:
            api_key = None
            raise _ProbeError("POST /key/generate returned no usable key")

        operation = "GET /key/info"
        data = _response_data(
            requests.get(
                f"{base_url}/key/info",
                headers=headers,
                params={"key": api_key},
                timeout=_REQUEST_TIMEOUT,
                allow_redirects=False,
            ),
            operation,
        )
        info = data.get("info")
        actual_budget = info.get("max_budget") if isinstance(info, dict) else None
        if isinstance(actual_budget, bool) or actual_budget is None:
            raise _ProbeError("GET /key/info did not confirm the requested budget")
        if float(actual_budget) != budget:
            raise _ProbeError("GET /key/info did not confirm the requested budget")
        result = CheckResult(
            ok=True, message="Temporary key creation and budget verification passed"
        )
    except _ProbeError as exc:
        result = CheckResult(ok=False, message=str(exc))
    except (requests.RequestException, ValueError, TypeError, OverflowError) as exc:
        result = CheckResult(
            ok=False, message=f"{operation} failed ({type(exc).__name__})"
        )
    finally:
        if cleanup_needed:
            try:
                data = _response_data(
                    requests.post(
                        f"{base_url}/key/delete",
                        headers=headers,
                        json={"keys": [api_key]}
                        if api_key
                        else {"key_aliases": [alias]},
                        timeout=_REQUEST_TIMEOUT,
                        allow_redirects=False,
                    ),
                    "POST /key/delete",
                )
                deleted_keys = data.get("deleted_keys")
                if api_key and (
                    not isinstance(deleted_keys, list) or api_key not in deleted_keys
                ):
                    raise _ProbeError("POST /key/delete did not confirm key deletion")
            except (
                _ProbeError,
                requests.RequestException,
                ValueError,
                TypeError,
            ) as exc:
                detail = (
                    str(exc) if isinstance(exc, _ProbeError) else type(exc).__name__
                )
                result = CheckResult(
                    ok=False,
                    message=f"{result.message}; temporary key cleanup failed "
                    f"({detail}, alias {alias}; 5m expiry requested)",
                )
            else:
                result = CheckResult(
                    ok=result.ok, message=f"{result.message}; temporary key deleted"
                )
    return result
