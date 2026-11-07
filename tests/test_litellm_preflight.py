"""LiteLLM key lifecycle and effective cloud-worker credential checks."""

import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
import requests
from crsbench.cloud.cli._preflight import _litellm_tracking_checks
from crsbench.utils.litellm_preflight import CheckResult, check_tracking_auth


def response(status=200, data=None):
    result = requests.Response()
    result.status_code = status
    result._content = json.dumps(data).encode()
    return result


@pytest.fixture
def api(monkeypatch):
    post = Mock(
        side_effect=[
            response(data={"key": "sk-temporary-secret"}),
            response(data={"deleted_keys": ["sk-temporary-secret"]}),
        ]
    )
    get = Mock(return_value=response(data={"info": {"max_budget": 2.0}}))
    monkeypatch.setattr("crsbench.utils.litellm_preflight.requests.post", post)
    monkeypatch.setattr("crsbench.utils.litellm_preflight.requests.get", get)
    return post, get


def test_tracking_probe_creates_checks_budget_and_deletes_key(api):
    post, get = api

    result = check_tracking_auth(
        "https://remote.example/", "sk-master-secret", max_budget=2
    )

    assert result.ok
    assert "deleted" in result.message
    assert post.call_count == 2
    assert post.call_args_list[0].args == ("https://remote.example/key/generate",)
    payload = post.call_args_list[0].kwargs["json"]
    assert payload["max_budget"] == 2
    assert payload["key_type"] == "llm_api"
    assert payload["duration"] == "5m"
    assert get.call_args.kwargs["params"] == {"key": "sk-temporary-secret"}
    assert post.call_args_list[1].kwargs["json"] == {"keys": ["sk-temporary-secret"]}
    for call in [*post.call_args_list, get.call_args]:
        assert call.kwargs["headers"]["Authorization"] == "Bearer sk-master-secret"
        assert call.kwargs["timeout"] == (5, 20)
        assert call.kwargs["allow_redirects"] is False


def test_tracking_probe_uses_zero_budget_when_no_trial_budget_is_configured(api):
    post, get = api
    get.return_value = response(data={"info": {"max_budget": 0}})

    assert check_tracking_auth("https://remote.example", "master").ok
    assert post.call_args_list[0].kwargs["json"]["max_budget"] == 0


@pytest.mark.parametrize("status", [401, 403, 404, 307])
def test_generation_denied_blocks_without_exposing_response_secrets(api, status):
    post, get = api
    post.side_effect = [response(status, {"error": "sk-master-secret"})]

    result = check_tracking_auth(
        "https://remote.example", "sk-master-secret", max_budget=2
    )

    assert not result.ok
    assert f"HTTP {status}" in result.message
    assert "sk-master-secret" not in result.message
    assert post.call_count == 1
    get.assert_not_called()


@pytest.mark.parametrize("budget", [None, 0, 3, True, "sk-master-secret", float("nan")])
def test_budget_verification_failure_always_deletes_generated_key(api, budget):
    post, get = api
    get.return_value = response(data={"info": {"max_budget": budget}})

    result = check_tracking_auth(
        "https://remote.example", "sk-master-secret", max_budget=2
    )

    assert not result.ok
    assert "sk-master-secret" not in result.message
    assert "sk-temporary-secret" not in result.message
    assert post.call_args.kwargs["json"] == {"keys": ["sk-temporary-secret"]}


@pytest.mark.parametrize("status", [403, 404, 500])
def test_key_info_failure_still_cleans_up(api, status):
    post, get = api
    get.return_value = response(status, {"error": "sk-temporary-secret"})

    result = check_tracking_auth("https://remote.example", "master", max_budget=2)

    assert not result.ok
    assert f"GET /key/info returned HTTP {status}" in result.message
    assert "sk-temporary-secret" not in result.message
    assert post.call_count == 2


def test_info_transport_error_does_not_leak_query_key_and_still_cleans_up(api):
    post, get = api
    get.side_effect = requests.Timeout(
        "https://remote.example/key/info?key=sk-temporary-secret"
    )

    result = check_tracking_auth("https://remote.example", "master", max_budget=2)

    assert not result.ok
    assert "Timeout" in result.message
    assert "sk-temporary-secret" not in result.message
    assert post.call_count == 2


@pytest.mark.parametrize(
    "generation_result",
    [
        requests.Timeout("sk-master-secret"),
        response(500, {"error": "sk-master-secret"}),
        response(data={}),
    ],
)
def test_ambiguous_generation_is_cleaned_up_by_unique_alias(api, generation_result):
    post, get = api
    post.side_effect = [generation_result, response(data={"deleted_keys": []})]

    result = check_tracking_auth(
        "https://remote.example", "sk-master-secret", max_budget=2
    )

    assert not result.ok
    assert "sk-master-secret" not in result.message
    alias = post.call_args_list[0].kwargs["json"]["key_alias"]
    assert post.call_args_list[1].kwargs["json"] == {"key_aliases": [alias]}
    get.assert_not_called()


def test_malformed_generation_response_is_not_reported_as_secret_text(api):
    post, get = api
    malformed = response()
    malformed._content = b"sk-master-secret"
    post.side_effect = [malformed, response(data={"deleted_keys": []})]

    result = check_tracking_auth(
        "https://remote.example", "sk-master-secret", max_budget=2
    )

    assert not result.ok
    assert "sk-master-secret" not in result.message
    assert "key_aliases" in post.call_args.kwargs["json"]


@pytest.mark.parametrize(
    "cleanup_result",
    [
        response(403, {"error": "sk-master-secret"}),
        response(data={"deleted_keys": []}),
        response(data={"deleted_keys": "sk-temporary-secret"}),
        requests.Timeout("sk-temporary-secret"),
    ],
)
def test_cleanup_failure_blocks_even_after_successful_budget_check(api, cleanup_result):
    post, get = api
    post.side_effect = [response(data={"key": "sk-temporary-secret"}), cleanup_result]

    result = check_tracking_auth(
        "https://remote.example", "sk-master-secret", max_budget=2
    )

    assert not result.ok
    assert "cleanup failed" in result.message
    assert "crsbench-preflight-" in result.message
    assert "sk-master-secret" not in result.message
    assert "sk-temporary-secret" not in result.message


def test_nonfinite_budget_does_not_create_a_key(api):
    post, get = api

    assert not check_tracking_auth(
        "https://remote.example", "master", max_budget=float("inf")
    ).ok
    post.assert_not_called()
    get.assert_not_called()


def cloud_inputs(envs, **overrides):
    config = SimpleNamespace(
        skip_litellm=False,
        llm_tracking_enabled=True,
        litellm_mode="external",
        litellm_cost_budget=2.0,
    )
    for name, value in overrides.items():
        setattr(config, name, value)
    preflight = SimpleNamespace(
        resolved_plan=SimpleNamespace(
            worker_placements=[SimpleNamespace(env=env) for env in envs]
        )
    )
    return config, preflight


def test_cloud_probes_distinct_effective_worker_credentials_once(monkeypatch):
    env = {
        "CRSBENCH_LLM_UPSTREAM_BASE_URL": "https://remote.example/",
        "CRSBENCH_LLM_UPSTREAM_MASTER_KEY": "worker-secret",
    }
    other = {**env, "CRSBENCH_LLM_UPSTREAM_MASTER_KEY": "other-worker-secret"}
    config, preflight = cloud_inputs([env] * 250 + [other])
    probe = Mock(return_value=CheckResult(ok=True, message="passed"))
    monkeypatch.setattr("crsbench.cloud.cli._preflight.check_tracking_auth", probe)
    monkeypatch.setenv("CRSBENCH_LLM_UPSTREAM_MASTER_KEY", "operator-secret")

    checks = _litellm_tracking_checks(config, preflight)

    assert len(checks) == 251
    assert all(c.status == "pass" for c in checks)
    assert probe.call_count == 2
    assert probe.call_args_list[0].args == ("https://remote.example/", "worker-secret")
    assert probe.call_args_list[1].args == (
        "https://remote.example/",
        "other-worker-secret",
    )
    assert probe.call_args.kwargs == {"max_budget": 2.0}


@pytest.mark.parametrize(
    "overrides", [{"skip_litellm": True}, {"llm_tracking_enabled": False}]
)
def test_cloud_skips_probe_when_tracking_is_not_required(monkeypatch, overrides):
    config, preflight = cloud_inputs([{}], **overrides)
    probe = Mock()
    monkeypatch.setattr("crsbench.cloud.cli._preflight.check_tracking_auth", probe)

    assert _litellm_tracking_checks(config, preflight) == []
    probe.assert_not_called()


def test_missing_worker_credentials_cannot_fall_back_to_operator_environment(
    monkeypatch,
):
    config, preflight = cloud_inputs([{}])
    probe = Mock()
    monkeypatch.setattr("crsbench.cloud.cli._preflight.check_tracking_auth", probe)
    monkeypatch.setenv("CRSBENCH_LLM_UPSTREAM_BASE_URL", "https://operator.example")
    monkeypatch.setenv("CRSBENCH_LLM_UPSTREAM_MASTER_KEY", "operator-secret")

    checks = _litellm_tracking_checks(config, preflight)

    assert len(checks) == 1
    assert checks[0].is_failure
    assert "CRSBENCH_LLM_UPSTREAM_MASTER_KEY" in checks[0].summary
    assert "operator-secret" not in checks[0].summary
    probe.assert_not_called()
