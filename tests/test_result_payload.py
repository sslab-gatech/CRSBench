"""Large evaluator results survive the RQ serialization boundary."""

import os
from unittest.mock import MagicMock

import pytest
from crsbench.distributed import result_payload
from crsbench.distributed.result_payload import compact_result_for_redis
from rq.results import Result


def test_large_result_round_trips_through_rq_without_losing_verdict_data() -> None:
    verdict = {
        "status": "cpv",
        "cpv_matches": ["cpv_0"],
        "crash_logs": {"asan": "repeated crash trace\n" * 100_000},
    }
    result = Result(
        "verify-1",
        Result.Type.SUCCESSFUL,
        MagicMock(),
        return_value=compact_result_for_redis(verdict),
    )

    serialized = result.serialize()
    redis_payload = {
        key: value.encode() if isinstance(value, str) else value
        for key, value in serialized.items()
    }
    restored = Result.restore("verify-1", "1-0", redis_payload, MagicMock())

    assert restored.return_value == verdict
    assert len(serialized["return_value"]) < 100_000


def test_incompressible_result_still_round_trips_through_rq() -> None:
    verdict = {"binary_evidence": os.urandom(1024 * 1024)}
    result = Result(
        "verify-2",
        Result.Type.SUCCESSFUL,
        MagicMock(),
        return_value=compact_result_for_redis(verdict),
    )
    serialized = result.serialize()
    redis_payload = {
        key: value.encode() if isinstance(value, str) else value
        for key, value in serialized.items()
    }

    assert (
        Result.restore("verify-2", "1-0", redis_payload, MagicMock()).return_value
        == verdict
    )


def test_oversized_incompressible_result_fails_with_clear_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(result_payload, "_COMPRESS_AT_BYTES", 1)
    monkeypatch.setattr(result_payload, "_MAX_STORED_RETURN_BYTES", 512)

    with pytest.raises(ValueError, match="Redis bulk limit"):
        compact_result_for_redis({"binary_evidence": os.urandom(1024)})
