"""Tests for safe Valkey lifecycle policy."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import call, patch

import pytest

from framework.errors import FrameworkError
from framework.services import (
    _require_valkey_pong,
    prepare_local_valkey,
    require_owned_local_valkey,
)


@pytest.mark.parametrize("host", ["localhost", "localhost:6379", "127.0.0.1:6379"])
def test_owned_local_valkey_endpoints(host: str) -> None:
    assert require_owned_local_valkey(host).endswith(":6379")


@pytest.mark.parametrize("host", ["redis.example:6379", "localhost:6380"])
def test_remote_or_unexpected_valkey_is_rejected(host: str) -> None:
    with pytest.raises(FrameworkError, match="restricted"):
        require_owned_local_valkey(host)


def test_fresh_valkey_is_stopped_started_flushed_and_checked() -> None:
    with (
        patch("framework.services._valkey_helper") as helper,
        patch("framework.services._require_valkey_pong") as pong,
    ):
        prepare_local_valkey(Path("/repo"), "localhost:6379")
    assert helper.call_args_list == [
        call(Path("/repo"), "stop"),
        call(Path("/repo"), "start"),
        call(Path("/repo"), "clean-all", "--force"),
        call(Path("/repo"), "status"),
    ]
    pong.assert_called_once_with(Path("/repo"))


def test_valkey_requires_exact_pong() -> None:
    with patch("framework.services._run") as run:
        run.return_value.stdout = "NOPE\n"
        with pytest.raises(FrameworkError, match="did not return PONG"):
            _require_valkey_pong(Path("/repo"))
