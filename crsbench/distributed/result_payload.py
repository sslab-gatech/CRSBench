"""Losslessly compact large values before RQ stores them in Redis."""

import pickle
import zlib
from typing import Any

_COMPRESS_AT_BYTES = 1024 * 1024


def _restore_compressed_result(payload: bytes) -> Any:
    return pickle.loads(zlib.decompress(payload))  # noqa: S301


class _CompressedResult:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload

    def __reduce__(self) -> tuple[Any, tuple[bytes]]:
        # RQ's normal pickle load restores the original return value.
        return _restore_compressed_result, (self.payload,)


def compact_result_for_redis(result: Any) -> Any:
    """Preserve the RQ return value while shrinking large repetitive verdicts.

    RQ base64-encodes return values in a single Redis stream field. POV crash
    output can exceed Redis's maximum bulk length; a transparent pickle
    reduction keeps the value and its reader interface unchanged.
    """
    try:
        serialized = pickle.dumps(result, protocol=pickle.HIGHEST_PROTOCOL)
    except (pickle.PicklingError, AttributeError, TypeError):
        # Preserve RQ's existing fallback for values it cannot serialize.
        return result
    if len(serialized) < _COMPRESS_AT_BYTES:
        return result
    compressed = zlib.compress(serialized, level=1)
    if len(compressed) >= len(serialized):
        return result
    return _CompressedResult(compressed)
