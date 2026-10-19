"""Optional OpenTelemetry tracing; a cheap no-op when OTel is absent."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from typing import Any

try:  # resolved once at import; never retried per call
    from opentelemetry import trace as _otel_trace
except ImportError:  # pragma: no cover - exercised via monkeypatch
    _otel_trace = None


class _NoopSpan:
    def add_event(self, name: str, attrs: Mapping[str, Any] | None = None) -> None:
        return None

    def set_attribute(self, key: str, value: Any) -> None:
        return None


_NOOP = _NoopSpan()


class _Span:
    def __init__(self, inner: Any) -> None:
        self._inner = inner

    def add_event(self, name: str, attrs: Mapping[str, Any] | None = None) -> None:
        self._inner.add_event(name, dict(attrs) if attrs else None)

    def set_attribute(self, key: str, value: Any) -> None:
        self._inner.set_attribute(key, value)


@contextmanager
def span(name: str, **attrs: Any) -> Iterator[_NoopSpan | _Span]:
    if _otel_trace is None:
        yield _NOOP
        return
    tracer = _otel_trace.get_tracer("toolgate_pin")
    # Exceptions are not recorded: their messages could echo scanned values.
    with tracer.start_as_current_span(
        name,
        attributes=attrs or None,
        record_exception=False,
        set_status_on_exception=False,
    ) as inner:
        yield _Span(inner)
