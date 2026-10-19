"""OpenTelemetry tracing for the gateway.

``setup_tracing`` installs the global TracerProvider once, at startup, with an
OTLP/HTTP exporter. Spans are created through the global tracer, so the
``toolgate_pin`` spans (which resolve the global tracer per call) nest under
the gateway spans. Without an endpoint nothing is installed and every span is
a cheap non-recording no-op.

Span attributes and events carry client ids, tool names, hashes, decisions,
reasons and counts only: never arguments, results, descriptions or tokens.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from opentelemetry import trace
from opentelemetry.trace import Span

TRACER_NAME = "toolgate_gateway"


def setup_tracing(service_name: str, otlp_endpoint: str | None) -> None:
    """Install a BatchSpanProcessor + OTLP/HTTP exporter as the global
    provider; a no-op when ``otlp_endpoint`` is empty."""
    if not otlp_endpoint:
        return
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
        OTLPSpanExporter,
    )
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor

    endpoint = otlp_endpoint.rstrip("/")
    if not endpoint.endswith("/v1/traces"):
        endpoint += "/v1/traces"
    provider = TracerProvider(resource=Resource.create({"service.name": service_name}))
    provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint)))
    trace.set_tracer_provider(provider)


@contextmanager
def span(name: str, **attributes: Any) -> Iterator[Span]:
    """A child span of the current one. Exceptions are not recorded: their
    messages could echo values the span must never carry."""
    with trace.get_tracer(TRACER_NAME).start_as_current_span(
        name,
        attributes=attributes or None,
        record_exception=False,
        set_status_on_exception=False,
    ) as current:
        yield current


def shutdown_tracing() -> None:
    """Flush and stop the installed provider; a no-op without one."""
    provider = trace.get_tracer_provider()
    shutdown = getattr(provider, "shutdown", None)
    if shutdown is not None:
        shutdown()


def trace_id_of(current: Span) -> str | None:
    """32-hex trace id of ``current``; None for a non-recording (no provider)
    span."""
    ctx = current.get_span_context()
    return format(ctx.trace_id, "032x") if ctx.is_valid else None
