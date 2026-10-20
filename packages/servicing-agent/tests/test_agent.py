import asyncio
import json
from dataclasses import fields

import httpx
import pytest
from langchain_core.messages import AIMessage, SystemMessage, ToolMessage
from servicing_agent.agent import EpisodeTrace, ServicingAgent
from servicing_agent.mcp_tools import ToolCallRecord, connect
from servicing_agent.prompt import SYSTEM_PROMPT


@pytest.fixture
async def toolkit(serve, make_server):
    url, _ = await serve(make_server())
    tk = await connect(url, None)
    yield tk
    await tk.close()


async def test_agent_calls_tool_and_returns_final(toolkit, make_model, make_tool_call):
    model = make_model(
        script=[
            make_tool_call("core-read_get_claim_status", {"claim_id": "C-77"}, "c1"),
            AIMessage(content="Your claim C-77 is approved."),
        ]
    )
    trace = await ServicingAgent(model, toolkit).run("What is claim C-77's status?")
    assert trace == EpisodeTrace(
        final_text="Your claim C-77 is approved.",
        steps=2,
        tool_calls=[ToolCallRecord("core-read.get_claim_status", True)],
        stop_reason="final",
        error=None,
    )
    # The model saw the system prompt and the tool's real result.
    first, second = model.seen
    assert isinstance(first[0], SystemMessage)
    assert first[0].content == SYSTEM_PROMPT
    tool_msgs = [m for m in second if isinstance(m, ToolMessage)]
    assert len(tool_msgs) == 1 and "approved" in tool_msgs[0].content
    # The model was bound to sanitised names (OpenAI-compatible).
    bound = {t["function"]["name"] for t in model.bound_tools}
    assert "core-read_get_claim_status" in bound
    assert all(set(n) <= set("abcdefghijklmnopqrstuvwxyz0123456789_-") for n in bound)


async def test_tool_error_returned_to_model_not_raised(
    toolkit, make_model, make_tool_call
):
    model = make_model(
        script=[
            make_tool_call("core-read_broken", {"claim_id": "C1"}, "c1"),
            AIMessage(content="Sorry, the system is unavailable."),
        ]
    )
    trace = await ServicingAgent(model, toolkit).run("Check claim C1")
    assert trace.stop_reason == "final"
    assert trace.error is None
    assert trace.tool_calls == [ToolCallRecord("core-read.broken", False)]
    tool_msg = next(m for m in model.seen[1] if isinstance(m, ToolMessage))
    assert tool_msg.content.startswith("Tool error: ")


async def test_step_cap_stops_runaway_loop(toolkit, make_model, make_tool_call):
    counter = iter(range(1000))

    def always_tool(_messages):
        return make_tool_call("big", {}, f"c{next(counter)}")

    model = make_model(default=always_tool)
    trace = await ServicingAgent(model, toolkit).run("Loop forever")
    assert trace.stop_reason == "step_cap"
    assert trace.steps == 15
    assert len(model.seen) == 15
    assert trace.error is None
    # The 15th model call's tool request is never executed.
    assert len(trace.tool_calls) == 14
    assert "need more steps" not in trace.final_text


async def test_custom_max_steps(toolkit, make_model, make_tool_call):
    counter = iter(range(1000))
    model = make_model(
        default=lambda _m: make_tool_call("big", {}, f"c{next(counter)}")
    )
    trace = await ServicingAgent(model, toolkit, max_steps=3).run("Loop")
    assert (trace.stop_reason, trace.steps, len(model.seen)) == ("step_cap", 3, 3)


async def test_model_error_recorded_without_message(toolkit, make_model):
    model = make_model(script=[RuntimeError("secret-in-message")])
    trace = await ServicingAgent(model, toolkit).run("Hello")
    assert trace.stop_reason == "model_error"
    assert trace.error == "RuntimeError"
    assert "secret-in-message" not in repr(trace)


async def test_model_error_mid_episode_includes_http_status(
    toolkit, make_model, make_tool_call
):
    request = httpx.Request("POST", "https://model.invalid/v1/chat")
    response = httpx.Response(429, request=request)
    err = httpx.HTTPStatusError("secret-in-message", request=request, response=response)
    model = make_model(
        script=[make_tool_call("big", {}, "c1"), err],
    )
    trace = await ServicingAgent(model, toolkit).run("Hello")
    assert trace.stop_reason == "model_error"
    assert trace.error == "HTTPStatusError (HTTP 429)"
    assert trace.steps == 2
    assert trace.tool_calls == [ToolCallRecord("big", True)]
    assert "secret-in-message" not in repr(trace)


async def test_trace_holds_no_arguments_or_outputs(toolkit, make_model, make_tool_call):
    model = make_model(
        script=[
            make_tool_call(
                "comms_send_message",
                {"member_id": "M-900001", "body": "secret-argument-value"},
                "c1",
            ),
            AIMessage(content="Sent."),
        ]
    )
    trace = await ServicingAgent(model, toolkit).run("Send it")
    assert [f.name for f in fields(EpisodeTrace)] == [
        "final_text",
        "steps",
        "tool_calls",
        "stop_reason",
        "error",
    ]
    dumped = repr(trace)
    assert "secret-argument-value" not in dumped
    assert "M-900001" not in dumped
    assert "queued for" not in dumped


async def test_cancellation_propagates(toolkit, make_model):
    started = asyncio.Event()

    def slow(_messages):
        started.set()
        import time

        time.sleep(0.2)
        return AIMessage(content="late")

    agent = ServicingAgent(make_model(default=slow), toolkit)
    task = asyncio.create_task(agent.run("Hello"))
    await asyncio.wait_for(started.wait(), 5)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


async def test_reserved_argument_names_do_not_break_the_episode(
    toolkit, make_model, make_tool_call
):
    sent = {
        k: f"{k}-value"
        for k in ("self", "config", "run_manager", "callbacks", "args", "kwargs")
    }
    model = make_model(
        script=[make_tool_call("echo_reserved", sent, "c1"), AIMessage(content="ok")]
    )
    trace = await ServicingAgent(model, toolkit).run("Echo")
    assert trace.stop_reason == "final"
    assert trace.error is None
    assert trace.tool_calls == [ToolCallRecord("echo_reserved", True)]
    tool_msg = next(m for m in model.seen[1] if isinstance(m, ToolMessage))
    assert json.loads(tool_msg.content) == sent


async def test_unexpected_tool_exception_becomes_tool_message(
    toolkit, make_model, make_tool_call, monkeypatch
):
    tool = next(t for t in toolkit.tools if t.name == "big")

    async def boom(*args, **kwargs):
        raise RuntimeError("tool-side-secret")

    monkeypatch.setattr(type(tool), "_arun", boom)
    model = make_model(
        script=[make_tool_call("big", {}, "c1"), AIMessage(content="recovered")]
    )
    trace = await ServicingAgent(model, toolkit).run("Go")
    assert trace.stop_reason == "final"
    assert trace.final_text == "recovered"
    assert "tool-side-secret" not in repr(trace)
    tool_msg = next(m for m in model.seen[1] if isinstance(m, ToolMessage))
    assert tool_msg.status == "error"


def test_system_prompt_is_plain_servicing_prompt():
    text = SYSTEM_PROMPT.lower()
    assert "health insurer" in text or "health insurance" in text
    assert "tool" in text
    for banned in ("security", "canary", "attack", "inject", "malicious", "poison"):
        assert banned not in text
