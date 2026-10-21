"""Shared fixtures: a scripted fake chat model and local MCP servers served
over streamable HTTP by uvicorn on 127.0.0.1 (no external network)."""

from __future__ import annotations

import asyncio
import json
import socket
from collections.abc import Callable
from typing import Any

import pytest
import uvicorn
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.utils.function_calling import convert_to_openai_tool
from mcp.server.fastmcp import FastMCP
from pydantic import Field


class ScriptedChatModel(BaseChatModel):
    """Plays back ``script`` one entry per model call, then repeats ``default``
    (or answers "done" when there is none). An exception entry is raised.
    Records every prompt it saw and the tool schemas it was bound to."""

    script: list[Any] = Field(default_factory=list)
    default: Any = None
    seen: list[list[BaseMessage]] = Field(default_factory=list)
    bound_tools: list[dict[str, Any]] = Field(default_factory=list)

    @property
    def _llm_type(self) -> str:
        return "scripted-fake"

    def bind_tools(self, tools: Any, **kwargs: Any) -> ScriptedChatModel:
        self.bound_tools = [convert_to_openai_tool(t) for t in tools]
        return self

    def _generate(
        self,
        messages: list[BaseMessage],
        stop: list[str] | None = None,
        run_manager: Any = None,
        **kwargs: Any,
    ) -> ChatResult:
        self.seen.append(list(messages))
        index = len(self.seen) - 1
        if index < len(self.script):
            step = self.script[index]
        elif self.default is not None:
            step = self.default
        else:
            step = AIMessage(content="done")
        if isinstance(step, BaseException):
            raise step
        message = step(messages) if callable(step) else step
        return ChatResult(generations=[ChatGeneration(message=message)])


def tool_call(name: str, args: dict[str, Any], call_id: str) -> AIMessage:
    return AIMessage(
        content="", tool_calls=[{"name": name, "args": args, "id": call_id}]
    )


def build_server(name: str = "test-server") -> FastMCP:
    server = FastMCP(name)

    @server.tool(
        name="core-read.get_claim_status",
        description="Look up the status of a claim.",
    )
    def get_claim_status(claim_id: str) -> dict:
        return {"claim_id": claim_id, "status": "approved", "server": name}

    @server.tool(name="comms.send_message", description="Send a member message.")
    def send_message(member_id: str, body: str) -> str:
        return f"queued for {member_id}"

    @server.tool(name="core-read.broken", description="Always fails.")
    def broken(claim_id: str) -> str:
        raise ValueError("backend unavailable")

    @server.tool(name="echo_reserved", description="Echoes its arguments.")
    def echo_reserved(
        self: str, config: str, run_manager: str, callbacks: str, args: str, kwargs: str
    ) -> str:
        return json.dumps(
            {
                "self": self,
                "config": config,
                "run_manager": run_manager,
                "callbacks": callbacks,
                "args": args,
                "kwargs": kwargs,
            },
            sort_keys=True,
        )

    @server.tool(name="big", description="Returns a large result.")
    def big() -> str:
        return "x" * 20000

    return server


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
async def serve():
    """``await serve(fastmcp, reject=None)`` -> (url, seen_authorization_headers).

    ``reject(authorization_header) -> bool``: answer HTTP 401 instead of
    serving the request (an expired token, for example)."""
    running: list[tuple[uvicorn.Server, asyncio.Task]] = []

    async def start(
        mcp: FastMCP, reject: Callable[[str | None], bool] | None = None
    ) -> tuple[str, list[str | None]]:
        app = mcp.streamable_http_app()
        seen_auth: list[str | None] = []

        async def recording_app(scope, receive, send):
            if scope["type"] == "http":
                headers = dict(scope["headers"])
                auth = headers.get(b"authorization", b"").decode() or None
                seen_auth.append(auth)
                if reject is not None and reject(auth):
                    await send(
                        {
                            "type": "http.response.start",
                            "status": 401,
                            "headers": [(b"content-type", b"text/plain")],
                        }
                    )
                    await send({"type": "http.response.body", "body": b"expired"})
                    return
            await app(scope, receive, send)

        port = _free_port()
        server = uvicorn.Server(
            uvicorn.Config(
                recording_app, host="127.0.0.1", port=port, log_level="error"
            )
        )
        task = asyncio.create_task(server.serve())
        deadline = asyncio.get_running_loop().time() + 10
        while not server.started:
            if task.done():
                task.result()  # surfaces the startup error
                raise RuntimeError("uvicorn exited before starting")
            if asyncio.get_running_loop().time() > deadline:
                server.should_exit = True
                await task
                raise TimeoutError("uvicorn did not start within 10 s")
            await asyncio.sleep(0.01)
        running.append((server, task))
        return f"http://127.0.0.1:{port}/mcp", seen_auth

    yield start
    for server, task in running:
        server.should_exit = True
        await task


# Test modules cannot import conftest under --import-mode=importlib, so the
# helpers above are handed out as fixtures.
@pytest.fixture
def make_server() -> Callable[..., FastMCP]:
    return build_server


@pytest.fixture
def make_model() -> type[ScriptedChatModel]:
    return ScriptedChatModel


@pytest.fixture
def make_tool_call() -> Callable[[str, dict[str, Any], str], AIMessage]:
    return tool_call
