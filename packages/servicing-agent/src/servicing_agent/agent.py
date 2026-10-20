"""A plain, bounded ReAct servicing agent over an MCP toolkit.

The agent keeps no record of tool arguments or results. An episode trace holds
the model's final text, the number of model calls, the names of the tools that
were called, why the episode stopped, and an error *type* (never a message).
"""

from __future__ import annotations

import warnings
from dataclasses import dataclass
from typing import Any, Literal

from langchain_core.callbacks import AsyncCallbackHandler
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage
from langchain_core.outputs import LLMResult
from langgraph.errors import GraphRecursionError

from servicing_agent.mcp_tools import McpToolkit, ToolCallRecord
from servicing_agent.prompt import SYSTEM_PROMPT

StopReason = Literal["final", "step_cap", "model_error"]


@dataclass(frozen=True)
class EpisodeTrace:
    final_text: str
    steps: int
    tool_calls: list[ToolCallRecord]
    stop_reason: StopReason
    error: str | None


def error_label(exc: BaseException) -> str:
    """Exception type name plus an HTTP status when the exception carries one."""
    status = getattr(exc, "status_code", None)
    if not isinstance(status, int):
        status = getattr(getattr(exc, "response", None), "status_code", None)
    if isinstance(status, int):
        return f"{type(exc).__name__} (HTTP {status})"
    return type(exc).__name__


def _text(message: Any) -> str:
    content = getattr(message, "content", "")
    if isinstance(content, str):
        return content
    parts: list[str] = []
    for block in content:
        if isinstance(block, str):
            parts.append(block)
        elif isinstance(block, dict) and block.get("type") == "text":
            parts.append(str(block.get("text", "")))
    return "".join(parts)


class _ModelCalls(AsyncCallbackHandler):
    """Counts model calls and keeps the latest response (in memory only), so
    the trace reports the model's own last message even when LangGraph swaps
    in its "need more steps" placeholder at the step cap."""

    def __init__(self) -> None:
        self.started = 0
        self.last: AIMessage | None = None

    async def on_chat_model_start(self, *args: Any, **kwargs: Any) -> None:
        self.started += 1

    async def on_llm_end(self, response: LLMResult, **kwargs: Any) -> None:
        for generations in response.generations:
            for gen in generations:
                message = getattr(gen, "message", None)
                if isinstance(message, AIMessage):
                    self.last = message


class ServicingAgent:
    def __init__(
        self, chat_model: BaseChatModel, toolkit: McpToolkit, *, max_steps: int = 15
    ) -> None:
        if max_steps < 1:
            raise ValueError("max_steps must be at least 1")
        self._toolkit = toolkit
        self._max_steps = max_steps
        from langgraph.prebuilt import create_react_agent

        with warnings.catch_warnings():
            # create_react_agent is deprecated in favour of langchain.agents,
            # which this package does not depend on.
            warnings.filterwarnings(
                "ignore", message=r".*create_react_agent has been moved.*"
            )
            self._graph = create_react_agent(
                chat_model, toolkit.tools, prompt=SYSTEM_PROMPT
            )

    async def run(self, task_prompt: str) -> EpisodeTrace:
        calls_before = self._toolkit.call_count
        counter = _ModelCalls()
        # One model call and one tool step per superstep pair: a limit of
        # 2 * max_steps allows exactly max_steps model calls (LangGraph's
        # remaining-steps guard then ends the run instead of calling tools).
        config: dict[str, Any] = {
            "recursion_limit": 2 * self._max_steps,
            "callbacks": [counter],
        }
        stop_reason: StopReason = "final"
        error: str | None = None
        try:
            await self._graph.ainvoke(
                {"messages": [("user", task_prompt)]}, config=config
            )
        except GraphRecursionError:
            stop_reason = "step_cap"
        except Exception as exc:  # noqa: BLE001 - type only; CancelledError passes
            stop_reason = "model_error"
            error = error_label(exc)
        last = counter.last
        if stop_reason == "final" and last is not None and last.tool_calls:
            # The model still wanted tools when the step budget ran out.
            stop_reason = "step_cap"
        return EpisodeTrace(
            final_text=_text(last) if last is not None else "",
            steps=counter.started,
            tool_calls=self._toolkit.calls[calls_before:],
            stop_reason=stop_reason,
            error=error,
        )
