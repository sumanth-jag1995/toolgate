"""comms MCP server: templated member messaging and callback scheduling.

``send_member_message`` takes no recipient and no body: the API sends a fixed
template to the member's contact on file, so the tool cannot be used to
exfiltrate data to an arbitrary address.
"""

from datetime import date
from typing import Annotated

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from pydantic import Field

from toolgate_mcp_servers.api_client import ApiClient, api_errors_to_tool_errors
from toolgate_mcp_servers.app_factory import build_server
from toolgate_mcp_servers.models import (
    CallbackReason,
    CallbackScheduled,
    CallbackWindow,
    ClaimId,
    IdempotencyKey,
    MemberId,
    MessageSent,
    MessageTemplate,
)
from toolgate_mcp_servers.settings import ServerSettings

NAME = "comms"
PORT = 8103
_WRITE = ToolAnnotations(
    readOnlyHint=False,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=False,
)


def register(mcp: FastMCP, api: ApiClient) -> None:
    @mcp.tool(annotations=_WRITE)
    async def send_member_message(
        member_id: MemberId,
        template_id: MessageTemplate,
        idempotency_key: IdempotencyKey,
        claim_id: Annotated[
            ClaimId | None,
            Field(
                description="Required for claim_status_update, payment_confirmation "
                "and documents_required"
            ),
        ] = None,
    ) -> MessageSent:
        """Sends a pre-approved template message to the member's contact on file."""
        body: dict = {"template": template_id}
        if claim_id is not None:
            body["claim_id"] = claim_id
        with api_errors_to_tool_errors():
            data = await api.post(
                f"/members/{member_id}/messages", body, idempotency_key
            )
        return MessageSent.model_validate(data)  # drops the recipient

    @mcp.tool(annotations=_WRITE)
    async def schedule_callback(
        member_id: MemberId,
        reason: CallbackReason,
        preferred_date: Annotated[
            date,
            Field(
                description="ISO 8601 date (YYYY-MM-DD), from today up to 30 days ahead"
            ),
        ],
        preferred_window: CallbackWindow,
        idempotency_key: IdempotencyKey,
    ) -> CallbackScheduled:
        """Requests a callback to the member in a preferred date and time window."""
        with api_errors_to_tool_errors():
            data = await api.post(
                f"/members/{member_id}/callbacks",
                {
                    "reason": reason,
                    "preferred_date": preferred_date.isoformat(),
                    "preferred_window": preferred_window,
                },
                idempotency_key,
            )
        return CallbackScheduled.model_validate(data)


def main() -> None:
    """Serve comms over streamable HTTP; other settings come from the environment."""
    settings = ServerSettings(mcp_audience=NAME, port=PORT)
    build_server(NAME, settings, register).run(transport="streamable-http")


if __name__ == "__main__":
    main()
