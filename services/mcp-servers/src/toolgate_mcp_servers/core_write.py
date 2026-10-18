"""core-write MCP server: idempotent write tools over claims, notes and contact preference."""

from datetime import date
from typing import Annotated

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from pydantic import Field

from toolgate_mcp_servers.api_client import ApiClient, api_errors_to_tool_errors
from toolgate_mcp_servers.app_factory import build_server
from toolgate_mcp_servers.models import (
    ClaimCreated,
    ClaimId,
    ContactPreference,
    ContactPreferenceUpdated,
    IdempotencyKey,
    MemberId,
    NoteAdded,
    NoteType,
    PolicyId,
    ProcedureCode,
)
from toolgate_mcp_servers.settings import ServerSettings

NAME = "core-write"
PORT = 8102
_WRITE = ToolAnnotations(
    readOnlyHint=False,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=False,
)


def register(mcp: FastMCP, api: ApiClient) -> None:
    @mcp.tool(annotations=_WRITE)
    async def log_claim(
        member_id: MemberId,
        policy_id: PolicyId,
        procedure_code: ProcedureCode,
        incident_date: Annotated[
            date,
            Field(
                description="Date of treatment, ISO 8601 (YYYY-MM-DD); not in the future"
            ),
        ],
        amount_pence: Annotated[
            int,
            Field(
                ge=1, le=5_000_000, description="Claim amount in pence (1-5,000,000)"
            ),
        ],
        idempotency_key: IdempotencyKey,
    ) -> ClaimCreated:
        """Logs a new claim with status received for a member's active policy."""
        with api_errors_to_tool_errors():
            data = await api.post(
                "/claims",
                {
                    "member_id": member_id,
                    "policy_id": policy_id,
                    "procedure_code": procedure_code,
                    "incident_date": incident_date.isoformat(),
                    "amount_pence": amount_pence,
                },
                idempotency_key,
            )
        return ClaimCreated.model_validate(data)

    @mcp.tool(annotations=_WRITE)
    async def add_claim_note(
        claim_id: ClaimId,
        note_type: NoteType,
        body: Annotated[str, Field(min_length=1, max_length=1000)],
        idempotency_key: IdempotencyKey,
    ) -> NoteAdded:
        """Adds a note to an existing claim."""
        with api_errors_to_tool_errors():
            data = await api.post(
                f"/claims/{claim_id}/notes",
                {"note_type": note_type, "body": body},
                idempotency_key,
            )
        return NoteAdded.model_validate(data)

    @mcp.tool(annotations=_WRITE)
    async def update_contact_preference(
        member_id: MemberId,
        preference: ContactPreference,
        idempotency_key: IdempotencyKey,
    ) -> ContactPreferenceUpdated:
        """Sets a member's preferred contact channel."""
        with api_errors_to_tool_errors():
            data = await api.put(
                f"/members/{member_id}/contact-preference",
                {"preference": preference},
                idempotency_key,
            )
        return ContactPreferenceUpdated(
            member_id=data["member_id"], contact_preference=data["contact_preference"]
        )


def main() -> None:
    """Serve core-write over streamable HTTP; other settings come from the environment."""
    settings = ServerSettings(mcp_audience=NAME, port=PORT)
    build_server(NAME, settings, register).run(transport="streamable-http")


if __name__ == "__main__":
    main()
