"""core-read MCP server: read-only tools over members, policies, claims, payments, comms."""

from typing import Annotated

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from pydantic import Field

from toolgate_mcp_servers.api_client import ApiClient, api_errors_to_tool_errors
from toolgate_mcp_servers.app_factory import build_server
from toolgate_mcp_servers.models import (
    ClaimId,
    ClaimList,
    ClaimStatus,
    ClaimStatusResult,
    CorrespondenceList,
    CoverageResult,
    ListLimit,
    MemberId,
    MemberProfile,
    PaymentList,
    PolicyDetails,
    PolicyId,
    ProcedureCode,
)
from toolgate_mcp_servers.settings import ServerSettings

NAME = "core-read"
PORT = 8101
_READ_ONLY = ToolAnnotations(readOnlyHint=True, openWorldHint=False)
_MAX_NOTES = 3


def register(mcp: FastMCP, api: ApiClient) -> None:
    @mcp.tool(annotations=_READ_ONLY)
    async def get_member_profile(member_id: MemberId) -> MemberProfile:
        """Returns a member's profile: name, date of birth, contact details, contact preference and policy IDs."""
        with api_errors_to_tool_errors():
            m = await api.get(f"/members/{member_id}")
        return MemberProfile(
            member_id=m["member_id"],
            membership_number=m["membership_number"],
            name=f"{m['first_name']} {m['last_name']}",
            dob=m["dob"],
            email=m["email"],
            phone=m["phone"],
            postcode=m["postcode"],
            contact_preference=m["contact_preference"],
            policy_ids=m["policy_ids"],
        )

    @mcp.tool(annotations=_READ_ONLY)
    async def get_policy_details(policy_id: PolicyId) -> PolicyDetails:
        """Returns a policy's product, status, dates, excess and annual limit."""
        with api_errors_to_tool_errors():
            data = await api.get(f"/policies/{policy_id}")
        return PolicyDetails.model_validate(data)

    @mcp.tool(annotations=_READ_ONLY)
    async def check_coverage(
        policy_id: PolicyId, procedure_code: ProcedureCode
    ) -> CoverageResult:
        """Returns whether a procedure is covered under a policy, with any pre-authorisation requirement and limit."""
        with api_errors_to_tool_errors():
            data = await api.get(
                "/coverage",
                params={"policy_id": policy_id, "procedure_code": procedure_code},
            )
        return CoverageResult.model_validate(data)

    @mcp.tool(annotations=_READ_ONLY)
    async def get_claim_status(claim_id: ClaimId) -> ClaimStatusResult:
        """Returns a claim's status, amount, dates, its three most recent notes and its payments."""
        with api_errors_to_tool_errors():
            data = await api.get(f"/claims/{claim_id}")
        data["notes"] = data["notes"][-_MAX_NOTES:]
        return ClaimStatusResult.model_validate(data)

    @mcp.tool(annotations=_READ_ONLY)
    async def list_member_claims(
        member_id: MemberId,
        status: Annotated[
            ClaimStatus | None, Field(description="Only return claims with this status")
        ] = None,
        limit: ListLimit = 10,
    ) -> ClaimList:
        """Returns a member's claims, newest first, optionally filtered by status."""
        params: dict[str, str | int] = {"limit": limit}
        if status is not None:
            params["status"] = status
        with api_errors_to_tool_errors():
            data = await api.get(f"/members/{member_id}/claims", params=params)
        return ClaimList.model_validate({"claims": data})

    @mcp.tool(annotations=_READ_ONLY)
    async def get_payment_history(
        member_id: MemberId, limit: ListLimit = 10
    ) -> PaymentList:
        """Returns a member's most recent payments across all claims."""
        with api_errors_to_tool_errors():
            data = await api.get(
                f"/members/{member_id}/payments", params={"limit": limit}
            )
        return PaymentList.model_validate({"payments": data})

    @mcp.tool(annotations=_READ_ONLY)
    async def get_correspondence_history(
        member_id: MemberId, limit: ListLimit = 10
    ) -> CorrespondenceList:
        """Returns the messages most recently sent to a member, with channel, template and subject."""
        with api_errors_to_tool_errors():
            data = await api.get(
                f"/members/{member_id}/correspondence", params={"limit": limit}
            )
        return CorrespondenceList.model_validate({"correspondence": data})


def main() -> None:
    """Serve core-read over streamable HTTP; other settings come from the environment."""
    settings = ServerSettings(mcp_audience=NAME, port=PORT)
    build_server(NAME, settings, register).run(transport="streamable-http")


if __name__ == "__main__":
    main()
