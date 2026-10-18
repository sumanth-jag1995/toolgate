"""Task-shape check: representative servicing tasks must finish in <= 4 tool calls."""

from datetime import date, datetime
from uuid import uuid4
from zoneinfo import ZoneInfo

MAX_CALLS = 4


def london_today() -> date:
    return datetime.now(ZoneInfo("Europe/London")).date()


class CallCounter:
    """Calls tools across the named sessions, counting calls and failing on tool errors."""

    def __init__(self, sessions):
        self._sessions = sessions
        self.count = 0

    async def __call__(self, server: str, tool: str, args: dict) -> dict:
        self.count += 1
        result = await self._sessions[server].call_tool(tool, args)
        assert not result.isError, f"{server}.{tool}: {result.content[0].text}"
        return result.structuredContent


async def test_claim_status_update_task_in_three_calls(sessions):
    calls = CallCounter(sessions)
    claims = await calls(
        "core-read",
        "list_member_claims",
        {"member_id": "M-900001", "status": "in_review"},
    )
    cid = claims["claims"][0]["claim_id"]
    await calls("core-read", "get_claim_status", {"claim_id": cid})
    sent = await calls(
        "comms",
        "send_member_message",
        {
            "member_id": "M-900001",
            "template_id": "claim_status_update",
            "claim_id": cid,
            "idempotency_key": str(uuid4()),
        },
    )
    assert isinstance(sent["correspondence_id"], int)
    assert calls.count <= MAX_CALLS


async def test_new_claim_task(sessions):
    calls = CallCounter(sessions)
    profile = await calls("core-read", "get_member_profile", {"member_id": "M-900001"})
    policy_id = profile["policy_ids"][0]
    coverage = await calls(
        "core-read",
        "check_coverage",
        {"policy_id": policy_id, "procedure_code": "mri_scan"},
    )
    assert coverage["covered"] is True
    claim = await calls(
        "core-write",
        "log_claim",
        {
            "member_id": "M-900001",
            "policy_id": policy_id,
            "procedure_code": "mri_scan",
            "incident_date": london_today().isoformat(),
            "amount_pence": 25000,
            "idempotency_key": str(uuid4()),
        },
    )
    await calls(
        "comms",
        "send_member_message",
        {
            "member_id": "M-900001",
            "template_id": "documents_required",
            "claim_id": claim["claim_id"],
            "idempotency_key": str(uuid4()),
        },
    )
    assert calls.count <= MAX_CALLS


async def test_contact_change_task(sessions):
    calls = CallCounter(sessions)
    await calls("core-read", "get_member_profile", {"member_id": "M-900001"})
    updated = await calls(
        "core-write",
        "update_contact_preference",
        {
            "member_id": "M-900001",
            "preference": "sms",
            "idempotency_key": str(uuid4()),
        },
    )
    assert updated["contact_preference"] == "sms"
    await calls(
        "comms",
        "send_member_message",
        {
            "member_id": "M-900001",
            "template_id": "callback_confirmation",
            "idempotency_key": str(uuid4()),
        },
    )
    assert calls.count <= MAX_CALLS
