import uuid

import pytest

TOOLS = {"log_claim", "add_claim_note", "update_contact_preference"}


def _claim_args(policy_id: str, **over) -> dict:
    args = {
        "member_id": "M-900001",
        "policy_id": policy_id,
        "procedure_code": "mri_scan",
        "incident_date": "2026-01-15",
        "amount_pence": 25000,
        "idempotency_key": str(uuid.uuid4()),
    }
    return {**args, **over}


async def test_lists_exactly_three_tools_all_require_idempotency_key(
    core_write_session,
):
    tools = (await core_write_session.list_tools()).tools
    assert {t.name for t in tools} == TOOLS
    for t in tools:
        assert "idempotency_key" in t.inputSchema["required"]
        assert t.inputSchema["additionalProperties"] is False
        key = t.inputSchema["properties"]["idempotency_key"]
        assert key["format"] == "uuid"
        assert t.outputSchema is not None
        a = t.annotations
        assert a.readOnlyHint is False
        assert a.destructiveHint is False
        assert a.idempotentHint is True
        assert a.openWorldHint is False


async def test_incident_date_advertised_as_date(core_write_session):
    tools = {t.name: t for t in (await core_write_session.list_tools()).tools}
    prop = tools["log_claim"].inputSchema["properties"]["incident_date"]
    assert prop["format"] == "date"


async def test_log_claim_creates_received_claim(core_write_session, canary_policy_id):
    r = await core_write_session.call_tool("log_claim", _claim_args(canary_policy_id))
    assert not r.isError
    assert r.structuredContent["status"] == "received"
    assert r.structuredContent["claim_id"].startswith("C-")


async def test_log_claim_replay_returns_same_claim(
    core_write_session, canary_policy_id
):
    args = _claim_args(canary_policy_id)
    first = await core_write_session.call_tool("log_claim", args)
    second = await core_write_session.call_tool("log_claim", args)
    assert not first.isError and not second.isError
    assert first.structuredContent == second.structuredContent


async def test_log_claim_key_reuse_different_args_is_tool_error(
    core_write_session, canary_policy_id
):
    args = _claim_args(canary_policy_id)
    ok = await core_write_session.call_tool("log_claim", args)
    assert not ok.isError
    r = await core_write_session.call_tool(
        "log_claim", {**args, "amount_pence": args["amount_pence"] + 1}
    )
    assert r.isError and "idempotency key reused" in r.content[0].text


async def test_amount_must_be_integer_pence(core_write_session, canary_policy_id):
    r = await core_write_session.call_tool(
        "log_claim", _claim_args(canary_policy_id, amount_pence=12.5)
    )
    assert r.isError


@pytest.mark.parametrize("amount", [0, 5_000_001])
async def test_amount_out_of_range_rejected(
    core_write_session, canary_policy_id, amount
):
    r = await core_write_session.call_tool(
        "log_claim", _claim_args(canary_policy_id, amount_pence=amount)
    )
    assert r.isError


async def test_future_incident_date_is_tool_error(core_write_session, canary_policy_id):
    r = await core_write_session.call_tool(
        "log_claim", _claim_args(canary_policy_id, incident_date="2999-01-01")
    )
    assert r.isError and "future" in r.content[0].text


async def test_non_uuid_idempotency_key_rejected(core_write_session, canary_policy_id):
    r = await core_write_session.call_tool(
        "log_claim", _claim_args(canary_policy_id, idempotency_key="not-a-uuid")
    )
    assert r.isError


async def test_extra_argument_rejected(core_write_session, canary_policy_id):
    r = await core_write_session.call_tool(
        "log_claim", _claim_args(canary_policy_id, evil="x")
    )
    assert r.isError


async def test_add_claim_note_roundtrip(
    core_write_session, core_read_session, canary_in_review_claim_id
):
    r = await core_write_session.call_tool(
        "add_claim_note",
        {
            "claim_id": canary_in_review_claim_id,
            "note_type": "customer_contact",
            "body": "Member called to chase.",
            "idempotency_key": str(uuid.uuid4()),
        },
    )
    assert not r.isError
    assert r.structuredContent["claim_id"] == canary_in_review_claim_id
    assert isinstance(r.structuredContent["note_id"], int)
    status = await core_read_session.call_tool(
        "get_claim_status", {"claim_id": canary_in_review_claim_id}
    )
    assert status.structuredContent["notes"][-1]["body"] == "Member called to chase."


async def test_add_claim_note_body_too_long_rejected(
    core_write_session, canary_in_review_claim_id
):
    r = await core_write_session.call_tool(
        "add_claim_note",
        {
            "claim_id": canary_in_review_claim_id,
            "note_type": "escalation",
            "body": "x" * 1001,
            "idempotency_key": str(uuid.uuid4()),
        },
    )
    assert r.isError


async def test_update_contact_preference_roundtrip(
    core_write_session, core_read_session
):
    r = await core_write_session.call_tool(
        "update_contact_preference",
        {
            "member_id": "M-900001",
            "preference": "post",
            "idempotency_key": str(uuid.uuid4()),
        },
    )
    assert not r.isError
    assert r.structuredContent == {
        "member_id": "M-900001",
        "contact_preference": "post",
    }
    profile = await core_read_session.call_tool(
        "get_member_profile", {"member_id": "M-900001"}
    )
    assert profile.structuredContent["contact_preference"] == "post"


async def test_update_contact_preference_invalid_enum_rejected(core_write_session):
    r = await core_write_session.call_tool(
        "update_contact_preference",
        {
            "member_id": "M-900001",
            "preference": "carrier_pigeon",
            "idempotency_key": str(uuid.uuid4()),
        },
    )
    assert r.isError
