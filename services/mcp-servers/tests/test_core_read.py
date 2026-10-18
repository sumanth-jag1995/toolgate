import time
from datetime import UTC, datetime, timedelta

import pytest

TOOLS = {
    "get_member_profile",
    "get_policy_details",
    "check_coverage",
    "get_claim_status",
    "list_member_claims",
    "get_payment_history",
    "get_correspondence_history",
}


async def test_lists_exactly_seven_tools(core_read_session):
    names = {t.name for t in (await core_read_session.list_tools()).tools}
    assert names == TOOLS


async def test_every_tool_is_strict_and_read_only(core_read_session):
    for t in (await core_read_session.list_tools()).tools:
        assert t.inputSchema["additionalProperties"] is False
        assert t.outputSchema is not None
        assert t.annotations.readOnlyHint is True
        assert t.annotations.openWorldHint is False


async def test_get_member_profile_canary(core_read_session):
    r = await core_read_session.call_tool(
        "get_member_profile", {"member_id": "M-900001"}
    )
    assert not r.isError
    assert r.structuredContent["membership_number"] == "TG-CANARY-7Q4X9"
    assert r.structuredContent["name"] == "Ada Quillfeather"
    assert r.structuredContent["policy_ids"] == ["P-900001"]
    assert "address_line" not in r.structuredContent


@pytest.mark.parametrize("bad", ["M-12", "M-000001' OR 1=1", ""])
async def test_bad_member_id_is_tool_error(core_read_session, bad):
    r = await core_read_session.call_tool("get_member_profile", {"member_id": bad})
    assert r.isError


async def test_extra_argument_rejected(core_read_session):
    r = await core_read_session.call_tool(
        "get_member_profile", {"member_id": "M-900001", "evil": "x"}
    )
    assert r.isError


async def test_unknown_member_is_not_found(core_read_session):
    r = await core_read_session.call_tool(
        "get_member_profile", {"member_id": "M-999999"}
    )
    assert r.isError and "not found" in r.content[0].text


async def test_get_policy_details(core_read_session, canary_policy_id):
    r = await core_read_session.call_tool(
        "get_policy_details", {"policy_id": canary_policy_id}
    )
    assert not r.isError
    assert r.structuredContent["product"] == "premier"
    assert r.structuredContent["member_id"] == "M-900001"


async def test_check_coverage(core_read_session, canary_policy_id):
    r = await core_read_session.call_tool(
        "check_coverage", {"policy_id": canary_policy_id, "procedure_code": "mri_scan"}
    )
    assert not r.isError
    assert r.structuredContent["covered"] is True
    assert r.structuredContent["policy_status"] == "active"


async def test_check_coverage_enum_enforced(core_read_session, canary_policy_id):
    r = await core_read_session.call_tool(
        "check_coverage",
        {"policy_id": canary_policy_id, "procedure_code": "brain_transplant"},
    )
    assert r.isError


async def test_get_claim_status_returns_last_three_notes(
    core_read_session, canary_in_review_claim_id, db_session
):
    from mock_enterprise.models import ClaimNote

    for i in range(5):
        db_session.add(
            ClaimNote(
                claim_id=canary_in_review_claim_id,
                note_type="customer_contact",
                created_at=datetime.now(UTC) + timedelta(minutes=i),
                body=f"note {i}",
                author_client="test",
            )
        )
    await db_session.commit()
    r = await core_read_session.call_tool(
        "get_claim_status", {"claim_id": canary_in_review_claim_id}
    )
    assert not r.isError
    assert r.structuredContent["status"] == "in_review"
    assert r.structuredContent["amount_pence"] == 38_500
    assert len(r.structuredContent["notes"]) <= 3
    assert [n["body"] for n in r.structuredContent["notes"]][-1] == "note 4"
    assert r.structuredContent["payments"] == []


async def test_get_claim_status_unknown_claim(core_read_session):
    r = await core_read_session.call_tool("get_claim_status", {"claim_id": "C-999999"})
    assert r.isError and "not found" in r.content[0].text


async def test_list_member_claims_status_filter(core_read_session):
    all_ = await core_read_session.call_tool(
        "list_member_claims", {"member_id": "M-900001"}
    )
    assert {c["claim_id"] for c in all_.structuredContent["claims"]} == {
        "C-900001",
        "C-900002",
    }
    r = await core_read_session.call_tool(
        "list_member_claims", {"member_id": "M-900001", "status": "in_review"}
    )
    assert [c["claim_id"] for c in r.structuredContent["claims"]] == ["C-900001"]


async def test_list_member_claims_limit_and_status_validation(core_read_session):
    r = await core_read_session.call_tool(
        "list_member_claims", {"member_id": "M-900001", "limit": 1}
    )
    assert len(r.structuredContent["claims"]) == 1
    for bad in ({"limit": 0}, {"limit": 21}, {"status": "bogus"}):
        r = await core_read_session.call_tool(
            "list_member_claims", {"member_id": "M-900001", **bad}
        )
        assert r.isError


async def test_payment_and_correspondence_history_canary(core_read_session):
    p = await core_read_session.call_tool(
        "get_payment_history", {"member_id": "M-900001"}
    )
    assert not p.isError
    assert [x["payment_id"] for x in p.structuredContent["payments"]] == ["PAY-900001"]
    c = await core_read_session.call_tool(
        "get_correspondence_history", {"member_id": "M-900001"}
    )
    assert not c.isError
    items = c.structuredContent["correspondence"]
    assert len(items) == 1 and items[0]["template"] == "payment_confirmation"


async def test_api_down_returns_tool_error(core_read_session_api_down):
    start = time.monotonic()
    r = await core_read_session_api_down.call_tool(
        "get_member_profile", {"member_id": "M-900001"}
    )
    assert r.isError
    assert time.monotonic() - start < 2
    text = r.content[0].text
    assert "unavailable" in text
    assert "enterprise.invalid" not in text and "Bearer" not in text
