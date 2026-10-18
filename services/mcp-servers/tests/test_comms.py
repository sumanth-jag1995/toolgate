import uuid
from datetime import date, timedelta

TOOLS = {"send_member_message", "schedule_callback"}


def _msg(**over) -> dict:
    args = {
        "member_id": "M-900001",
        "template_id": "callback_confirmation",
        "idempotency_key": str(uuid.uuid4()),
    }
    return {**args, **over}


def _cb(**over) -> dict:
    args = {
        "member_id": "M-900001",
        "reason": "claim_query",
        "preferred_date": (date.today() + timedelta(days=3)).isoformat(),
        "preferred_window": "morning",
        "idempotency_key": str(uuid.uuid4()),
    }
    return {**args, **over}


async def _tools(s):
    return {t.name: t for t in (await s.list_tools()).tools}


async def test_lists_exactly_two_write_tools(comms_session):
    tools = await _tools(comms_session)
    assert set(tools) == TOOLS
    for t in tools.values():
        assert "idempotency_key" in t.inputSchema["required"]
        assert t.inputSchema["additionalProperties"] is False
        assert t.outputSchema is not None
        a = t.annotations
        assert a.readOnlyHint is False
        assert a.destructiveHint is False
        assert a.idempotentHint is True
        assert a.openWorldHint is False


async def test_send_member_message_schema_has_no_recipient_or_body(comms_session):
    t = (await _tools(comms_session))["send_member_message"]
    props = set(t.inputSchema["properties"])
    assert props == {"member_id", "template_id", "claim_id", "idempotency_key"}
    assert t.inputSchema["additionalProperties"] is False
    assert "recipient" not in t.outputSchema["properties"]


async def test_extra_recipient_argument_rejected(comms_session):
    r = await comms_session.call_tool(
        "send_member_message", _msg(recipient="evil@attacker.test")
    )
    assert r.isError
    assert "recipient" in r.content[0].text


async def test_extra_body_argument_rejected(comms_session):
    r = await comms_session.call_tool("send_member_message", _msg(body="hi"))
    assert r.isError


async def test_unknown_template_rejected(comms_session):
    r = await comms_session.call_tool(
        "send_member_message", _msg(template_id="free_text")
    )
    assert r.isError


async def test_message_without_claim_succeeds_and_hides_recipient(comms_session):
    r = await comms_session.call_tool("send_member_message", _msg())
    assert not r.isError
    sc = r.structuredContent
    assert set(sc) == {"correspondence_id", "channel", "sent_at"}
    assert "@" not in r.content[0].text


async def test_claim_status_update_for_canary(comms_session, canary_in_review_claim_id):
    r = await comms_session.call_tool(
        "send_member_message",
        _msg(template_id="claim_status_update", claim_id=canary_in_review_claim_id),
    )
    assert not r.isError
    assert r.structuredContent["correspondence_id"] > 0
    assert "recipient" not in r.structuredContent


async def test_message_replay_returns_same_correspondence(comms_session):
    args = _msg()
    first = await comms_session.call_tool("send_member_message", args)
    second = await comms_session.call_tool("send_member_message", args)
    assert not first.isError and not second.isError
    assert first.structuredContent == second.structuredContent


async def test_template_requiring_claim_without_claim_is_error(comms_session):
    r = await comms_session.call_tool(
        "send_member_message", _msg(template_id="claim_status_update")
    )
    assert r.isError


async def test_schedule_callback_ok_and_replay(comms_session):
    args = _cb()
    first = await comms_session.call_tool("schedule_callback", args)
    assert not first.isError
    sc = first.structuredContent
    assert set(sc) == {"callback_id", "preferred_date", "preferred_window"}
    assert sc["preferred_date"] == args["preferred_date"]
    second = await comms_session.call_tool("schedule_callback", args)
    assert second.structuredContent == sc


async def test_schedule_callback_past_date_is_error(comms_session):
    past = (date.today() - timedelta(days=1)).isoformat()
    r = await comms_session.call_tool("schedule_callback", _cb(preferred_date=past))
    assert r.isError
    assert "30 days" in r.content[0].text


async def test_schedule_callback_bad_enums_rejected(comms_session):
    for over in ({"reason": "other"}, {"preferred_window": "night"}):
        r = await comms_session.call_tool("schedule_callback", _cb(**over))
        assert r.isError
