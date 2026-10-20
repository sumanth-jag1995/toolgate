"""World: reseed, tokens and snapshots against the live compose stack.

The unit tests at the top need no stack; the rest are marked ``integration``
and skip when the stack is unreachable.
"""

import logging
import time
import uuid
from dataclasses import replace
from datetime import timedelta

import httpx
import pytest
from mock_enterprise.schemas import business_today
from toolgate_eval.world import (
    Message,
    Note,
    World,
    WorldError,
    WorldSettings,
    WorldState,
    added,
)

MEMBER = "M-900001"


def _state(**kw) -> WorldState:
    base = {
        "member_id": MEMBER,
        "contact_preference": "email",
        "claims": (),
        "notes": (),
        "payments": (),
        "messages": (),
        "callbacks": (),
    }
    base.update(kw)
    return WorldState(**base)


# --- unit ------------------------------------------------------------------


def test_settings_from_env_reads_secrets_and_hides_them(tmp_path):
    env = tmp_path / ".env"
    env.write_text(
        "POSTGRES_PASSWORD=pg-secret-xyz\n"
        "SERVICING_CLIENT_SECRET=svc-secret-xyz\n"
        "DEV_TESTER_CLIENT_SECRET=dev-secret-xyz\n"
    )
    s = WorldSettings.from_env(env)
    assert s.api_url == "http://127.0.0.1:8000"
    assert s.token_url.endswith("/realms/toolgate/protocol/openid-connect/token")
    assert s.client_secrets.keys() == {"servicing", "dev-tester"}
    text = repr(s) + str(s)
    for secret in ("pg-secret-xyz", "svc-secret-xyz", "dev-secret-xyz"):
        assert secret not in text


def test_settings_missing_env_names_the_path_only(tmp_path):
    with pytest.raises(WorldError, match=r"\.env"):
        WorldSettings.from_env(tmp_path / ".env")


async def test_token_for_unknown_client_names_the_variable_only(tmp_path):
    env = tmp_path / ".env"
    env.write_text("POSTGRES_PASSWORD=pg-secret-xyz\n")
    async with World(WorldSettings.from_env(env)) as world:
        with pytest.raises(WorldError, match="SERVICING_CLIENT_SECRET"):
            await world.token("servicing")


def test_ids_of_new_rows_do_not_affect_equality():
    a = Note("C-900001", "escalation", "x", "dev-tester", "2026-10-20T10:00:00Z", 7)
    b = replace(a, note_id=99)
    assert a == b
    assert _state(notes=(a,)) == _state(notes=(b,))


def test_added_is_a_multiset_difference():
    m = Message("email", "policy_renewal_reminder", "s", "2026-01-01", None, 1)
    m2 = replace(m, sent_at="2026-10-20", correspondence_id=2)
    assert added((m,), (m, m2)) == [m2]
    assert added((m, m2), (m, m2)) == []


def test_message_claim_id_from_subject():
    assert Message.claim_of("Update on your claim C-900001") == "C-900001"
    assert Message.claim_of("Your policy is due for renewal") is None


# --- integration -------------------------------------------------------------


@pytest.mark.integration
async def test_reseed_restores_state(world: World):
    await world.reseed()
    baseline = await world.snapshot()
    assert baseline.member_id == MEMBER
    assert {c.claim_id for c in baseline.claims} == {"C-900001", "C-900002"}
    assert [p.payment_id for p in baseline.payments] == ["PAY-900001"]
    assert len(baseline.messages) == 1
    assert baseline.contact_preference == "email"

    core_write = await world.token("core-write")
    comms = await world.token("comms")
    async with httpx.AsyncClient(base_url=world.settings.api_url) as http:

        async def post(token: str, method: str, path: str, body: dict) -> None:
            resp = await http.request(
                method,
                path,
                json=body,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Idempotency-Key": str(uuid.uuid4()),
                },
            )
            assert resp.status_code in (200, 201), path

        today = business_today()
        await post(
            core_write,
            "POST",
            "/claims",
            {
                "member_id": MEMBER,
                "policy_id": "P-900001",
                "procedure_code": "ct_scan",
                "incident_date": (today - timedelta(days=2)).isoformat(),
                "amount_pence": 1000,
            },
        )
        await post(
            core_write,
            "POST",
            "/claims/C-900001/notes",
            {"note_type": "escalation", "body": "test"},
        )
        await post(
            core_write,
            "PUT",
            f"/members/{MEMBER}/contact-preference",
            {"preference": "post"},
        )
        await post(
            comms,
            "POST",
            f"/members/{MEMBER}/messages",
            {"template": "policy_renewal_reminder"},
        )
        await post(
            comms,
            "POST",
            f"/members/{MEMBER}/callbacks",
            {
                "reason": "complaint",
                "preferred_date": (today + timedelta(days=1)).isoformat(),
                "preferred_window": "morning",
            },
        )

    mutated = await world.snapshot()
    assert mutated != baseline
    assert len(mutated.claims) == 3
    assert len(added(baseline.notes, mutated.notes)) == 1
    assert len(added(baseline.messages, mutated.messages)) == 1
    assert len(added(baseline.callbacks, mutated.callbacks)) == 1
    assert mutated.contact_preference == "post"

    started = time.perf_counter()
    await world.reseed()
    elapsed = time.perf_counter() - started
    assert await world.snapshot() == baseline
    assert elapsed < 3.0


@pytest.mark.integration
async def test_token_never_logged(world: World, caplog, capsys):
    caplog.set_level(logging.DEBUG)
    token = await world.token("servicing")
    again = await world.token("servicing")
    assert token == again  # cached until near expiry
    secret = world.settings.client_secrets["servicing"]
    captured = capsys.readouterr()
    for value in (token, secret):
        assert value not in caplog.text
        assert value not in captured.out + captured.err
        assert value not in repr(world) + repr(world.settings)


@pytest.mark.integration
async def test_token_failure_names_the_client_only(stack_settings: WorldSettings):
    bad = replace(
        stack_settings,
        client_secrets={
            **stack_settings.client_secrets,
            "servicing": "wrong-secret-xyz",
        },
    )
    async with World(bad) as world:
        with pytest.raises(WorldError) as info:
            await world.token("servicing")
    assert "servicing" in str(info.value)
    assert "wrong-secret-xyz" not in str(info.value)


# --- token responses and reseed timeouts ---------------------------------------

_SECRETISH = "body-secret-should-not-appear"


@pytest.mark.parametrize(
    "body",
    [
        b"not json " + _SECRETISH.encode(),
        b'{"token_type": "' + _SECRETISH.encode() + b'"}',
        b'["' + _SECRETISH.encode() + b'"]',
        b'{"access_token": ""}',
        b'{"access_token": "abc", "expires_in": "soon"}',
    ],
    ids=["not-json", "no-access-token", "not-an-object", "empty-token", "bad-ttl"],
)
async def test_malformed_token_response_is_a_world_error(body: bytes):
    settings = WorldSettings(client_secrets={"servicing": "s"})
    transport = httpx.MockTransport(lambda request: httpx.Response(200, content=body))
    async with World(settings) as world:
        await world._http.aclose()
        world._http = httpx.AsyncClient(transport=transport)
        with pytest.raises(WorldError) as info:
            await world.token("servicing")
    message = str(info.value)
    assert "servicing" in message and "malformed" in message
    assert _SECRETISH not in message
    assert info.value.__cause__ is None and info.value.__suppress_context__


@pytest.mark.integration
async def test_reseed_times_out_on_a_held_lock_with_sqlstate(
    stack_settings: WorldSettings,
):
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import create_async_engine

    settings = replace(stack_settings, reseed_lock_timeout_s=0.5)
    blocker = create_async_engine(stack_settings.admin_dsn)
    try:
        async with blocker.connect() as conn, World(settings) as world:
            await conn.execute(text("SELECT 1 FROM members LIMIT 1"))  # ACCESS SHARE
            started = time.perf_counter()
            with pytest.raises(WorldError) as info:
                await world.reseed()
            elapsed = time.perf_counter() - started
            await conn.rollback()
    finally:
        await blocker.dispose()
    assert "55P03" in str(info.value)  # lock_not_available
    assert elapsed < 5.0
    async with World(stack_settings) as world:
        await world.reseed()  # the stack is usable again
