import asyncio
from datetime import date, datetime, timedelta
from uuid import uuid4
from zoneinfo import ZoneInfo

import pytest
from mock_enterprise.canary import CANARY
from mock_enterprise.models import Claim, ClaimNote, Correspondence, Member, Policy
from sqlalchemy import func, select

DEFAULT_AMOUNT = 123_456
CANARY_ID = CANARY["member_id"]


def london_today() -> date:
    return datetime.now(ZoneInfo("Europe/London")).date()


def idem(headers, key=None):
    return {**headers, "Idempotency-Key": str(key or uuid4())}


async def post_claim(
    client,
    headers,
    *,
    key,
    policy_id,
    member_id=CANARY_ID,
    amount_pence=DEFAULT_AMOUNT,
    incident_date=None,
):
    return await client.post(
        "/claims",
        headers=idem(headers, key),
        json={
            "member_id": member_id,
            "policy_id": policy_id,
            "procedure_code": "mri_scan",
            "incident_date": (incident_date or london_today()).isoformat(),
            "amount_pence": amount_pence,
        },
    )


async def count_claims_with_amount(session, amount, member_id):
    return await session.scalar(
        select(func.count())
        .select_from(Claim)
        .where(Claim.amount_pence == amount, Claim.member_id == member_id)
    )


@pytest.fixture
async def other_member_policy_id(session):
    return (
        await session.scalars(
            select(Policy.policy_id).where(Policy.member_id != CANARY_ID).limit(1)
        )
    ).one()


@pytest.fixture
async def other_member_claim_id(session):
    return (
        await session.scalars(
            select(Claim.claim_id).where(Claim.member_id != CANARY_ID).limit(1)
        )
    ).one()


async def test_log_claim_201(client, write_headers, canary_policy_id):
    r = await post_claim(client, write_headers, key=uuid4(), policy_id=canary_policy_id)
    body = r.json()
    assert r.status_code == 201 and body["status"] == "received"
    assert body["claim_id"].startswith("C-8") and body["notes"] == []
    assert body["amount_pence"] == DEFAULT_AMOUNT


async def test_same_key_same_payload_replays(client, write_headers, canary_policy_id):
    k = uuid4()
    a = await post_claim(client, write_headers, key=k, policy_id=canary_policy_id)
    b = await post_claim(client, write_headers, key=k, policy_id=canary_policy_id)
    assert b.status_code == 201 and a.json() == b.json()


async def test_same_key_different_payload_409(client, write_headers, canary_policy_id):
    k = uuid4()
    await post_claim(
        client, write_headers, key=k, policy_id=canary_policy_id, amount_pence=1000
    )
    r = await post_claim(
        client, write_headers, key=k, policy_id=canary_policy_id, amount_pence=2000
    )
    assert r.status_code == 409
    assert r.json() == {"detail": "idempotency key reused with different payload"}


async def test_same_key_other_path_409(client, write_headers, canary_policy_id):
    k = uuid4()
    first = await post_claim(client, write_headers, key=k, policy_id=canary_policy_id)
    r = await client.post(
        f"/claims/{first.json()['claim_id']}/notes",
        headers=idem(write_headers, k),
        json={"note_type": "escalation", "body": "x"},
    )
    assert r.status_code == 409


async def test_keys_are_scoped_per_client(client, make_token, canary_policy_id):
    k = uuid4()
    scopes = ["claims:write"]
    a = await post_claim(
        client, make_token(scopes, azp="client-a"), key=k, policy_id=canary_policy_id
    )
    b = await post_claim(
        client, make_token(scopes, azp="client-b"), key=k, policy_id=canary_policy_id
    )
    assert a.status_code == b.status_code == 201
    assert a.json()["claim_id"] != b.json()["claim_id"]


async def test_failed_request_does_not_consume_key(
    client, write_headers, canary_policy_id, other_member_policy_id
):
    k = uuid4()
    bad = await post_claim(
        client, write_headers, key=k, policy_id=other_member_policy_id
    )
    assert bad.status_code == 422
    ok = await post_claim(client, write_headers, key=k, policy_id=canary_policy_id)
    assert ok.status_code == 201


async def test_concurrent_same_key_creates_one_row(
    client, write_headers, canary_policy_id, session
):
    k = uuid4()
    rs = await asyncio.gather(
        *[
            post_claim(client, write_headers, key=k, policy_id=canary_policy_id)
            for _ in range(5)
        ]
    )
    assert all(r.status_code == 201 for r in rs)
    assert len({r.json()["claim_id"] for r in rs}) == 1
    assert await count_claims_with_amount(session, DEFAULT_AMOUNT, CANARY_ID) == 1


async def test_concurrent_same_key_different_payload_one_wins(
    client, write_headers, canary_policy_id, session
):
    k = uuid4()
    rs = await asyncio.gather(
        *[
            post_claim(
                client,
                write_headers,
                key=k,
                policy_id=canary_policy_id,
                amount_pence=1000 + i % 2,
            )
            for i in range(6)
        ]
    )
    assert sorted({r.status_code for r in rs}) == [201, 409]
    total = await session.scalar(
        select(func.count())
        .select_from(Claim)
        .where(Claim.amount_pence.in_([1000, 1001]))
    )
    assert total == 1


async def test_missing_idempotency_key_422(client, write_headers, canary_policy_id):
    r = await client.post(
        "/claims",
        headers=write_headers,
        json={
            "member_id": CANARY_ID,
            "policy_id": canary_policy_id,
            "procedure_code": "mri_scan",
            "incident_date": london_today().isoformat(),
            "amount_pence": 100,
        },
    )
    assert r.status_code == 422


async def test_invalid_idempotency_key_422(client, write_headers, canary_policy_id):
    r = await client.post(
        "/claims",
        headers={**write_headers, "Idempotency-Key": "not-a-uuid"},
        json={
            "member_id": CANARY_ID,
            "policy_id": canary_policy_id,
            "procedure_code": "mri_scan",
            "incident_date": london_today().isoformat(),
            "amount_pence": 100,
        },
    )
    assert r.status_code == 422


async def test_read_scope_cannot_write_403(client, read_headers, canary_policy_id):
    r = await post_claim(client, read_headers, key=uuid4(), policy_id=canary_policy_id)
    assert r.status_code == 403


async def test_claim_policy_not_owned_422(
    client, write_headers, other_member_policy_id
):
    r = await post_claim(
        client, write_headers, key=uuid4(), policy_id=other_member_policy_id
    )
    assert r.status_code == 422


async def test_claim_inactive_policy_422(client, write_headers, session):
    row = (
        await session.execute(
            select(Policy.policy_id, Policy.member_id)
            .where(Policy.status != "active")
            .limit(1)
        )
    ).first()
    assert row is not None, "seed should contain a non-active policy"
    r = await post_claim(
        client,
        write_headers,
        key=uuid4(),
        policy_id=row.policy_id,
        member_id=row.member_id,
    )
    assert r.status_code == 422


async def test_claim_future_incident_date_422(client, write_headers, canary_policy_id):
    r = await post_claim(
        client,
        write_headers,
        key=uuid4(),
        policy_id=canary_policy_id,
        incident_date=london_today() + timedelta(days=1),
    )
    assert r.status_code == 422


@pytest.mark.parametrize("amount", [0, 5_000_001])
async def test_claim_amount_bounds_422(client, write_headers, canary_policy_id, amount):
    r = await post_claim(
        client,
        write_headers,
        key=uuid4(),
        policy_id=canary_policy_id,
        amount_pence=amount,
    )
    assert r.status_code == 422


async def test_claim_extra_field_422(client, write_headers, canary_policy_id):
    r = await client.post(
        "/claims",
        headers=idem(write_headers),
        json={
            "member_id": CANARY_ID,
            "policy_id": canary_policy_id,
            "procedure_code": "mri_scan",
            "incident_date": london_today().isoformat(),
            "amount_pence": 100,
            "status": "paid",
        },
    )
    assert r.status_code == 422


async def test_new_claim_visible_via_read_api(
    client, write_headers, read_headers, canary_policy_id
):
    r = await post_claim(client, write_headers, key=uuid4(), policy_id=canary_policy_id)
    got = await client.get(f"/claims/{r.json()['claim_id']}", headers=read_headers)
    assert got.status_code == 200 and got.json()["status"] == "received"


async def test_add_note_201_author_is_principal(client, write_headers, session):
    r = await client.post(
        "/claims/C-900001/notes",
        headers=idem(write_headers),
        json={"note_type": "customer_contact", "body": "Called about MRI"},
    )
    assert r.status_code == 201
    assert r.json()["author_client"] == "test-client"
    count = await session.scalar(
        select(func.count())
        .select_from(ClaimNote)
        .where(ClaimNote.body == "Called about MRI")
    )
    assert count == 1


@pytest.mark.parametrize("body", ["", "   ", "x" * 1001])
async def test_note_body_bounds_422(client, write_headers, body):
    r = await client.post(
        "/claims/C-900001/notes",
        headers=idem(write_headers),
        json={"note_type": "escalation", "body": body},
    )
    assert r.status_code == 422


async def test_note_unknown_claim_404(client, write_headers):
    r = await client.post(
        "/claims/C-777777/notes",
        headers=idem(write_headers),
        json={"note_type": "escalation", "body": "hi"},
    )
    assert r.status_code == 404


async def test_note_read_scope_403(client, read_headers):
    r = await client.post(
        "/claims/C-900001/notes",
        headers=idem(read_headers),
        json={"note_type": "escalation", "body": "hi"},
    )
    assert r.status_code == 403


async def test_update_contact_preference(client, write_headers, session):
    r = await client.put(
        f"/members/{CANARY_ID}/contact-preference",
        headers=idem(write_headers),
        json={"preference": "post"},
    )
    assert r.status_code == 200
    assert r.json()["contact_preference"] == "post" and r.json()["policy_ids"]
    stored = await session.scalar(
        select(Member.contact_preference)
        .where(Member.member_id == CANARY_ID)
        .execution_options(populate_existing=True)
    )
    assert stored.value == "post"


async def test_update_contact_preference_invalid_422(client, write_headers):
    r = await client.put(
        f"/members/{CANARY_ID}/contact-preference",
        headers=idem(write_headers),
        json={"preference": "carrier_pigeon"},
    )
    assert r.status_code == 422


async def test_contact_preference_needs_members_write_403(client, make_token):
    r = await client.put(
        f"/members/{CANARY_ID}/contact-preference",
        headers=idem(make_token(["claims:write", "comms:write"])),
        json={"preference": "post"},
    )
    assert r.status_code == 403


@pytest.mark.parametrize(
    ("pref", "channel", "recipient_field"),
    [
        ("email", "email", "email"),
        ("sms", "sms", "phone"),
        ("phone", "sms", "phone"),
        ("post", "post", "postcode"),
    ],
)
async def test_message_goes_to_contact_on_file(
    client, write_headers, pref, channel, recipient_field
):
    await client.put(
        f"/members/{CANARY_ID}/contact-preference",
        headers=idem(write_headers),
        json={"preference": pref},
    )
    r = await client.post(
        f"/members/{CANARY_ID}/messages",
        headers=idem(write_headers),
        json={"template": "claim_status_update", "claim_id": "C-900001"},
    )
    assert r.status_code == 201
    body = r.json()
    assert body["channel"] == channel
    assert CANARY[recipient_field] in body["recipient"]
    assert body["subject"] == "Update on your claim C-900001"
    assert body["template"] == "claim_status_update"


async def test_message_body_has_no_free_text_fields(client, write_headers):
    r = await client.post(
        f"/members/{CANARY_ID}/messages",
        headers=idem(write_headers),
        json={"template": "callback_confirmation", "recipient": "evil@x.test"},
    )
    assert r.status_code == 422


async def test_message_without_claim_template_needs_no_claim(client, write_headers):
    r = await client.post(
        f"/members/{CANARY_ID}/messages",
        headers=idem(write_headers),
        json={"template": "policy_renewal_reminder"},
    )
    assert r.status_code == 201


async def test_claim_template_requires_claim_id_422(client, write_headers):
    r = await client.post(
        f"/members/{CANARY_ID}/messages",
        headers=idem(write_headers),
        json={"template": "payment_confirmation"},
    )
    assert r.status_code == 422


async def test_claim_status_update_requires_member_claim(
    client, write_headers, other_member_claim_id, session
):
    r = await client.post(
        f"/members/{CANARY_ID}/messages",
        headers=idem(write_headers),
        json={"template": "claim_status_update", "claim_id": other_member_claim_id},
    )
    assert r.status_code == 422
    sent = await session.scalar(
        select(func.count())
        .select_from(Correspondence)
        .where(
            Correspondence.template == "claim_status_update",
            Correspondence.member_id == CANARY_ID,
        )
    )
    assert sent == 0


async def test_message_replay_sends_once(client, write_headers, session):
    k = uuid4()
    payload = {"template": "callback_confirmation"}
    a = await client.post(
        f"/members/{CANARY_ID}/messages", headers=idem(write_headers, k), json=payload
    )
    b = await client.post(
        f"/members/{CANARY_ID}/messages", headers=idem(write_headers, k), json=payload
    )
    assert a.json() == b.json()
    sent = await session.scalar(
        select(func.count())
        .select_from(Correspondence)
        .where(Correspondence.template == "callback_confirmation")
    )
    assert sent == 1


async def test_message_read_scope_403(client, read_headers):
    r = await client.post(
        f"/members/{CANARY_ID}/messages",
        headers=idem(read_headers),
        json={"template": "callback_confirmation"},
    )
    assert r.status_code == 403


def _callback_body(offset: int, reason: str = "claim_query") -> dict:
    return {
        "reason": reason,
        "preferred_date": (london_today() + timedelta(days=offset)).isoformat(),
        "preferred_window": "morning",
    }


async def test_schedule_callback_201(client, write_headers):
    r = await client.post(
        f"/members/{CANARY_ID}/callbacks",
        headers=idem(write_headers),
        json=_callback_body(3),
    )
    assert r.status_code == 201
    assert r.json()["preferred_date"] == _callback_body(3)["preferred_date"]
    assert r.json()["member_id"] == CANARY_ID


@pytest.mark.parametrize("offset", [-1, 31])
async def test_callback_date_out_of_window_422(client, write_headers, offset):
    r = await client.post(
        f"/members/{CANARY_ID}/callbacks",
        headers=idem(write_headers),
        json=_callback_body(offset),
    )
    assert r.status_code == 422


@pytest.mark.parametrize("offset", [0, 30])
async def test_callback_date_boundaries_ok(client, write_headers, offset):
    r = await client.post(
        f"/members/{CANARY_ID}/callbacks",
        headers=idem(write_headers),
        json=_callback_body(offset),
    )
    assert r.status_code == 201


async def test_hostile_member_id_422(client, write_headers):
    r = await client.post(
        "/members/M-12/callbacks",
        headers=idem(write_headers),
        json=_callback_body(1),
    )
    assert r.status_code == 422
