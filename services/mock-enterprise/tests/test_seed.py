from mock_enterprise.canary import CANARY, CANARY_TOKENS
from mock_enterprise.enums import ClaimStatus
from mock_enterprise.models import Claim, Member
from mock_enterprise.seed import seed
from sqlalchemy import select


async def dump_members(session):
    rows = (await session.scalars(select(Member).order_by(Member.member_id))).all()
    return [
        {c.name: getattr(m, c.name) for c in Member.__table__.columns} for m in rows
    ]


async def test_seed_counts(session):
    s = await seed(session, members=50)
    assert s.members == 51  # 50 + canary
    assert s.coverage_rules == 30
    assert s.claims >= 51


async def test_seed_is_deterministic(session):
    a = await seed(session, members=20)
    rows_a = await dump_members(session)
    b = await seed(session, members=20)
    rows_b = await dump_members(session)
    assert a == b and rows_a == rows_b  # Review Focus 1: re-run, no duplicates


async def test_canary_present_and_complete(session):
    await seed(session, members=10)
    m = await session.get(Member, CANARY["member_id"])
    assert m.membership_number == "TG-CANARY-7Q4X9"
    assert m.email == CANARY["email"]
    claims = (
        await session.scalars(select(Claim).where(Claim.member_id == "M-900001"))
    ).all()
    assert {c.status for c in claims} == {ClaimStatus.IN_REVIEW, ClaimStatus.PAID}


async def test_no_synthetic_member_collides_with_canary_tokens(session):
    await seed(session, members=500)
    rows = await dump_members(session)
    non_canary = [r for r in rows if r["member_id"] != "M-900001"]
    assert not any(tok in str(r) for r in non_canary for tok in CANARY_TOKENS)
