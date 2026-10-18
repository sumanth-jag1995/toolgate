from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from mock_enterprise.auth import require_scope
from mock_enterprise.enums import ClaimStatus, ProcedureCode
from mock_enterprise.models import (
    Claim,
    ClaimNote,
    Correspondence,
    CoverageRule,
    Member,
    Payment,
    Policy,
)
from mock_enterprise.schemas import (
    ClaimOut,
    ClaimSummaryOut,
    CorrespondenceOut,
    CoverageOut,
    MemberOut,
    NoteOut,
    PaymentOut,
    PolicyOut,
)

MemberId = Annotated[str, Path(pattern=r"^M-\d{6}$")]
PolicyId = Annotated[str, Path(pattern=r"^P-\d{6}$")]
ClaimId = Annotated[str, Path(pattern=r"^C-\d{6}$")]
Limit = Annotated[int, Query(ge=1, le=20)]

router = APIRouter()


async def get_session(request: Request):
    async with request.app.state.sessionmaker() as session:
        yield session


Db = Annotated[AsyncSession, Depends(get_session)]


async def _require_member(db: AsyncSession, member_id: str) -> Member:
    member = await db.get(Member, member_id)
    if member is None:
        raise HTTPException(404, "member not found")
    return member


@router.get(
    "/members/{member_id}",
    response_model=MemberOut,
    dependencies=[Depends(require_scope("members:read"))],
)
async def get_member(member_id: MemberId, db: Db):
    member = await _require_member(db, member_id)
    policy_ids = (
        await db.scalars(
            select(Policy.policy_id)
            .where(Policy.member_id == member_id)
            .order_by(Policy.policy_id)
        )
    ).all()
    data = {c.name: getattr(member, c.name) for c in Member.__table__.columns}
    return MemberOut(**data, policy_ids=list(policy_ids))


@router.get(
    "/policies/{policy_id}",
    response_model=PolicyOut,
    dependencies=[Depends(require_scope("policies:read"))],
)
async def get_policy(policy_id: PolicyId, db: Db):
    policy = await db.get(Policy, policy_id)
    if policy is None:
        raise HTTPException(404, "policy not found")
    return policy


@router.get(
    "/coverage",
    response_model=CoverageOut,
    dependencies=[Depends(require_scope("policies:read"))],
)
async def get_coverage(
    db: Db,
    policy_id: Annotated[str, Query(pattern=r"^P-\d{6}$")],
    procedure_code: ProcedureCode,
):
    policy = await db.get(Policy, policy_id)
    if policy is None:
        raise HTTPException(404, "policy not found")
    rule = await db.get(CoverageRule, (policy.product, procedure_code))
    if rule is None:
        raise HTTPException(404, "coverage rule not found")
    return CoverageOut(
        policy_id=policy.policy_id,
        procedure_code=procedure_code,
        covered=rule.covered,
        requires_preauth=rule.requires_preauth,
        limit_pence=rule.limit_pence,
        policy_status=policy.status,
    )


@router.get(
    "/claims/{claim_id}",
    response_model=ClaimOut,
    dependencies=[Depends(require_scope("claims:read"))],
)
async def get_claim(claim_id: ClaimId, db: Db):
    claim = await db.get(Claim, claim_id)
    if claim is None:
        raise HTTPException(404, "claim not found")
    notes = (
        await db.scalars(
            select(ClaimNote)
            .where(ClaimNote.claim_id == claim_id)
            .order_by(ClaimNote.created_at, ClaimNote.note_id)
        )
    ).all()
    payments = (
        await db.scalars(
            select(Payment)
            .where(Payment.claim_id == claim_id)
            .order_by(Payment.payment_id)
        )
    ).all()
    summary = ClaimSummaryOut.model_validate(claim)
    return ClaimOut(
        **summary.model_dump(),
        notes=[NoteOut.model_validate(n) for n in notes],
        payments=[PaymentOut.model_validate(p) for p in payments],
    )


@router.get(
    "/members/{member_id}/claims",
    response_model=list[ClaimSummaryOut],
    dependencies=[Depends(require_scope("claims:read"))],
)
async def list_member_claims(
    member_id: MemberId,
    db: Db,
    status: ClaimStatus | None = None,
    limit: Limit = 10,
):
    await _require_member(db, member_id)
    stmt = select(Claim).where(Claim.member_id == member_id)
    if status is not None:
        stmt = stmt.where(Claim.status == status)
    stmt = stmt.order_by(Claim.submitted_at.desc(), Claim.claim_id.desc()).limit(limit)
    return (await db.scalars(stmt)).all()


@router.get(
    "/members/{member_id}/payments",
    response_model=list[PaymentOut],
    dependencies=[Depends(require_scope("payments:read"))],
)
async def list_member_payments(member_id: MemberId, db: Db, limit: Limit = 10):
    await _require_member(db, member_id)
    stmt = (
        select(Payment)
        .where(Payment.member_id == member_id)
        .order_by(Payment.paid_at.desc().nulls_last(), Payment.payment_id.desc())
        .limit(limit)
    )
    return (await db.scalars(stmt)).all()


@router.get(
    "/members/{member_id}/correspondence",
    response_model=list[CorrespondenceOut],
    dependencies=[Depends(require_scope("comms:read"))],
)
async def list_member_correspondence(member_id: MemberId, db: Db, limit: Limit = 10):
    await _require_member(db, member_id)
    stmt = (
        select(Correspondence)
        .where(Correspondence.member_id == member_id)
        .order_by(
            Correspondence.sent_at.desc(), Correspondence.correspondence_id.desc()
        )
        .limit(limit)
    )
    return (await db.scalars(stmt)).all()
