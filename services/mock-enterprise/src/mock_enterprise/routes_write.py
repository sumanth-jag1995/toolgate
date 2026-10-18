from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from mock_enterprise.auth import Principal, require_scope
from mock_enterprise.enums import (
    ClaimStatus,
    ContactPreference,
    MessageTemplate,
    PolicyStatus,
)
from mock_enterprise.idempotency import run_idempotent
from mock_enterprise.models import (
    Callback,
    Claim,
    ClaimNote,
    Correspondence,
    Member,
    Policy,
    claim_id_seq,
)
from mock_enterprise.routes_read import (
    ClaimId,
    Db,
    MemberId,
    build_member_out,
)
from mock_enterprise.schemas import (
    CallbackCreate,
    CallbackOut,
    ClaimCreate,
    ClaimOut,
    ContactPreferenceUpdate,
    CorrespondenceOut,
    MemberOut,
    MessageCreate,
    NoteCreate,
    NoteOut,
)

router = APIRouter()

IdemKey = Annotated[UUID, Header(alias="Idempotency-Key")]
Handler = Callable[[], Awaitable[tuple[int, dict]]]

_CLAIM_REQUIRED = {
    MessageTemplate.CLAIM_STATUS_UPDATE,
    MessageTemplate.PAYMENT_CONFIRMATION,
    MessageTemplate.DOCUMENTS_REQUIRED,
}
_SUBJECTS = {
    MessageTemplate.CLAIM_STATUS_UPDATE: "Update on your claim {claim_id}",
    MessageTemplate.PAYMENT_CONFIRMATION: "Payment confirmation for claim {claim_id}",
    MessageTemplate.DOCUMENTS_REQUIRED: "Documents needed for your claim {claim_id}",
    MessageTemplate.CALLBACK_CONFIRMATION: "Your callback is booked",
    MessageTemplate.POLICY_RENEWAL_REMINDER: "Your policy is due for renewal",
}


async def _idempotent(
    request: Request,
    db: AsyncSession,
    principal: Principal,
    key: UUID,
    body: BaseModel,
    handler: Handler,
) -> JSONResponse:
    status_code, payload = await run_idempotent(
        db,
        client_id=principal.client_id,
        key=key,
        request_body={
            "method": request.method,
            "path": request.url.path,
            "body": body.model_dump(mode="json"),
        },
        handler=handler,
    )
    return JSONResponse(status_code=status_code, content=payload)


async def _require_member(db: AsyncSession, member_id: str) -> Member:
    member = await db.get(Member, member_id)
    if member is None:
        raise HTTPException(404, "member not found")
    return member


@router.post("/claims", status_code=201, response_model=ClaimOut)
async def create_claim(
    body: ClaimCreate,
    request: Request,
    db: Db,
    principal: Annotated[Principal, Depends(require_scope("claims:write"))],
    key: IdemKey,
):
    async def handler() -> tuple[int, dict]:
        await _require_member(db, body.member_id)
        policy = await db.get(Policy, body.policy_id)
        if (
            policy is None
            or policy.member_id != body.member_id
            or policy.status != PolicyStatus.ACTIVE
        ):
            raise HTTPException(
                422, "policy not found, not owned by member, or not active"
            )
        seq = await db.scalar(select(claim_id_seq.next_value()))
        claim = Claim(
            claim_id=f"C-{seq:06d}",
            policy_id=body.policy_id,
            member_id=body.member_id,
            procedure_code=body.procedure_code,
            status=ClaimStatus.RECEIVED,
            amount_pence=body.amount_pence,
            incident_date=body.incident_date,
            submitted_at=datetime.now(UTC),
        )
        db.add(claim)
        await db.flush()
        out = ClaimOut(
            **{
                f: getattr(claim, f)
                for f in (
                    "claim_id",
                    "policy_id",
                    "member_id",
                    "procedure_code",
                    "status",
                    "amount_pence",
                    "incident_date",
                    "submitted_at",
                )
            },
            notes=[],
            payments=[],
        )
        return 201, out.model_dump(mode="json")

    return await _idempotent(request, db, principal, key, body, handler)


@router.post("/claims/{claim_id}/notes", status_code=201, response_model=NoteOut)
async def add_claim_note(
    claim_id: ClaimId,
    body: NoteCreate,
    request: Request,
    db: Db,
    principal: Annotated[Principal, Depends(require_scope("claims:write"))],
    key: IdemKey,
):
    async def handler() -> tuple[int, dict]:
        if await db.get(Claim, claim_id) is None:
            raise HTTPException(404, "claim not found")
        note = ClaimNote(
            claim_id=claim_id,
            note_type=body.note_type,
            body=body.body,
            author_client=principal.client_id,
            created_at=datetime.now(UTC),
        )
        db.add(note)
        await db.flush()
        return 201, NoteOut.model_validate(note).model_dump(mode="json")

    return await _idempotent(request, db, principal, key, body, handler)


@router.put("/members/{member_id}/contact-preference", response_model=MemberOut)
async def update_contact_preference(
    member_id: MemberId,
    body: ContactPreferenceUpdate,
    request: Request,
    db: Db,
    principal: Annotated[Principal, Depends(require_scope("members:write"))],
    key: IdemKey,
):
    async def handler() -> tuple[int, dict]:
        member = await _require_member(db, member_id)
        member.contact_preference = body.preference
        await db.flush()
        out = await build_member_out(db, member)
        return 200, out.model_dump(mode="json")

    return await _idempotent(request, db, principal, key, body, handler)


def _contact_on_file(member: Member) -> tuple[ContactPreference, str]:
    match member.contact_preference:
        case ContactPreference.EMAIL:
            return ContactPreference.EMAIL, member.email
        case ContactPreference.SMS | ContactPreference.PHONE:
            return ContactPreference.SMS, member.phone
        case _:
            return ContactPreference.POST, f"{member.address_line}, {member.postcode}"


@router.post(
    "/members/{member_id}/messages", status_code=201, response_model=CorrespondenceOut
)
async def send_message(
    member_id: MemberId,
    body: MessageCreate,
    request: Request,
    db: Db,
    principal: Annotated[Principal, Depends(require_scope("comms:write"))],
    key: IdemKey,
):
    async def handler() -> tuple[int, dict]:
        member = await _require_member(db, member_id)
        if body.template in _CLAIM_REQUIRED and body.claim_id is None:
            raise HTTPException(422, f"claim_id required for {body.template.value}")
        if body.claim_id is not None:
            claim = await db.get(Claim, body.claim_id)
            if claim is None or claim.member_id != member_id:
                raise HTTPException(422, "claim not found for this member")
        channel, recipient = _contact_on_file(member)
        row = Correspondence(
            member_id=member_id,
            channel=channel,
            template=body.template.value,
            recipient=recipient,
            subject=_SUBJECTS[body.template].format(claim_id=body.claim_id),
            sent_at=datetime.now(UTC),
        )
        db.add(row)
        await db.flush()
        return 201, CorrespondenceOut.model_validate(row).model_dump(mode="json")

    return await _idempotent(request, db, principal, key, body, handler)


@router.post(
    "/members/{member_id}/callbacks", status_code=201, response_model=CallbackOut
)
async def schedule_callback(
    member_id: MemberId,
    body: CallbackCreate,
    request: Request,
    db: Db,
    principal: Annotated[Principal, Depends(require_scope("comms:write"))],
    key: IdemKey,
):
    async def handler() -> tuple[int, dict]:
        await _require_member(db, member_id)
        row = Callback(
            member_id=member_id,
            reason=body.reason,
            preferred_date=body.preferred_date,
            preferred_window=body.preferred_window,
            created_at=datetime.now(UTC),
        )
        db.add(row)
        await db.flush()
        return 201, CallbackOut.model_validate(row).model_dump(mode="json")

    return await _idempotent(request, db, principal, key, body, handler)
