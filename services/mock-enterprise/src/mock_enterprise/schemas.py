from datetime import date, datetime, timedelta
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, field_validator

from mock_enterprise.enums import (
    CallbackReason,
    CallbackWindow,
    ClaimStatus,
    ContactPreference,
    MessageTemplate,
    NoteType,
    PaymentStatus,
    PolicyStatus,
    ProcedureCode,
    Product,
)


class _Out(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class MemberOut(_Out):
    member_id: str
    membership_number: str
    first_name: str
    last_name: str
    dob: date
    email: str
    phone: str
    address_line: str
    postcode: str
    contact_preference: ContactPreference
    policy_ids: list[str]


class PolicyOut(_Out):
    policy_id: str
    member_id: str
    product: Product
    status: PolicyStatus
    start_date: date
    renewal_date: date
    excess_pence: int
    annual_limit_pence: int


class CoverageOut(_Out):
    policy_id: str
    procedure_code: ProcedureCode
    covered: bool
    requires_preauth: bool
    limit_pence: int
    policy_status: PolicyStatus


class NoteOut(_Out):
    note_id: int
    claim_id: str
    note_type: NoteType
    body: str
    author_client: str
    created_at: datetime


class PaymentOut(_Out):
    payment_id: str
    claim_id: str
    member_id: str
    amount_pence: int
    status: PaymentStatus
    paid_at: datetime | None


class ClaimSummaryOut(_Out):
    claim_id: str
    policy_id: str
    member_id: str
    procedure_code: ProcedureCode
    status: ClaimStatus
    amount_pence: int
    incident_date: date
    submitted_at: datetime


class ClaimOut(ClaimSummaryOut):
    notes: list[NoteOut]
    payments: list[PaymentOut]


class CorrespondenceOut(_Out):
    correspondence_id: int
    member_id: str
    channel: ContactPreference
    template: str
    recipient: str
    subject: str
    sent_at: datetime


class CallbackOut(_Out):
    callback_id: int
    member_id: str
    reason: CallbackReason
    preferred_date: date
    preferred_window: CallbackWindow
    created_at: datetime


class _In(BaseModel):
    model_config = ConfigDict(extra="forbid")


MemberIdStr = Annotated[str, Field(pattern=r"^M-\d{6}$")]
PolicyIdStr = Annotated[str, Field(pattern=r"^P-\d{6}$")]
ClaimIdStr = Annotated[str, Field(pattern=r"^C-\d{6}$")]


class ClaimCreate(_In):
    member_id: MemberIdStr
    policy_id: PolicyIdStr
    procedure_code: ProcedureCode
    incident_date: date
    amount_pence: Annotated[int, Field(ge=1, le=5_000_000)]

    @field_validator("incident_date")
    @classmethod
    def _not_future(cls, v: date) -> date:
        if v > date.today():
            raise ValueError("incident_date must not be in the future")
        return v


class NoteCreate(_In):
    note_type: NoteType
    body: Annotated[str, Field(min_length=1, max_length=1000)]

    @field_validator("body")
    @classmethod
    def _not_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("body must not be blank")
        return v


class ContactPreferenceUpdate(_In):
    preference: ContactPreference


class MessageCreate(_In):
    template: MessageTemplate
    claim_id: ClaimIdStr | None = None


class CallbackCreate(_In):
    reason: CallbackReason
    preferred_date: date
    preferred_window: CallbackWindow

    @field_validator("preferred_date")
    @classmethod
    def _within_window(cls, v: date) -> date:
        today = date.today()
        if not today <= v <= today + timedelta(days=30):
            raise ValueError("preferred_date must be within the next 30 days")
        return v
