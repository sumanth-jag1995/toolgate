from datetime import date, datetime

from pydantic import BaseModel, ConfigDict

from mock_enterprise.enums import (
    ClaimStatus,
    ContactPreference,
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
