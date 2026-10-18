"""Shared tool I/O types for the Toolgate MCP servers.

Closed domains mirror ``mock_enterprise.enums`` as ``Literal`` types; this package
must not import ``mock_enterprise`` at runtime.
"""

from datetime import date, datetime
from typing import Annotated, Literal

from pydantic import BaseModel, Field

MemberId = Annotated[
    str, Field(pattern=r"^M-\d{6}$", description="Member ID, e.g. M-000123")
]
PolicyId = Annotated[
    str, Field(pattern=r"^P-\d{6}$", description="Policy ID, e.g. P-000123")
]
ClaimId = Annotated[
    str, Field(pattern=r"^C-\d{6}$", description="Claim ID, e.g. C-000123")
]
ListLimit = Annotated[
    int, Field(ge=1, le=20, description="Maximum number of items to return (1-20)")
]

UUID_RE = (
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
IdempotencyKey = Annotated[
    str,
    Field(
        pattern=UUID_RE,
        json_schema_extra={"format": "uuid"},
        description="Client-generated UUID; retrying with the same key replays the original result",
    ),
]

ProcedureCode = Literal[
    "mri_scan",
    "ct_scan",
    "physiotherapy",
    "consultation_specialist",
    "cataract_surgery",
    "hip_replacement",
    "knee_arthroscopy",
    "mental_health_therapy",
    "dermatology",
    "blood_tests",
]
Product = Literal["core", "plus", "premier"]
PolicyStatus = Literal["active", "lapsed", "cancelled"]
ClaimStatus = Literal["received", "in_review", "approved", "rejected", "paid"]
PaymentStatus = Literal["scheduled", "sent", "failed"]
ContactPreference = Literal["email", "sms", "post", "phone"]
NoteType = Literal["customer_contact", "document_received", "escalation"]


class MemberProfile(BaseModel):
    member_id: str
    membership_number: str
    name: str
    dob: date
    email: str
    phone: str
    postcode: str
    contact_preference: ContactPreference
    policy_ids: list[str]


class PolicyDetails(BaseModel):
    policy_id: str
    member_id: str
    product: Product
    status: PolicyStatus
    start_date: date
    renewal_date: date
    excess_pence: int
    annual_limit_pence: int


class CoverageResult(BaseModel):
    policy_id: str
    procedure_code: ProcedureCode
    covered: bool
    requires_preauth: bool
    limit_pence: int
    policy_status: PolicyStatus


class ClaimNote(BaseModel):
    note_type: NoteType
    body: str
    author_client: str
    created_at: datetime


class Payment(BaseModel):
    payment_id: str
    claim_id: str
    amount_pence: int
    status: PaymentStatus
    paid_at: datetime | None


class ClaimStatusResult(BaseModel):
    claim_id: str
    policy_id: str
    member_id: str
    procedure_code: ProcedureCode
    status: ClaimStatus
    amount_pence: int
    incident_date: date
    submitted_at: datetime
    notes: list[ClaimNote] = Field(
        description="Most recent notes, at most 3, oldest first"
    )
    payments: list[Payment]


class ClaimSummary(BaseModel):
    claim_id: str
    policy_id: str
    procedure_code: ProcedureCode
    status: ClaimStatus
    amount_pence: int
    incident_date: date
    submitted_at: datetime


class ClaimList(BaseModel):
    claims: list[ClaimSummary]


class PaymentList(BaseModel):
    payments: list[Payment]


class CorrespondenceItem(BaseModel):
    correspondence_id: int
    channel: ContactPreference
    template: str
    recipient: str
    subject: str
    sent_at: datetime


class CorrespondenceList(BaseModel):
    correspondence: list[CorrespondenceItem]


class ClaimCreated(BaseModel):
    claim_id: str
    status: ClaimStatus


class NoteAdded(BaseModel):
    note_id: int
    claim_id: str


class ContactPreferenceUpdated(BaseModel):
    member_id: str
    contact_preference: ContactPreference
