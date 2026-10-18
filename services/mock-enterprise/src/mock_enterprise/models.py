from datetime import date, datetime
from enum import Enum as PyEnum

from sqlalchemy import (
    BigInteger,
    Boolean,
    Date,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    Sequence,
    String,
    Text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from mock_enterprise.enums import (
    CallbackReason,
    CallbackWindow,
    ClaimStatus,
    ContactPreference,
    NoteType,
    PaymentStatus,
    PolicyStatus,
    ProcedureCode,
    Product,
)


def _enum(cls: type[PyEnum]) -> Enum:
    return Enum(
        cls,
        native_enum=False,
        length=64,
        values_callable=lambda e: [x.value for x in e],
        validate_strings=True,
    )


class Base(DeclarativeBase):
    pass


# Claim IDs created via the API (C-800000...) sit above the seeded range.
claim_id_seq = Sequence("claim_id_seq", start=800000, metadata=Base.metadata)


class Member(Base):
    __tablename__ = "members"
    member_id: Mapped[str] = mapped_column(String(16), primary_key=True)
    membership_number: Mapped[str] = mapped_column(String(32), unique=True)
    first_name: Mapped[str] = mapped_column(String(100))
    last_name: Mapped[str] = mapped_column(String(100))
    dob: Mapped[date] = mapped_column(Date)
    email: Mapped[str] = mapped_column(String(200))
    phone: Mapped[str] = mapped_column(String(32))
    address_line: Mapped[str] = mapped_column(String(300))
    postcode: Mapped[str] = mapped_column(String(16))
    contact_preference: Mapped[ContactPreference] = mapped_column(
        _enum(ContactPreference)
    )


class Policy(Base):
    __tablename__ = "policies"
    policy_id: Mapped[str] = mapped_column(String(16), primary_key=True)
    member_id: Mapped[str] = mapped_column(ForeignKey("members.member_id"))
    product: Mapped[Product] = mapped_column(_enum(Product))
    status: Mapped[PolicyStatus] = mapped_column(_enum(PolicyStatus))
    start_date: Mapped[date] = mapped_column(Date)
    renewal_date: Mapped[date] = mapped_column(Date)
    excess_pence: Mapped[int] = mapped_column(BigInteger)
    annual_limit_pence: Mapped[int] = mapped_column(BigInteger)


class CoverageRule(Base):
    __tablename__ = "coverage_rules"
    product: Mapped[Product] = mapped_column(_enum(Product), primary_key=True)
    procedure_code: Mapped[ProcedureCode] = mapped_column(
        _enum(ProcedureCode), primary_key=True
    )
    covered: Mapped[bool] = mapped_column(Boolean)
    requires_preauth: Mapped[bool] = mapped_column(Boolean)
    limit_pence: Mapped[int] = mapped_column(BigInteger)


class Claim(Base):
    __tablename__ = "claims"
    claim_id: Mapped[str] = mapped_column(String(16), primary_key=True)
    policy_id: Mapped[str] = mapped_column(ForeignKey("policies.policy_id"))
    member_id: Mapped[str] = mapped_column(ForeignKey("members.member_id"))
    procedure_code: Mapped[ProcedureCode] = mapped_column(_enum(ProcedureCode))
    status: Mapped[ClaimStatus] = mapped_column(_enum(ClaimStatus))
    amount_pence: Mapped[int] = mapped_column(BigInteger)
    incident_date: Mapped[date] = mapped_column(Date)
    submitted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class ClaimNote(Base):
    __tablename__ = "claim_notes"
    note_id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    claim_id: Mapped[str] = mapped_column(ForeignKey("claims.claim_id"))
    note_type: Mapped[NoteType] = mapped_column(_enum(NoteType))
    body: Mapped[str] = mapped_column(Text)
    author_client: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class Payment(Base):
    __tablename__ = "payments"
    payment_id: Mapped[str] = mapped_column(String(16), primary_key=True)
    claim_id: Mapped[str] = mapped_column(ForeignKey("claims.claim_id"))
    member_id: Mapped[str] = mapped_column(ForeignKey("members.member_id"))
    amount_pence: Mapped[int] = mapped_column(BigInteger)
    status: Mapped[PaymentStatus] = mapped_column(_enum(PaymentStatus))
    paid_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class Correspondence(Base):
    __tablename__ = "correspondence"
    correspondence_id: Mapped[int] = mapped_column(
        Integer, primary_key=True, autoincrement=True
    )
    member_id: Mapped[str] = mapped_column(ForeignKey("members.member_id"))
    channel: Mapped[ContactPreference] = mapped_column(_enum(ContactPreference))
    template: Mapped[str] = mapped_column(String(64))
    recipient: Mapped[str] = mapped_column(String(200))
    subject: Mapped[str] = mapped_column(String(300))
    sent_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class Callback(Base):
    __tablename__ = "callbacks"
    callback_id: Mapped[int] = mapped_column(
        Integer, primary_key=True, autoincrement=True
    )
    member_id: Mapped[str] = mapped_column(ForeignKey("members.member_id"))
    reason: Mapped[CallbackReason] = mapped_column(_enum(CallbackReason))
    preferred_date: Mapped[date] = mapped_column(Date)
    preferred_window: Mapped[CallbackWindow] = mapped_column(_enum(CallbackWindow))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class IdempotencyRecord(Base):
    __tablename__ = "idempotency_records"
    client_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    request_hash: Mapped[str] = mapped_column(String(64))
    response_json: Mapped[str] = mapped_column(Text)
    status_code: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
