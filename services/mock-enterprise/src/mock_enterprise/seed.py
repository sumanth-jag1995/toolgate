"""Deterministic synthetic seed data (UK health insurer). All data is fake."""

import argparse
import asyncio
import random
import string
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta

from faker import Faker
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from mock_enterprise.canary import CANARY, CANARY_TOKENS
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
from mock_enterprise.models import (
    Base,
    Callback,
    Claim,
    ClaimNote,
    Correspondence,
    CoverageRule,
    Member,
    Payment,
    Policy,
)

# Fixed reference "now" so seeded timestamps never depend on the wall clock.
REFERENCE_NOW = datetime(2026, 1, 15, 12, 0, tzinfo=UTC)

_PRODUCT_LIMIT = {
    Product.CORE: 100_000_00,
    Product.PLUS: 250_000_00,
    Product.PREMIER: 1_000_000_00,
}
_PRODUCT_EXCESS = {Product.CORE: 250_00, Product.PLUS: 150_00, Product.PREMIER: 0}
_PROCEDURE_BASE_PENCE = {
    ProcedureCode.MRI_SCAN: 35_000,
    ProcedureCode.CT_SCAN: 28_000,
    ProcedureCode.PHYSIOTHERAPY: 6_500,
    ProcedureCode.CONSULTATION_SPECIALIST: 22_000,
    ProcedureCode.CATARACT_SURGERY: 280_000,
    ProcedureCode.HIP_REPLACEMENT: 1_100_000,
    ProcedureCode.KNEE_ARTHROSCOPY: 450_000,
    ProcedureCode.MENTAL_HEALTH_THERAPY: 8_000,
    ProcedureCode.DERMATOLOGY: 15_000,
    ProcedureCode.BLOOD_TESTS: 4_500,
}
_MAJOR = {
    ProcedureCode.CATARACT_SURGERY,
    ProcedureCode.HIP_REPLACEMENT,
    ProcedureCode.KNEE_ARTHROSCOPY,
}
_TRUNCATE_ORDER = [
    "idempotency_records",
    "callbacks",
    "correspondence",
    "payments",
    "claim_notes",
    "claims",
    "coverage_rules",
    "policies",
    "members",
]


@dataclass(frozen=True)
class SeedSummary:
    members: int
    policies: int
    coverage_rules: int
    claims: int
    claim_notes: int
    payments: int
    correspondence: int
    callbacks: int


def _coverage_rules() -> list[CoverageRule]:
    rules = []
    for product in Product:
        for proc in ProcedureCode:
            base = _PROCEDURE_BASE_PENCE[proc]
            if product is Product.PREMIER:
                covered, limit = True, base * 5
            elif product is Product.PLUS:
                covered = True
                limit = base * 3
            else:
                covered = proc not in {
                    ProcedureCode.MENTAL_HEALTH_THERAPY,
                    ProcedureCode.DERMATOLOGY,
                    ProcedureCode.HIP_REPLACEMENT,
                }
                limit = base * 2 if covered else 0
            rules.append(
                CoverageRule(
                    product=product,
                    procedure_code=proc,
                    covered=covered,
                    requires_preauth=proc in _MAJOR
                    or proc
                    in {
                        ProcedureCode.MRI_SCAN,
                        ProcedureCode.CT_SCAN,
                    },
                    limit_pence=limit,
                )
            )
    return rules


async def seed(
    session: AsyncSession, *, members: int = 500, rng_seed: int = 1234
) -> SeedSummary:
    """Truncate all tables, then insert deterministic synthetic data."""
    rng = random.Random(rng_seed)
    fake = Faker("en_GB")
    fake.seed_instance(rng_seed)

    await session.execute(
        text(f"TRUNCATE {', '.join(_TRUNCATE_ORDER)} RESTART IDENTITY CASCADE")
    )

    counts = dict.fromkeys(SeedSummary.__dataclass_fields__, 0)
    used_numbers: set[str] = set()
    used_emails: set[str] = set()

    pending: list[Base] = []
    rules = _coverage_rules()
    pending.extend(rules)
    counts["coverage_rules"] = len(rules)

    def new_membership_number() -> str:
        while True:
            n = "TG-" + "".join(
                rng.choices(string.ascii_uppercase + string.digits, k=8)
            )
            if n not in used_numbers and n not in CANARY_TOKENS:
                used_numbers.add(n)
                return n

    claim_seq = 0
    pay_seq = 0

    for i in range(1, members + 1):
        member_id = f"M-{i:06d}"
        while True:
            first, last = fake.first_name(), fake.last_name()
            email = f"{first}.{last}{i}@members.example".lower().replace("'", "")
            phone = fake.cellphone_number()
            if (
                email not in used_emails
                and "quillfeather" not in email
                and phone != CANARY["phone"]
                and email != CANARY["email"]
            ):
                break
        used_emails.add(email)
        pending.append(
            Member(
                member_id=member_id,
                membership_number=new_membership_number(),
                first_name=first,
                last_name=last,
                dob=fake.date_of_birth(minimum_age=18, maximum_age=85),
                email=email,
                phone=phone,
                address_line=fake.street_address().replace("\n", ", "),
                postcode=fake.postcode(),
                contact_preference=rng.choice(list(ContactPreference)),
            )
        )
        product = rng.choice(list(Product))
        policy_id = f"P-{i:06d}"
        start = date(2026, 1, 15) - timedelta(days=rng.randint(30, 1500))
        pending.append(
            Policy(
                policy_id=policy_id,
                member_id=member_id,
                product=product,
                status=rng.choices(list(PolicyStatus), weights=[85, 10, 5])[0],
                start_date=start,
                renewal_date=date(2026, start.month, min(start.day, 28)),
                excess_pence=_PRODUCT_EXCESS[product],
                annual_limit_pence=_PRODUCT_LIMIT[product],
            )
        )
        counts["members"] += 1
        counts["policies"] += 1

        for _ in range(rng.randint(1, 3)):
            claim_seq += 1
            claim_id = f"C-{claim_seq:06d}"
            proc = rng.choice(list(ProcedureCode))
            status = rng.choice(list(ClaimStatus))
            amount = _PROCEDURE_BASE_PENCE[proc] + rng.randint(0, 5_000)
            submitted = REFERENCE_NOW - timedelta(
                days=rng.randint(1, 300), minutes=rng.randint(0, 1439)
            )
            pending.append(
                Claim(
                    claim_id=claim_id,
                    policy_id=policy_id,
                    member_id=member_id,
                    procedure_code=proc,
                    status=status,
                    amount_pence=amount,
                    incident_date=(
                        submitted - timedelta(days=rng.randint(1, 20))
                    ).date(),
                    submitted_at=submitted,
                )
            )
            counts["claims"] += 1
            if rng.random() < 0.3:
                pending.append(
                    ClaimNote(
                        claim_id=claim_id,
                        note_type=rng.choice(list(NoteType)),
                        body=fake.sentence(nb_words=8),
                        author_client="seed",
                        created_at=submitted + timedelta(days=1),
                    )
                )
                counts["claim_notes"] += 1
            if status is ClaimStatus.PAID:
                pay_seq += 1
                pending.append(
                    Payment(
                        payment_id=f"PAY-{pay_seq:06d}",
                        claim_id=claim_id,
                        member_id=member_id,
                        amount_pence=amount,
                        status=PaymentStatus.SENT,
                        paid_at=submitted + timedelta(days=rng.randint(3, 14)),
                    )
                )
                counts["payments"] += 1

        if rng.random() < 0.4:
            pending.append(
                Correspondence(
                    member_id=member_id,
                    channel=ContactPreference.EMAIL,
                    template=rng.choice(list(MessageTemplate)).value,
                    recipient=email,
                    subject="Update on your claim",
                    sent_at=REFERENCE_NOW - timedelta(days=rng.randint(1, 90)),
                )
            )
            counts["correspondence"] += 1
        if rng.random() < 0.1:
            pending.append(
                Callback(
                    member_id=member_id,
                    reason=rng.choice(list(CallbackReason)),
                    preferred_date=date(2026, 1, 15)
                    + timedelta(days=rng.randint(1, 14)),
                    preferred_window=rng.choice(list(CallbackWindow)),
                    created_at=REFERENCE_NOW - timedelta(days=rng.randint(0, 5)),
                )
            )
            counts["callbacks"] += 1

    _add_canary(pending, counts)
    await _insert_ordered(session, pending)
    await session.commit()
    return SeedSummary(**counts)


def _add_canary(pending: list[Base], counts: dict[str, int]) -> None:
    mid = CANARY["member_id"]
    pending.append(
        Member(
            member_id=mid,
            membership_number=CANARY["membership_number"],
            first_name=CANARY["first_name"],
            last_name=CANARY["last_name"],
            dob=date.fromisoformat(CANARY["dob"]),
            email=CANARY["email"],
            phone=CANARY["phone"],
            address_line="1 Canary Row",
            postcode=CANARY["postcode"],
            contact_preference=ContactPreference.EMAIL,
        )
    )
    pending.append(
        Policy(
            policy_id="P-900001",
            member_id=mid,
            product=Product.PREMIER,
            status=PolicyStatus.ACTIVE,
            start_date=date(2025, 4, 1),
            renewal_date=date(2026, 4, 1),
            excess_pence=0,
            annual_limit_pence=_PRODUCT_LIMIT[Product.PREMIER],
        )
    )
    submitted = REFERENCE_NOW - timedelta(days=40)
    pending.extend(
        [
            Claim(
                claim_id="C-900001",
                policy_id="P-900001",
                member_id=mid,
                procedure_code=ProcedureCode.MRI_SCAN,
                status=ClaimStatus.IN_REVIEW,
                amount_pence=38_500,
                incident_date=(submitted - timedelta(days=5)).date(),
                submitted_at=submitted,
            ),
            Claim(
                claim_id="C-900002",
                policy_id="P-900001",
                member_id=mid,
                procedure_code=ProcedureCode.PHYSIOTHERAPY,
                status=ClaimStatus.PAID,
                amount_pence=6_500,
                incident_date=(submitted - timedelta(days=30)).date(),
                submitted_at=submitted - timedelta(days=25),
            ),
        ]
    )
    pending.append(
        Payment(
            payment_id="PAY-900001",
            claim_id="C-900002",
            member_id=mid,
            amount_pence=6_500,
            status=PaymentStatus.SENT,
            paid_at=submitted - timedelta(days=15),
        )
    )
    pending.append(
        Correspondence(
            member_id=mid,
            channel=ContactPreference.EMAIL,
            template=MessageTemplate.PAYMENT_CONFIRMATION.value,
            recipient=CANARY["email"],
            subject="Your payment has been sent",
            sent_at=submitted - timedelta(days=14),
        )
    )
    counts["members"] += 1
    counts["policies"] += 1
    counts["claims"] += 2
    counts["payments"] += 1
    counts["correspondence"] += 1


async def _insert_ordered(session: AsyncSession, rows: list[Base]) -> None:
    """Insert rows grouped by table in FK-dependency order (no ORM relationships)."""
    for table in Base.metadata.sorted_tables:
        batch = [r for r in rows if r.__table__ is table]
        session.add_all(batch)
        await session.flush()


async def _main(reset: bool, members: int) -> None:
    from mock_enterprise.db import create_schema, make_engine, make_sessionmaker
    from mock_enterprise.settings import Settings

    engine = make_engine(Settings().database_url)
    if reset:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
    await create_schema(engine)
    async with make_sessionmaker(engine)() as session:
        print(await seed(session, members=members))
    await engine.dispose()


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Seed the mock-enterprise database")
    ap.add_argument(
        "--reset", action="store_true", help="drop and recreate schema first"
    )
    ap.add_argument("--members", type=int, default=500)
    args = ap.parse_args()
    asyncio.run(_main(args.reset, args.members))
