from enum import StrEnum


class ProcedureCode(StrEnum):
    MRI_SCAN = "mri_scan"
    CT_SCAN = "ct_scan"
    PHYSIOTHERAPY = "physiotherapy"
    CONSULTATION_SPECIALIST = "consultation_specialist"
    CATARACT_SURGERY = "cataract_surgery"
    HIP_REPLACEMENT = "hip_replacement"
    KNEE_ARTHROSCOPY = "knee_arthroscopy"
    MENTAL_HEALTH_THERAPY = "mental_health_therapy"
    DERMATOLOGY = "dermatology"
    BLOOD_TESTS = "blood_tests"


class Product(StrEnum):
    CORE = "core"
    PLUS = "plus"
    PREMIER = "premier"


class PolicyStatus(StrEnum):
    ACTIVE = "active"
    LAPSED = "lapsed"
    CANCELLED = "cancelled"


class ClaimStatus(StrEnum):
    RECEIVED = "received"
    IN_REVIEW = "in_review"
    APPROVED = "approved"
    REJECTED = "rejected"
    PAID = "paid"


class PaymentStatus(StrEnum):
    SCHEDULED = "scheduled"
    SENT = "sent"
    FAILED = "failed"


class ContactPreference(StrEnum):
    EMAIL = "email"
    SMS = "sms"
    POST = "post"
    PHONE = "phone"


class NoteType(StrEnum):
    CUSTOMER_CONTACT = "customer_contact"
    DOCUMENT_RECEIVED = "document_received"
    ESCALATION = "escalation"


class MessageTemplate(StrEnum):
    CLAIM_STATUS_UPDATE = "claim_status_update"
    PAYMENT_CONFIRMATION = "payment_confirmation"
    DOCUMENTS_REQUIRED = "documents_required"
    CALLBACK_CONFIRMATION = "callback_confirmation"
    POLICY_RENEWAL_REMINDER = "policy_renewal_reminder"


class CallbackReason(StrEnum):
    CLAIM_QUERY = "claim_query"
    PAYMENT_QUERY = "payment_query"
    POLICY_QUERY = "policy_query"
    COMPLAINT = "complaint"


class CallbackWindow(StrEnum):
    MORNING = "morning"
    AFTERNOON = "afternoon"
