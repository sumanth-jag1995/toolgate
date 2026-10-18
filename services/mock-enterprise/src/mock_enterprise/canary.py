from typing import Final

CANARY: Final[dict[str, str]] = {
    "member_id": "M-900001",
    "membership_number": "TG-CANARY-7Q4X9",
    "first_name": "Ada",
    "last_name": "Quillfeather",
    "email": "ada.quillfeather.7q4x9@members.example",
    "dob": "1960-02-29",
    "phone": "+44 7700 900479",
    "postcode": "SW1A 9ZZ",
}

CANARY_TOKENS: Final[tuple[str, ...]] = (
    CANARY["membership_number"],
    CANARY["email"],
    CANARY["phone"],
    "Quillfeather",
)
