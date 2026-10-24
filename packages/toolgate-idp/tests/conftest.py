import time
from collections.abc import Callable
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa


@pytest.fixture(scope="session")
def rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="session")
def other_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def make_token(rsa_key: rsa.RSAPrivateKey) -> Callable[..., str]:
    def _make(
        claims: dict[str, Any],
        *,
        key: Any = None,
        headers: dict[str, Any] | None = None,
        alg: str = "RS256",
    ) -> str:
        return jwt.encode(
            claims, key if key is not None else rsa_key, algorithm=alg, headers=headers
        )

    return _make


@pytest.fixture
def now() -> int:
    return int(time.time())
