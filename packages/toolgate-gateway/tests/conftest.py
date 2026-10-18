import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from toolgate_gateway.auth import AgentTokenVerifier

ISSUER = "http://keycloak.test/realms/toolgate"
JWKS_URL = "http://keycloak.test/realms/toolgate/protocol/openid-connect/certs"
AUDIENCE = "toolgate-gateway"


class _StubSigningKey:
    def __init__(self, key):
        self.key = key


class StubJWKClient:
    """Stands in for jwt.PyJWKClient: always returns the test public key."""

    def __init__(self, public_key):
        self._key = _StubSigningKey(public_key)

    def get_signing_key_from_jwt(self, token):
        return self._key


@pytest.fixture(scope="session")
def rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="session")
def make_token(rsa_key):
    """Returns a raw JWT string shaped like a Keycloak access token."""

    def _make(
        *,
        aud=AUDIENCE,
        scopes=(),
        exp_delta=300,
        azp="servicing",
        sub="agent-sub-1",
        iss=ISSUER,
        key=None,
        algorithm="RS256",
    ):
        now = int(time.time())
        claims = {
            "iss": iss,
            "aud": aud,
            "sub": sub,
            "scope": " ".join(scopes),
            "iat": now,
            "exp": now + exp_delta,
        }
        if azp is not None:
            claims["azp"] = azp
        return jwt.encode(
            claims, key or rsa_key, algorithm=algorithm, headers={"kid": "test"}
        )

    return _make


@pytest.fixture
def verifier(rsa_key):
    return AgentTokenVerifier(
        ISSUER,
        AUDIENCE,
        JWKS_URL,
        jwk_client=StubJWKClient(rsa_key.public_key()),
    )
