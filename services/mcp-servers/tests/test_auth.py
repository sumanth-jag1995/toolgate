import jwt
from cryptography.hazmat.primitives.asymmetric import rsa


async def test_valid_token_accepted(verifier, make_token):
    at = await verifier.verify_token(make_token(aud="core-read", scopes=[]))
    assert at is not None and at.client_id == "dev-tester"
    assert at.scopes == []


async def test_scopes_and_expiry_extracted(verifier, make_token):
    token = make_token(scopes=["members:read", "claims:read"])
    at = await verifier.verify_token(token)
    assert at is not None
    assert at.scopes == ["members:read", "claims:read"]
    assert at.token == token
    assert (
        at.expires_at == jwt.decode(token, options={"verify_signature": False})["exp"]
    )


async def test_audience_list_accepted(verifier, make_token):
    at = await verifier.verify_token(make_token(aud=["account", "core-read"]))
    assert at is not None


async def test_wrong_audience_rejected(verifier, make_token):
    assert await verifier.verify_token(make_token(aud="core-write")) is None


async def test_wrong_issuer_rejected(verifier, make_token):
    assert (
        await verifier.verify_token(make_token(iss="http://evil.test/realms/x")) is None
    )


async def test_expired_rejected(verifier, make_token):
    assert await verifier.verify_token(make_token(exp_delta=-60)) is None


async def test_bad_signature_rejected(verifier, make_token):
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    assert await verifier.verify_token(make_token(key=other)) is None


async def test_missing_azp_rejected(verifier, make_token):
    assert await verifier.verify_token(make_token(azp="")) is None


async def test_hs256_rejected(verifier):
    token = jwt.encode(
        {"iss": "x", "aud": "core-read", "exp": 9999999999, "azp": "a"},
        "secret-secret-secret-secret-secret!",
        algorithm="HS256",
    )
    assert await verifier.verify_token(token) is None


async def test_garbage_rejected(verifier):
    assert await verifier.verify_token("not-a-jwt") is None


async def test_jwks_failure_rejected(make_token):
    from toolgate_mcp_servers.auth import JwtTokenVerifier

    class Boom:
        def get_signing_key_from_jwt(self, token):
            raise jwt.PyJWKClientConnectionError("jwks down")

    v = JwtTokenVerifier("http://i", "core-read", "http://j", jwk_client=Boom())
    assert await v.verify_token(make_token()) is None
