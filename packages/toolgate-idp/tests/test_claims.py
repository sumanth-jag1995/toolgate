import hashlib
import hmac
import json
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from jwt.utils import base64url_encode
from toolgate_idp import (
    IdpConfig,
    decode_token,
    identity_from_claims,
    parse_agent_client_map,
    validate_cognito_settings,
)

ISS = "https://idp.test/pool"
KC = IdpConfig(mode="keycloak", issuer=ISS, audience="toolgate-gateway")
CG = IdpConfig(mode="cognito", issuer=ISS, audience="core-read")
MOCK = IdpConfig(
    mode="cognito",
    issuer=ISS,
    audience="mock-api",
    require_invoke_scope=False,
    scope_prefix="mock-enterprise/",
)
MAPPED = IdpConfig(
    mode="cognito",
    issuer=ISS,
    audience="core-read",
    agent_client_map={"cid-1": "agent-a"},
)


def run(token: str, key: Any, cfg: IdpConfig):
    claims = decode_token(token, key.public_key(), cfg)
    return identity_from_claims(claims, cfg)


def rejected(token: str, key: Any, cfg: IdpConfig) -> bool:
    try:
        return run(token, key, cfg) is None
    except jwt.PyJWTError:
        return True


def cog(now: int, **over: Any) -> dict[str, Any]:
    c: dict[str, Any] = {
        "iss": ISS,
        "exp": now + 300,
        "client_id": "cid-1",
        "token_use": "access",
        "scope": "core-read/invoke",
        "sub": "s",
    }
    c.update(over)
    return {k: v for k, v in c.items() if v is not None}


def kc(now: int, **over: Any) -> dict[str, Any]:
    c: dict[str, Any] = {
        "iss": ISS,
        "exp": now + 300,
        "aud": "toolgate-gateway",
        "azp": "agent-a",
        "scope": "x y",
    }
    c.update(over)
    return {k: v for k, v in c.items() if v is not None}


# keycloak
def test_keycloak_accepts_aud_and_azp(make_token, rsa_key, now):
    ident = run(make_token(kc(now)), rsa_key, KC)
    assert ident is not None
    assert ident.client_id == "agent-a"
    assert ident.scopes == {"x", "y"}


def test_keycloak_missing_azp_rejected(make_token, rsa_key, now):
    assert rejected(make_token(kc(now, azp=None)), rsa_key, KC)


def test_keycloak_wrong_audience_rejected(make_token, rsa_key, now):
    assert rejected(make_token(kc(now, aud="other")), rsa_key, KC)


def test_keycloak_missing_aud_rejected(make_token, rsa_key, now):
    assert rejected(make_token(kc(now, aud=None)), rsa_key, KC)


def test_keycloak_rejects_cognito_shaped_token(make_token, rsa_key, now):
    assert rejected(make_token(cog(now)), rsa_key, KC)


# cognito
def test_cognito_accepts_valid_access_token(make_token, rsa_key, now):
    ident = run(make_token(cog(now, scope="core-read/invoke a:b")), rsa_key, CG)
    assert ident is not None
    assert ident.client_id == "cid-1"
    assert ident.scopes == {"core-read/invoke", "a:b"}
    assert ident.subject == "s"
    assert ident.expires_at == now + 300


def test_cognito_id_token_rejected(make_token, rsa_key, now):
    assert rejected(make_token(cog(now, token_use="id")), rsa_key, CG)


def test_cognito_missing_token_use_rejected(make_token, rsa_key, now):
    assert rejected(make_token(cog(now, token_use=None)), rsa_key, CG)


def test_cognito_missing_invoke_scope_rejected(make_token, rsa_key, now):
    assert rejected(make_token(cog(now, scope="members:read")), rsa_key, CG)


def test_cognito_other_resource_scope_rejected(make_token, rsa_key, now):
    assert rejected(make_token(cog(now, scope="core-write/invoke")), rsa_key, CG)


@pytest.mark.parametrize(
    "scope",
    ["xcore-read/invoke", "core-read/invoke2", "core-read/invoke:admin", "core-read"],
)
def test_cognito_lookalike_scopes_rejected(make_token, rsa_key, now, scope):
    assert rejected(make_token(cog(now, scope=scope)), rsa_key, CG)


def test_cognito_wrong_issuer_rejected(make_token, rsa_key, now):
    assert rejected(make_token(cog(now, iss="https://evil.test")), rsa_key, CG)


def test_cognito_expired_rejected(make_token, rsa_key, now):
    assert rejected(make_token(cog(now, exp=now - 10)), rsa_key, CG)


def test_cognito_missing_exp_rejected(make_token, rsa_key, now):
    assert rejected(make_token(cog(now, exp=None)), rsa_key, CG)


def test_cognito_alg_none_rejected(rsa_key, now):
    tok = jwt.encode(cog(now), key=None, algorithm="none")
    assert rejected(tok, rsa_key, CG)


def test_cognito_hs256_with_public_key_rejected(rsa_key, now):
    pub = rsa_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    head = base64url_encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body = base64url_encode(json.dumps(cog(now)).encode())
    sig = base64url_encode(hmac.new(pub, head + b"." + body, hashlib.sha256).digest())
    tok = (head + b"." + body + b"." + sig).decode()
    assert rejected(tok, rsa_key, CG)


def test_cognito_bad_signature_rejected(make_token, rsa_key, other_key, now):
    assert rejected(make_token(cog(now), key=other_key), rsa_key, CG)


@pytest.mark.parametrize("cid", [None, "", 5, ["a"]])
def test_cognito_bad_client_id_rejected(make_token, rsa_key, now, cid):
    claims = cog(now)
    if cid is None:
        del claims["client_id"]
    else:
        claims["client_id"] = cid
    assert rejected(make_token(claims), rsa_key, CG)


def test_cognito_keycloak_shaped_token_rejected(make_token, rsa_key, now):
    assert rejected(make_token(kc(now, scope="core-read/invoke")), rsa_key, CG)


def test_cognito_aud_claim_is_irrelevant(make_token, rsa_key, now):
    assert run(make_token(cog(now, aud="whatever")), rsa_key, CG) is not None
    assert rejected(make_token(cog(now, aud="whatever", scope="a:b")), rsa_key, CG)


# scope normalisation
def test_scope_prefix_stripped(make_token, rsa_key, now):
    tok = make_token(cog(now, scope="mock-enterprise/members:read"))
    ident = run(tok, rsa_key, MOCK)
    assert ident is not None
    assert ident.scopes == {"members:read"}


@pytest.mark.parametrize(
    "scope",
    [
        "mock-enterprise2/members:read",
        "other/mock-enterprise/members:read",
        "MOCK-ENTERPRISE/members:read",
    ],
)
def test_scope_prefix_not_over_stripped(make_token, rsa_key, now, scope):
    ident = run(make_token(cog(now, scope=scope)), rsa_key, MOCK)
    assert ident is not None
    assert ident.scopes == {scope}


def test_bare_scope_kept_when_present(make_token, rsa_key, now):
    ident = run(make_token(cog(now, scope="members:read")), rsa_key, MOCK)
    assert ident is not None
    assert ident.scopes == {"members:read"}


def test_require_invoke_scope_false_for_mock_api(make_token, rsa_key, now):
    ident = run(make_token(cog(now, scope=None)), rsa_key, MOCK)
    assert ident is not None
    assert ident.scopes == frozenset()


# mapping
def test_agent_mapping_applied(make_token, rsa_key, now):
    ident = run(make_token(cog(now)), rsa_key, MAPPED)
    assert ident is not None
    assert ident.client_id == "agent-a"


def test_unmapped_client_rejected(make_token, rsa_key, now):
    assert rejected(make_token(cog(now, client_id="cid-2")), rsa_key, MAPPED)


def test_empty_map_means_no_mapping(make_token, rsa_key, now):
    ident = run(make_token(cog(now)), rsa_key, CG)
    assert ident is not None
    assert ident.client_id == "cid-1"


def test_parse_agent_client_map_accepts_object():
    raw = '{"c1": "a1", "c2": "a2"}'
    assert parse_agent_client_map(raw) == {"c1": "a1", "c2": "a2"}


@pytest.mark.parametrize(
    "raw",
    [
        "not json",
        "[]",
        '["a"]',
        '{"c": 1}',
        '{"c": ""}',
        '{"": "a"}',
        '{"c": null}',
        "{}",
    ],
)
def test_parse_agent_client_map_rejects(raw):
    with pytest.raises(ValueError):
        parse_agent_client_map(raw)


def test_parse_error_does_not_echo_values():
    for raw in [
        "SECRETVALUE",
        '{"SECRETKEY": 5}',
        '["SECRETVALUE"]',
        '{"SECRETKEY": ""}',
    ]:
        with pytest.raises(ValueError) as ei:
            parse_agent_client_map(raw)
        assert "SECRET" not in str(ei.value)


def test_validate_cognito_settings_requires_audience():
    with pytest.raises(ValueError):
        validate_cognito_settings(IdpConfig(mode="cognito", issuer=ISS, audience=""))
    validate_cognito_settings(CG)
    validate_cognito_settings(IdpConfig(mode="keycloak", issuer=ISS, audience=""))
