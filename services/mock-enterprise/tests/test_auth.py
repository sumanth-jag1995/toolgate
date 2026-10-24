from uuid import uuid4


async def test_missing_token_401(client):
    r = await client.get("/members/M-900001")
    assert r.status_code == 401
    assert r.headers["www-authenticate"].startswith("Bearer")


async def test_garbage_token_401(client):
    r = await client.get("/members/M-900001", headers={"Authorization": "Bearer nope"})
    assert r.status_code == 401
    assert r.headers["www-authenticate"].startswith("Bearer")


async def test_expired_token_401(client, make_token):
    r = await client.get(
        "/members/M-900001", headers=make_token(["members:read"], exp_delta=-60)
    )
    assert r.status_code == 401


async def test_wrong_audience_401(client, make_token):
    r = await client.get(
        "/members/M-900001", headers=make_token(["members:read"], aud="core-read")
    )
    assert r.status_code == 401


async def test_missing_scope_403(client, make_token):
    r = await client.get("/members/M-900001", headers=make_token(["claims:read"]))
    assert r.status_code == 403


async def test_valid_scope_200(client, make_token):
    r = await client.get("/members/M-900001", headers=make_token(["members:read"]))
    assert r.status_code == 200


async def test_cognito_mode_accepts_prefixed_scopes(cognito_client, make_cognito_token):
    h = make_cognito_token(["mock-enterprise/members:read"])
    r = await cognito_client.get("/members/M-900001", headers=h)
    assert r.status_code == 200


async def test_cognito_mode_other_prefix_scope_forbidden(
    cognito_client, make_cognito_token
):
    h = make_cognito_token(["other/members:read"])
    r = await cognito_client.get("/members/M-900001", headers=h)
    assert r.status_code == 403


async def test_cognito_mode_rejects_keycloak_shaped_token(cognito_client, make_token):
    r = await cognito_client.get(
        "/members/M-900001", headers=make_token(["members:read"])
    )
    assert r.status_code == 401


async def test_cognito_mode_rejects_id_token(cognito_client, make_cognito_token):
    h = make_cognito_token(["mock-enterprise/members:read"], token_use="id")
    r = await cognito_client.get("/members/M-900001", headers=h)
    assert r.status_code == 401


async def test_keycloak_mode_rejects_cognito_token(client, make_cognito_token):
    h = make_cognito_token(["mock-enterprise/members:read"])
    r = await client.get("/members/M-900001", headers=h)
    assert r.status_code == 401


async def test_cognito_mode_write_route_needs_write_scope(
    cognito_client, make_cognito_token
):
    url = "/members/M-900001/contact-preference"
    body = {"preference": "post"}
    read_only = make_cognito_token(["mock-enterprise/members:read"])
    r = await cognito_client.put(
        url,
        headers={**read_only, "Idempotency-Key": str(uuid4())},
        json=body,
    )
    assert r.status_code == 403
    writer = make_cognito_token(["mock-enterprise/members:write"])
    r = await cognito_client.put(
        url,
        headers={**writer, "Idempotency-Key": str(uuid4())},
        json=body,
    )
    assert r.status_code == 200
