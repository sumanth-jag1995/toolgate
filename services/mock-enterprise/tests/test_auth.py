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
