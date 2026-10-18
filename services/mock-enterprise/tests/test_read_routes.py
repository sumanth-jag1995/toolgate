from urllib.parse import quote

import pytest


async def test_get_canary_member(client, read_headers):
    r = await client.get("/members/M-900001", headers=read_headers)
    body = r.json()
    assert r.status_code == 200 and body["membership_number"] == "TG-CANARY-7Q4X9"
    assert len(body["policy_ids"]) == 1


@pytest.mark.parametrize("bad", ["M-12", "M-000001' OR 1=1", "x"])
async def test_malformed_member_id_422(client, read_headers, bad):
    r = await client.get(f"/members/{quote(bad)}", headers=read_headers)
    assert r.status_code == 422


async def test_unknown_member_404(client, read_headers):
    r = await client.get("/members/M-999999", headers=read_headers)
    assert r.status_code == 404
    assert r.json() == {"detail": "member not found"}


async def test_get_policy(client, read_headers, canary_policy_id):
    r = await client.get(f"/policies/{canary_policy_id}", headers=read_headers)
    assert r.status_code == 200
    assert r.json()["product"] == "premier"


async def test_unknown_policy_404(client, read_headers):
    r = await client.get("/policies/P-999999", headers=read_headers)
    assert r.status_code == 404 and r.json() == {"detail": "policy not found"}


async def test_coverage_premier_mri(client, read_headers, canary_policy_id):
    r = await client.get(
        "/coverage",
        params={"policy_id": canary_policy_id, "procedure_code": "mri_scan"},
        headers=read_headers,
    )
    body = r.json()
    assert body["covered"] is True and body["policy_status"] == "active"


async def test_coverage_bad_policy_id_422(client, read_headers):
    r = await client.get(
        "/coverage",
        params={"policy_id": "nope", "procedure_code": "mri_scan"},
        headers=read_headers,
    )
    assert r.status_code == 422


async def test_coverage_unknown_procedure_422(client, read_headers, canary_policy_id):
    r = await client.get(
        "/coverage",
        params={"policy_id": canary_policy_id, "procedure_code": "teleport"},
        headers=read_headers,
    )
    assert r.status_code == 422


async def test_get_claim_with_notes_and_payments(client, read_headers):
    r = await client.get("/claims/C-900002", headers=read_headers)
    body = r.json()
    assert r.status_code == 200 and body["status"] == "paid"
    assert [p["payment_id"] for p in body["payments"]] == ["PAY-900001"]
    assert isinstance(body["notes"], list)


async def test_unknown_claim_404(client, read_headers):
    r = await client.get("/claims/C-999999", headers=read_headers)
    assert r.status_code == 404 and r.json() == {"detail": "claim not found"}


async def test_list_claims_limit_and_order(client, read_headers):
    r = await client.get("/members/M-900001/claims", headers=read_headers)
    rows = r.json()
    assert len(rows) == 2
    assert rows[0]["submitted_at"] >= rows[1]["submitted_at"]
    r = await client.get(
        "/members/M-900001/claims", params={"limit": 1}, headers=read_headers
    )
    assert len(r.json()) == 1


async def test_list_claims_status_filter(client, read_headers):
    r = await client.get(
        "/members/M-900001/claims", params={"status": "paid"}, headers=read_headers
    )
    assert [c["claim_id"] for c in r.json()] == ["C-900002"]


async def test_limit_out_of_range_422(client, read_headers):
    r = await client.get(
        "/members/M-900001/claims", params={"limit": 21}, headers=read_headers
    )
    assert r.status_code == 422


async def test_list_claims_unknown_member_404(client, read_headers):
    r = await client.get("/members/M-999999/claims", headers=read_headers)
    assert r.status_code == 404


async def test_payments(client, read_headers):
    r = await client.get("/members/M-900001/payments", headers=read_headers)
    assert [p["payment_id"] for p in r.json()] == ["PAY-900001"]


async def test_correspondence(client, read_headers):
    r = await client.get(
        "/members/M-900001/correspondence", params={"limit": 5}, headers=read_headers
    )
    assert r.status_code == 200 and isinstance(r.json(), list)


async def test_payments_requires_scope(client, make_token):
    r = await client.get(
        "/members/M-900001/payments", headers=make_token(["members:read"])
    )
    assert r.status_code == 403
