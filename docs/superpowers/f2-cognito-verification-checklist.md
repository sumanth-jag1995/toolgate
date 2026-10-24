# F2: verify Cognito mode against a real user pool

Cognito mode (sub-project G) is tested only with locally minted tokens. After `make aws-up`, verify each item against the real pool before relying on it. Record results in the F2 write-up.

1. `client_credentials` POST to the `token_url` output with `client_id` and `client_secret` in the form body (no Basic header) returns 200 for each of the 7 clients. If Cognito insists on HTTP Basic, change `ClientCredentialsAuth` (gateway) and `ClientCredentialsTokenProvider` (MCP servers).
2. The `scope` form parameter is accepted with the exact strings: gateway `core-read/invoke core-write/invoke comms/invoke`; each server its `mock-enterprise/...` scopes. The issued `scope` claim is space-separated with the same strings; a scope the client is not allowed returns `invalid_scope`.
3. With no `scope` parameter the token carries all the client's allowed scopes (the documented no-`TOKEN_SCOPE` behaviour).
4. The decoded access token has `token_use == "access"` (lower case), `client_id` equal to the `app_client_ids` output, `sub == client_id`, an integer `exp`, header `alg` RS256 with a `kid` present in the JWKS, and no `aud` and no `azp`.
5. `iss` equals the `issuer_url` output exactly (`https://cognito-idp.us-east-1.amazonaws.com/<pool_id>`, no trailing slash).
6. The `jwks_url` is reachable from the private subnets (NAT or a VPC endpoint) and `PyJWKClient` resolves the `kid`.
7. End to end: an agent token through the gateway reaches each MCP server and mock-api; an agent token sent straight to an MCP server gets 401; an MCP server's token sent to the gateway gets 401; the gateway's token sent to mock-api is refused (no mock-enterprise scope: 403); the audit row has `client_id` = the agent name and `agent_id` = the raw Cognito client id.
8. The access-token lifetime (10 minutes by default) works with the gateway's 30 s refresh margin and the MCP provider's caching.
9. Cost: Cognito charges for machine-to-machine (client-credentials) use. Check the current pricing for 7 app clients and the token-request volume against the $25 budget.
