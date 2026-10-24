# toolgate Terraform

Local state only (`terraform.tfstate`, git-ignored). The state holds Cognito
client secrets in plaintext, so never commit or share it. Copy
`terraform.tfvars.example` to `terraform.tfvars` (git-ignored) before use.

Approximate running cost (us-east-1, check current AWS pricing before relying on it):

| Item | Approx. cost |
| --- | --- |
| NAT gateway | ~$0.045/h plus data |
| RDS db.t4g.micro | ~$0.016/h plus storage |
| Public IPv4 address | ~$0.005/h each |
| Fargate tasks | ~$0.012/h for a 0.25 vCPU / 0.5 GB task, ~$0.025/h for the 0.5 vCPU / 1 GB gateway (x86 Linux; one task per listed service) |
| Application Load Balancer | ~$0.023/h plus LCU usage |
| Cognito M2M (client credentials) | check current AWS pricing |

The budget alarm (default $25/month) is account-wide. Tear the stack down when
not in use.

## Services

`images` maps a service name to its ECR image URI; a Fargate service is created
only for names listed (ECR repositories exist for all enabled names so images
can be pushed first). `evil-server` and `sink` need `enable_eval_targets = true`
and their own images. Images must bake `/policy` (lockfile, `agents.yaml`,
`gateway.cloud.yaml`). Tasks reach each other at `<name>.toolgate.local`. Run the
`gateway-migrate` task definition once (`aws ecs run-task`) before the gateway.
Without `domain_name` the ALB serves plain HTTP on port 80 (demo-grade).

## Database credentials

Tasks never carry the database password in a URL. `PGUSER` and `PGPASSWORD`
come from the RDS-managed master secret (mock-api, gateway-migrate) or the
generated gateway secret (gateway) through task-definition `secrets`;
`PGHOST`, `PGPORT` and `PGDATABASE` are plain environment, and the DSNs are
`postgresql:///toolgate` and `postgresql+asyncpg:///toolgate`. Rotation caveat:
the RDS-managed secret rotates about every 7 days and tasks read it only at
start, so restart the tasks (force a new deployment) after a rotation.

## Running the migration

Run the `gateway-migrate` task definition once before the gateway, using the
private subnets and the service security group from the outputs:

    aws ecs run-task --cluster <ecs_cluster_name> --launch-type FARGATE \
      --task-definition <gateway_migrate_task_definition_arn> \
      --network-configuration "awsvpcConfiguration={subnets=[<private_subnet_ids>],securityGroups=[<service_sg_id>],assignPublicIp=DISABLED}"

A custom `domain_name` needs a manual CNAME to `alb_dns_name`.

## Identity provider modes

Every ECS task runs with `IDP=cognito` (`GATEWAY_IDP` for the gateway); local compose uses the default `keycloak`. In cognito mode tokens are checked for `iss`, `exp` and `token_use == "access"` (no `aud`), the caller id is the `client_id` claim, and the audience is the scope `<audience>/invoke`. Environment set by the ecs module (plain `environment`, no secrets):

- gateway: `GATEWAY_IDP`, `GATEWAY_AGENT_CLIENT_MAP` (JSON, built from the cognito `app_client_ids` output for exactly the agents in `policy/agents.yaml`), `GATEWAY_TOKEN_SCOPE=core-read/invoke core-write/invoke comms/invoke`.
- core-read, core-write, comms: `IDP`, `TOKEN_SCOPE` (the cognito `server_token_scopes` output, derived from the same `clients` variable that defines the Cognito clients, e.g. `mock-enterprise/members:read`).
- mock-api: `IDP`, `SCOPE_PREFIX=mock-enterprise/` (stripped before the bare-scope check).

Client secrets stay in task-definition `secrets`; only client ids are in the map.

## Known limits / F2

- One shared service security group (per-service groups later).
- RDS connections use TLS without certificate verification.
- Cognito mode is not yet verified against a real Cognito pool. The services have an `IDP=cognito` mode (see below) covered by unit tests with generated keys only. Not yet checked: that Cognito returns the requested scopes for the `client_credentials` grant, and that it accepts the client secret in the form body. That is an F2 step.
- One outbound token for all downstreams. The gateway uses a single client-credentials token for core-read, core-write and comms, so in cognito mode audience separation between servers is scope-based (`<server>/invoke`) and weaker than per-token `aud`. If an untrusted downstream (such as the `evil-server` eval target) were ever added to `policy/gateway.cloud.yaml`, it would receive a token valid at all three servers; this already holds in keycloak mode.
- Cognito mode with no `TOKEN_SCOPE` starts and sends no scope; Cognito then issues all the client's allowed scopes. `GATEWAY_AGENT_CLIENT_MAP` is ignored in keycloak mode.
- Audit identity in cognito mode. The audit trail records `client_id` = the mapped agent name and `agent_id` = the raw Cognito client id (`sub`).
- Deployment note. The client-to-agent mapping is by app client id only. Do not enable user-facing sign-in flows on a mapped app client that has the `toolgate-gateway/invoke` scope: any user signing in through it would become that agent.
- `eval_target_ports` are placeholders until the eval images exist.
- The gateway image must bake `/policy`; `infra/docker/gateway.cloud.Dockerfile` does this and `scripts/push_images.sh` builds it.
- mock-api runs `seed --reset` on every start.
