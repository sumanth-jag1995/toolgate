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
| Fargate tasks, ALB | added with the next task |
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

## Known limits / F2

- One shared service security group (per-service groups later).
- RDS connections use TLS without certificate verification.
- Cognito access tokens lack `aud`, so the servers need an IdP mode in F2.
- `eval_target_ports` are placeholders until the eval images exist.
- The gateway image must bake `/policy` (Task 6 provides the cloud Dockerfile).
- mock-api runs `seed --reset` on every start.
