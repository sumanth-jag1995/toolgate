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
