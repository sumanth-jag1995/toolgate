locals {
  db_host = split(":", var.db_endpoint)[0]
  db_port = split(":", var.db_endpoint)[1]

  # libpq-style connection settings. The DSNs carry no host or credentials;
  # asyncpg reads PGHOST/PGPORT/PGUSER/PGPASSWORD/PGDATABASE from the
  # environment. PGUSER/PGPASSWORD arrive through Secrets Manager only.
  pg_env = {
    PGHOST     = local.db_host
    PGPORT     = local.db_port
    PGDATABASE = "toolgate"
  }

  mcp_servers = ["core-read", "core-write", "comms"]

  # Names of the secrets the gateway needs beyond its Cognito client:
  # gateway_db_password and audit_hmac_key (generated below).
  gateway_secret_arn = aws_secretsmanager_secret.gateway.arn

  image_of = merge(
    var.images,
    contains(keys(var.images), "gateway") ? { "gateway-migrate" = var.images["gateway"] } : {}
  )

  # Mirrors infra/docker-compose.yml: container names, ports, commands and the
  # environment variable names. Values that are secrets come from Secrets
  # Manager through `secrets` (valueFrom = "<arn>:<json key>::"); nothing
  # secret is written here.
  mcp_env = {
    MOCK_API_URL = "http://mock-api.toolgate.local:8000"
    TOKEN_URL    = var.token_url
    JWT_ISSUER   = var.issuer_url
    JWKS_URL     = var.jwks_url
  }

  mcp_spec = {
    for n in local.mcp_servers : n => {
      port    = { "core-read" = 8101, "core-write" = 8102, "comms" = 8103 }[n]
      command = ["python", "-m", "toolgate_mcp_servers.${replace(n, "-", "_")}"]
      env     = local.mcp_env
      secrets = {
        CLIENT_ID     = "${var.client_secret_arns[n]}:client_id::"
        CLIENT_SECRET = "${var.client_secret_arns[n]}:client_secret::"
      }
      secret_arns = [var.client_secret_arns[n]]
      cpu         = 256
      memory      = 512
      oneshot     = false
    }
  }

  eval_spec = {
    for n, p in var.eval_target_ports : n => {
      port        = p
      command     = []
      env         = {}
      secrets     = {}
      secret_arns = []
      cpu         = 256
      memory      = 512
      oneshot     = false
    }
  }

  specs = merge(local.mcp_spec, local.eval_spec, {
    "mock-api" = {
      port = 8000
      command = [
        "/bin/sh", "-c",
        "python -m mock_enterprise.seed --reset && exec python -m mock_enterprise.app",
      ]
      env = merge(local.pg_env, {
        JWT_ISSUER   = var.issuer_url
        JWKS_URL     = var.jwks_url
        DATABASE_URL = "postgresql+asyncpg:///toolgate"
      })
      secrets = {
        PGUSER     = "${var.db_secret_arn}:username::"
        PGPASSWORD = "${var.db_secret_arn}:password::"
      }
      secret_arns = [var.db_secret_arn]
      cpu         = 256
      memory      = 512
      oneshot     = false
    }

    "gateway" = {
      port    = 8200
      command = []
      env = merge(local.pg_env, {
        GATEWAY_ISSUER              = var.issuer_url
        GATEWAY_JWKS_URL            = var.jwks_url
        GATEWAY_TOKEN_URL           = var.token_url
        GATEWAY_LOCKFILE_PATH       = "/policy/toolgate.lock.json"
        GATEWAY_POLICY_PATH         = "/policy/agents.yaml"
        GATEWAY_DOWNSTREAMS_PATH    = "/policy/gateway.cloud.yaml"
        GATEWAY_PUBLIC_URL          = local.public_url
        OTEL_EXPORTER_OTLP_ENDPOINT = "http://localhost:4318"
        # App role only (INSERT on gateway.audit_log); its password is PGPASSWORD.
        DATABASE_URL = "postgresql:///toolgate"
        PGUSER       = "toolgate_gateway_app"
      })
      secrets = {
        GATEWAY_CLIENT_ID     = "${var.client_secret_arns["gateway"]}:client_id::"
        GATEWAY_CLIENT_SECRET = "${var.client_secret_arns["gateway"]}:client_secret::"
        PGPASSWORD            = "${local.gateway_secret_arn}:gateway_db_password::"
        AUDIT_HMAC_KEY        = "${local.gateway_secret_arn}:audit_hmac_key::"
      }
      secret_arns = [var.client_secret_arns["gateway"], local.gateway_secret_arn]
      cpu         = 512
      memory      = 1024
      oneshot     = false
    }

    # One-shot (run with `aws ecs run-task`): creates the gateway schema and the
    # INSERT-only app role. Not a service. Connects as the RDS master user.
    "gateway-migrate" = {
      port = 0
      command = [
        "toolgate-gateway", "migrate",
        "--admin-dsn-env", "GATEWAY_ADMIN_DSN",
        "--app-password-env", "GATEWAY_DB_PASSWORD",
      ]
      env = merge(local.pg_env, {
        GATEWAY_ADMIN_DSN = "postgresql:///toolgate"
      })
      secrets = {
        PGUSER              = "${var.db_secret_arn}:username::"
        PGPASSWORD          = "${var.db_secret_arn}:password::"
        GATEWAY_DB_PASSWORD = "${local.gateway_secret_arn}:gateway_db_password::"
      }
      secret_arns = [var.db_secret_arn, local.gateway_secret_arn]
      cpu         = 256
      memory      = 512
      oneshot     = true
    }
  })

  active   = { for k, v in local.specs : k => v if contains(keys(local.image_of), k) }
  services = { for k, v in local.active : k => v if !v.oneshot }

  public_url = var.domain_name == "" ? "http://${aws_lb.this.dns_name}" : "https://${var.domain_name}"
}

# ---------------------------------------------------------------------------
# Secrets generated here for the gateway (never output).
# ---------------------------------------------------------------------------
resource "random_password" "gateway_db" {
  length  = 32
  special = false
}

resource "random_password" "audit_hmac" {
  length  = 48
  special = false
}

resource "aws_secretsmanager_secret" "gateway" {
  name_prefix             = "toolgate/gateway-"
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "gateway" {
  secret_id = aws_secretsmanager_secret.gateway.id
  secret_string = jsonencode({
    gateway_db_password = random_password.gateway_db.result
    audit_hmac_key      = random_password.audit_hmac.result
  })
}

# ---------------------------------------------------------------------------
# Registry, cluster, service discovery
# ---------------------------------------------------------------------------
resource "aws_ecr_repository" "this" {
  for_each             = var.repository_names
  name                 = "toolgate/${each.key}"
  force_delete         = true
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }
}

resource "aws_ecs_cluster" "this" {
  name = "toolgate"
}

resource "aws_service_discovery_private_dns_namespace" "this" {
  name = "toolgate.local"
  vpc  = var.vpc_id
}

resource "aws_service_discovery_service" "this" {
  for_each = local.services
  name     = each.key

  dns_config {
    namespace_id   = aws_service_discovery_private_dns_namespace.this.id
    routing_policy = "MULTIVALUE"

    dns_records {
      type = "A"
      ttl  = 10
    }
  }

  health_check_custom_config {
    failure_threshold = 1
  }
}

# ---------------------------------------------------------------------------
# IAM: one execution role and one task role per task. The execution role fetches
# the task definition `secrets` and is limited to the task's own secrets, ECR
# repository and log group. Task roles carry no secret access.
# ---------------------------------------------------------------------------
data "aws_caller_identity" "current" {}

data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "execution" {
  for_each           = local.active
  name_prefix        = "toolgate-${each.key}-exec-"
  assume_role_policy = data.aws_iam_policy_document.assume.json
}

resource "aws_iam_role" "task" {
  for_each           = local.active
  name_prefix        = "toolgate-${each.key}-task-"
  assume_role_policy = data.aws_iam_policy_document.assume.json
}

data "aws_iam_policy_document" "execution" {
  for_each = local.active

  statement {
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }

  dynamic "statement" {
    for_each = contains(var.repository_names, each.key == "gateway-migrate" ? "gateway" : each.key) ? [1] : []
    content {
      actions   = ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer", "ecr:BatchCheckLayerAvailability"]
      resources = [aws_ecr_repository.this[each.key == "gateway-migrate" ? "gateway" : each.key].arn]
    }
  }

  statement {
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["arn:aws:logs:${var.region}:${data.aws_caller_identity.current.account_id}:log-group:${var.log_group_names[each.key]}:*"]
  }

  dynamic "statement" {
    for_each = length(each.value.secret_arns) > 0 ? [1] : []
    content {
      actions   = ["secretsmanager:GetSecretValue"]
      resources = each.value.secret_arns
    }
  }
}

resource "aws_iam_role_policy" "execution" {
  for_each = local.active
  name     = "execution"
  role     = aws_iam_role.execution[each.key].id
  policy   = data.aws_iam_policy_document.execution[each.key].json
}

# The ADOT sidecar runs under the gateway task role and exports traces to X-Ray.
data "aws_iam_policy_document" "xray" {
  statement {
    actions   = ["xray:PutTraceSegments", "xray:PutTelemetryRecords"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "xray" {
  for_each = contains(keys(local.active), "gateway") ? toset(["gateway"]) : toset([])
  name     = "xray"
  role     = aws_iam_role.task[each.key].id
  policy   = data.aws_iam_policy_document.xray.json
}

# ---------------------------------------------------------------------------
# Task definitions and services (awsvpc, private subnets, no public IP)
# ---------------------------------------------------------------------------
resource "aws_ecs_task_definition" "this" {
  for_each                 = local.active
  family                   = "toolgate-${each.key}"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = each.value.cpu
  memory                   = each.value.memory
  execution_role_arn       = aws_iam_role.execution[each.key].arn
  task_role_arn            = aws_iam_role.task[each.key].arn

  container_definitions = jsonencode(concat(
    [merge(
      {
        name      = each.key
        image     = local.image_of[each.key]
        essential = true
        environment = [
          for k, v in each.value.env : { name = k, value = v }
        ]
        secrets = [
          for k, v in each.value.secrets : { name = k, valueFrom = v }
        ]
        logConfiguration = {
          logDriver = "awslogs"
          options = {
            "awslogs-group"         = var.log_group_names[each.key]
            "awslogs-region"        = var.region
            "awslogs-stream-prefix" = each.key
          }
        }
      },
      each.value.port > 0 ? { portMappings = [{ containerPort = each.value.port, protocol = "tcp" }] } : {},
      length(each.value.command) > 0 ? { command = each.value.command } : {},
    )],
    each.key == "gateway" ? [{
      name      = "otel-collector"
      image     = var.collector_image
      essential = false
      environment = [
        { name = "AOT_CONFIG_CONTENT", value = var.collector_config }
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = var.log_group_names[each.key]
          "awslogs-region"        = var.region
          "awslogs-stream-prefix" = "otel-collector"
        }
      }
    }] : []
  ))
}

resource "aws_ecs_service" "this" {
  for_each        = local.services
  name            = each.key
  cluster         = aws_ecs_cluster.this.id
  task_definition = aws_ecs_task_definition.this[each.key].arn
  desired_count   = 1
  launch_type     = "FARGATE"

  enable_ecs_managed_tags = true
  propagate_tags          = "SERVICE"

  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [var.service_sg_id]
    assign_public_ip = false
  }

  service_registries {
    registry_arn = aws_service_discovery_service.this[each.key].arn
  }

  # Only the gateway is reachable from the internet.
  dynamic "load_balancer" {
    for_each = each.key == "gateway" ? [1] : []
    content {
      target_group_arn = aws_lb_target_group.gateway.arn
      container_name   = "gateway"
      container_port   = 8200
    }
  }

  depends_on = [aws_lb_listener_rule.gateway]
}

# ---------------------------------------------------------------------------
# ALB. Demo-grade HTTP on port 80 unless domain_name (and certificate_arn) are
# set, in which case HTTPS on 443 is used and port 80 redirects to it.
# ---------------------------------------------------------------------------
resource "aws_lb" "this" {
  name                       = "toolgate"
  load_balancer_type         = "application"
  internal                   = false
  subnets                    = var.public_subnet_ids
  security_groups            = [var.alb_sg_id]
  drop_invalid_header_fields = true
  # MCP streamable HTTP can hold responses open.
  idle_timeout = 300
}

resource "aws_lb_target_group" "gateway" {
  name                 = "toolgate-gateway"
  port                 = 8200
  protocol             = "HTTP"
  target_type          = "ip"
  vpc_id               = var.vpc_id
  deregistration_delay = 30

  # /mcp answers 401 without a token, so health uses the RFC 9728 metadata
  # document the gateway serves unauthenticated.
  health_check {
    path    = "/.well-known/oauth-protected-resource/mcp"
    matcher = "200"
  }
}

resource "aws_lb_listener" "http" {
  count             = var.domain_name == "" ? 1 : 0
  load_balancer_arn = aws_lb.this.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "fixed-response"
    fixed_response {
      content_type = "text/plain"
      message_body = "not found"
      status_code  = "404"
    }
  }
}

resource "aws_lb_listener" "http_redirect" {
  count             = var.domain_name != "" ? 1 : 0
  load_balancer_arn = aws_lb.this.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

resource "aws_lb_listener" "https" {
  count             = var.domain_name != "" ? 1 : 0
  load_balancer_arn = aws_lb.this.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.certificate_arn

  default_action {
    type = "fixed-response"
    fixed_response {
      content_type = "text/plain"
      message_body = "not found"
      status_code  = "404"
    }
  }
}

resource "aws_lb_listener_rule" "gateway" {
  listener_arn = var.domain_name == "" ? aws_lb_listener.http[0].arn : aws_lb_listener.https[0].arn
  priority     = 10

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.gateway.arn
  }

  condition {
    path_pattern {
      values = ["/mcp", "/mcp/*", "/.well-known/*"]
    }
  }
}
