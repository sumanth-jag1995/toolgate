resource "aws_cognito_user_pool" "this" {
  name = "toolgate"
}

resource "random_id" "domain" {
  byte_length = 4
}

resource "aws_cognito_user_pool_domain" "this" {
  domain       = "toolgate-${random_id.domain.hex}"
  user_pool_id = aws_cognito_user_pool.this.id
}

resource "aws_cognito_resource_server" "tools" {
  identifier   = var.resource_server_id
  name         = var.resource_server_id
  user_pool_id = aws_cognito_user_pool.this.id

  dynamic "scope" {
    for_each = var.scopes
    content {
      scope_name        = scope.key
      scope_description = scope.value
    }
  }
}

resource "aws_cognito_user_pool_client" "agent" {
  for_each = var.agents

  name         = each.key
  user_pool_id = aws_cognito_user_pool.this.id

  generate_secret                      = true
  allowed_oauth_flows_user_pool_client = true
  allowed_oauth_flows                  = ["client_credentials"]
  allowed_oauth_scopes                 = [for s in each.value : "${aws_cognito_resource_server.tools.identifier}/${s}"]
  supported_identity_providers         = ["COGNITO"]
  access_token_validity                = 10
  token_validity_units {
    access_token = "minutes"
  }
}

# Client secrets live in Secrets Manager only; they are never output.
resource "aws_secretsmanager_secret" "client" {
  for_each                = var.agents
  name_prefix             = "toolgate/cognito-${each.key}-"
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "client" {
  for_each  = var.agents
  secret_id = aws_secretsmanager_secret.client[each.key].id
  secret_string = jsonencode({
    client_id     = aws_cognito_user_pool_client.agent[each.key].id
    client_secret = aws_cognito_user_pool_client.agent[each.key].client_secret
  })
}
