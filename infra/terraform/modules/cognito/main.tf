resource "aws_cognito_user_pool" "this" {
  name = "toolgate"

  admin_create_user_config {
    allow_admin_create_user_only = true
  }
}

resource "random_id" "domain" {
  byte_length = 4
}

resource "aws_cognito_user_pool_domain" "this" {
  domain       = "toolgate-${random_id.domain.hex}"
  user_pool_id = aws_cognito_user_pool.this.id
}

resource "aws_cognito_resource_server" "this" {
  for_each     = var.resource_servers
  identifier   = each.key
  name         = each.key
  user_pool_id = aws_cognito_user_pool.this.id

  dynamic "scope" {
    for_each = each.value
    content {
      scope_name        = scope.value
      scope_description = "${each.key} ${scope.value}"
    }
  }
}

# NOTE: Cognito access tokens carry `client_id` and `scope` but no `aud` or
# `azp`. The services run in IDP=cognito mode, where the audience check is
# replaced by the `<audience>/invoke` scope and the caller id is `client_id`.
resource "aws_cognito_user_pool_client" "this" {
  for_each     = var.clients
  name         = each.key
  user_pool_id = aws_cognito_user_pool.this.id

  generate_secret                      = true
  explicit_auth_flows                  = ["ALLOW_REFRESH_TOKEN_AUTH"]
  allowed_oauth_flows_user_pool_client = true
  allowed_oauth_flows                  = ["client_credentials"]
  allowed_oauth_scopes                 = each.value
  supported_identity_providers         = ["COGNITO"]
  access_token_validity                = 10

  token_validity_units {
    access_token = "minutes"
  }

  depends_on = [aws_cognito_resource_server.this]
}

# Client secrets are stored in Secrets Manager only and are never output.
# They also sit in plaintext in the local Terraform state (git-ignored).
resource "aws_secretsmanager_secret" "client" {
  for_each                = var.clients
  name_prefix             = "toolgate/cognito-${each.key}-"
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "client" {
  for_each  = var.clients
  secret_id = aws_secretsmanager_secret.client[each.key].id
  secret_string = jsonencode({
    client_id     = aws_cognito_user_pool_client.this[each.key].id
    client_secret = aws_cognito_user_pool_client.this[each.key].client_secret
  })
}
