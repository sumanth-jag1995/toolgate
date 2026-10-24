output "user_pool_id" {
  value = aws_cognito_user_pool.this.id
}

output "issuer_url" {
  value = "https://cognito-idp.${var.region}.amazonaws.com/${aws_cognito_user_pool.this.id}"
}

output "app_client_ids" {
  value = { for k, c in aws_cognito_user_pool_client.this : k => c.id }
}

output "client_secret_arns" {
  value = { for k, s in aws_secretsmanager_secret.client : k => s.arn }
}

output "token_url" {
  value = "https://${aws_cognito_user_pool_domain.this.domain}.auth.${var.region}.amazoncognito.com/oauth2/token"
}

output "jwks_url" {
  value = "https://cognito-idp.${var.region}.amazonaws.com/${aws_cognito_user_pool.this.id}/.well-known/jwks.json"
}

# Space-separated scopes exactly as Cognito issues them, from the same variable
# that defines the clients (single source for the MCP servers' TOKEN_SCOPE).
output "server_token_scopes" {
  value = { for n in ["core-read", "core-write", "comms"] : n => join(" ", var.clients[n]) }
}
