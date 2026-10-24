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
