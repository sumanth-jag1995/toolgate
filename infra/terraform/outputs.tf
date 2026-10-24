output "vpc_id" {
  value = module.network.vpc_id
}

output "public_subnet_ids" {
  value = module.network.public_subnet_ids
}

output "private_subnet_ids" {
  value = module.network.private_subnet_ids
}

output "alb_sg_id" {
  value = module.network.alb_sg_id
}

output "service_sg_id" {
  value = module.network.service_sg_id
}

output "db_endpoint" {
  value = module.data.db_endpoint
}

output "db_secret_arn" {
  value = module.data.db_secret_arn
}

output "user_pool_id" {
  value = module.cognito.user_pool_id
}

output "issuer_url" {
  value = module.cognito.issuer_url
}

output "app_client_ids" {
  value = module.cognito.app_client_ids
}

output "client_secret_arns" {
  value = module.cognito.client_secret_arns
}

output "budget_name" {
  value = module.budget.budget_name
}
