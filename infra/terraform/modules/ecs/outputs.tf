output "alb_dns_name" {
  value = aws_lb.this.dns_name
}

output "cluster_name" {
  value = aws_ecs_cluster.this.name
}

output "ecr_repository_urls" {
  value = { for k, r in aws_ecr_repository.this : k => r.repository_url }
}

output "service_names" {
  value = [for k, s in aws_ecs_service.this : s.name]
}

output "gateway_migrate_task_definition_arn" {
  value = try(aws_ecs_task_definition.this["gateway-migrate"].arn, null)
}
