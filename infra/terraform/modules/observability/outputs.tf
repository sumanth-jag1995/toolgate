output "log_group_names" {
  value = { for k, g in aws_cloudwatch_log_group.this : k => g.name }
}

output "collector_image" {
  value = "public.ecr.aws/aws-observability/aws-otel-collector:v0.40.0"
}

output "collector_config" {
  value = local.collector_config
}

output "collector_port" {
  value = 4318
}
