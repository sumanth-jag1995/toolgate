variable "region" {
  type = string
}

variable "log_group_names" {
  description = "One CloudWatch log group per ECS task definition."
  type        = set(string)
}
