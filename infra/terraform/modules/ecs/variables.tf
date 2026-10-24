variable "region" {
  type = string
}

variable "vpc_id" {
  type = string
}

variable "public_subnet_ids" {
  type = list(string)
}

variable "private_subnet_ids" {
  type = list(string)
}

variable "alb_sg_id" {
  type = string
}

variable "service_sg_id" {
  type = string
}

variable "repository_names" {
  description = "ECR repositories to create (one per enabled image name)."
  type        = set(string)
}

variable "images" {
  description = "Image name to ECR image URI. A service is created only for names present here."
  type        = map(string)
  default     = {}
}

variable "eval_target_ports" {
  description = "Container ports for the optional eval targets (placeholders until F2 supplies the images)."
  type        = map(number)
}

variable "domain_name" {
  type    = string
  default = ""
}

variable "certificate_arn" {
  type    = string
  default = ""
}

variable "log_group_names" {
  description = "Task name to CloudWatch log group name."
  type        = map(string)
}

variable "collector_image" {
  type = string
}

variable "collector_config" {
  type = string
}

variable "db_endpoint" {
  description = "host:port of the RDS instance."
  type        = string
}

variable "db_secret_arn" {
  description = "RDS-managed master secret (JSON with username and password keys)."
  type        = string
}

variable "client_secret_arns" {
  description = "Cognito client name to Secrets Manager ARN (JSON with client_id and client_secret keys)."
  type        = map(string)
}

variable "issuer_url" {
  type = string
}

variable "jwks_url" {
  type = string
}

variable "token_url" {
  type = string
}

variable "app_client_ids" {
  description = "Cognito client name to app client id (not a secret)."
  type        = map(string)
}

variable "server_token_scopes" {
  description = "MCP server name to the space-separated mock-enterprise scopes its Cognito client is granted."
  type        = map(string)
}
