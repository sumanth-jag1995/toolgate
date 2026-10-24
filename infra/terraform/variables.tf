variable "region" {
  description = "AWS region for all resources."
  type        = string
  default     = "us-east-1"

  validation {
    condition     = var.region == "us-east-1"
    error_message = "toolgate is deployed to us-east-1 only."
  }
}

variable "alert_email" {
  description = "Email address that receives AWS Budget alerts."
  type        = string

  validation {
    condition     = can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", var.alert_email))
    error_message = "alert_email must be a valid email address."
  }
}

variable "budget_usd" {
  description = "Monthly cost budget in USD."
  type        = number
  default     = 25

  validation {
    condition     = var.budget_usd > 0
    error_message = "budget_usd must be greater than 0."
  }
}

variable "images" {
  description = "Image name to ECR image URI. A Fargate service is created for each name listed (mock-api, core-read, core-write, comms, gateway, and evil-server and sink when enable_eval_targets)."
  type        = map(string)
  default     = {}

  validation {
    condition = alltrue([
      for k in keys(var.images) :
      contains(["mock-api", "core-read", "core-write", "comms", "gateway", "evil-server", "sink"], k)
    ])
    error_message = "images keys must be mock-api, core-read, core-write, comms, gateway, evil-server or sink."
  }

  validation {
    condition     = alltrue([for v in values(var.images) : can(regex("^[^\\s]+$", v))])
    error_message = "images values must be non-empty image URIs without whitespace."
  }
}

variable "enable_eval_targets" {
  description = "Create ECR repositories and services for evil-server and sink (needs images for them; F2 supplies Dockerfiles)."
  type        = bool
  default     = false
}

variable "eval_target_ports" {
  description = "Container ports of the eval targets. Placeholders until the F2 images define them."
  type        = map(number)
  default = {
    "evil-server" = 8301
    "sink"        = 8302
  }
}

variable "domain_name" {
  description = "Public DNS name for the gateway. When empty the ALB serves plain HTTP on port 80 (demo-grade, no TLS); when set, HTTPS on 443 with certificate_arn."
  type        = string
  default     = ""

  validation {
    condition     = var.domain_name == "" || can(regex("^([a-z0-9]([a-z0-9-]*[a-z0-9])?\\.)+[a-z]{2,}$", var.domain_name))
    error_message = "domain_name must be empty or a lowercase DNS name."
  }
}

variable "certificate_arn" {
  description = "ACM certificate ARN for domain_name (same region as the ALB)."
  type        = string
  default     = ""

  validation {
    condition     = var.domain_name == "" || startswith(var.certificate_arn, "arn:aws:acm:")
    error_message = "certificate_arn must be an ACM certificate ARN when domain_name is set."
  }
}
