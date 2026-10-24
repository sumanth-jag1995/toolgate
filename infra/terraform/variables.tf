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
