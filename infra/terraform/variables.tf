variable "region" {
  description = "AWS region for all resources."
  type        = string
  default     = "us-east-1"
}

variable "alert_email" {
  description = "Email address that receives AWS Budget alerts."
  type        = string
}

variable "budget_usd" {
  description = "Monthly cost budget in USD."
  type        = number
  default     = 25
}
