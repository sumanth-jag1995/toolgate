variable "vpc_cidr" {
  type    = string
  default = "10.20.0.0/16"
}

variable "service_port" {
  description = "Container port the ALB forwards to."
  type        = number
  default     = 8080
}
