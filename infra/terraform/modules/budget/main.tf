# The budget is account-wide (no tag filter), so it counts all spend in the
# AWS account, not only resources tagged project=toolgate.
resource "aws_budgets_budget" "monthly" {
  name         = "toolgate-monthly"
  budget_type  = "COST"
  time_unit    = "MONTHLY"
  limit_amount = tostring(var.budget_usd)
  limit_unit   = "USD"

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 80
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = [var.alert_email]
  }

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 100
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = [var.alert_email]
  }

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 100
    threshold_type             = "PERCENTAGE"
    notification_type          = "FORECASTED"
    subscriber_email_addresses = [var.alert_email]
  }
}
