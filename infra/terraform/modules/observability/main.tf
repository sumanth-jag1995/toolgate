resource "aws_cloudwatch_log_group" "this" {
  for_each          = var.log_group_names
  name              = "/toolgate/${each.key}"
  retention_in_days = 7
}

# ADOT collector sidecar for the gateway: receives OTLP/HTTP on localhost:4318
# (the gateway's OTEL_EXPORTER_OTLP_ENDPOINT) and exports traces to X-Ray.
locals {
  collector_config = yamlencode({
    receivers = {
      otlp = { protocols = { http = { endpoint = "0.0.0.0:4318" } } }
    }
    exporters = {
      awsxray = { region = var.region }
    }
    service = {
      pipelines = {
        traces = { receivers = ["otlp"], exporters = ["awsxray"] }
      }
    }
  })
}
