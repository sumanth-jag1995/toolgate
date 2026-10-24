provider "aws" {
  region = var.region

  default_tags {
    tags = {
      project = "toolgate"
    }
  }
}

locals {
  core_names = ["mock-api", "core-read", "core-write", "comms", "gateway"]
  eval_names = var.enable_eval_targets ? keys(var.eval_target_ports) : []

  # ECR repositories exist for every enabled name so images can be pushed
  # before they are listed in var.images.
  repository_names = toset(concat(local.core_names, local.eval_names))

  # Services are created only for enabled names that have an image.
  active_images = {
    for k, v in var.images : k => v if contains(local.repository_names, k)
  }

  task_names = toset(concat(
    keys(local.active_images),
    contains(keys(local.active_images), "gateway") ? ["gateway-migrate"] : []
  ))
}

module "network" {
  source = "./modules/network"
  # The ALB forwards to the gateway container port.
  service_port = 8200
}

module "data" {
  source             = "./modules/data"
  private_subnet_ids = module.network.private_subnet_ids
  db_sg_id           = module.network.db_sg_id
}

module "cognito" {
  source = "./modules/cognito"
  region = var.region
}

module "budget" {
  source      = "./modules/budget"
  budget_usd  = var.budget_usd
  alert_email = var.alert_email
}

module "observability" {
  source          = "./modules/observability"
  region          = var.region
  log_group_names = local.task_names
}

module "ecs" {
  source = "./modules/ecs"

  region             = var.region
  vpc_id             = module.network.vpc_id
  public_subnet_ids  = module.network.public_subnet_ids
  private_subnet_ids = module.network.private_subnet_ids
  alb_sg_id          = module.network.alb_sg_id
  service_sg_id      = module.network.service_sg_id

  repository_names  = local.repository_names
  images            = local.active_images
  eval_target_ports = { for k, v in var.eval_target_ports : k => v if contains(local.eval_names, k) }
  domain_name       = var.domain_name
  certificate_arn   = var.certificate_arn

  log_group_names  = module.observability.log_group_names
  collector_image  = module.observability.collector_image
  collector_config = module.observability.collector_config

  db_endpoint         = module.data.db_endpoint
  db_secret_arn       = module.data.db_secret_arn
  client_secret_arns  = module.cognito.client_secret_arns
  app_client_ids      = module.cognito.app_client_ids
  server_token_scopes = module.cognito.server_token_scopes
  issuer_url          = module.cognito.issuer_url
  jwks_url            = module.cognito.jwks_url
  token_url           = module.cognito.token_url
}
