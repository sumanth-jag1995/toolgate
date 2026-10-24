provider "aws" {
  region = var.region

  default_tags {
    tags = {
      project = "toolgate"
    }
  }
}

module "network" {
  source = "./modules/network"
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
