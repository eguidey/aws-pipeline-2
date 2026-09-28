# ---------------------------------------------------------------------------
# Root configuration: composes the modules into one environment.
# Pick the environment with a variables file + backend file:
#   terraform init  -backend-config=environments/prod.backend.hcl
#   terraform apply -var-file=environments/prod.tfvars
# ---------------------------------------------------------------------------

locals {
  # Preventive guardrails shared with policy/check.py (plan-time and deploy-time gates).
  policy = jsondecode(file("${path.module}/../policy/rules.json"))
}

module "kms" {
  source = "./modules/kms"
  name   = var.project_name
  region = var.region
}

module "network" {
  source                = "./modules/network"
  name                  = var.project_name
  vpc_cidr              = var.vpc_cidr
  allowed_ingress_cidrs = var.allowed_ingress_cidrs
  kms_key_arn           = module.kms.key_arn
  log_retention_days    = var.log_retention_days
}

module "registry" {
  source      = "./modules/registry"
  name        = var.project_name
  kms_key_arn = module.kms.key_arn
}

module "app_service" {
  source             = "./modules/app_service"
  name               = var.project_name
  region             = var.region
  kms_key_arn        = module.kms.key_arn
  repository_arn     = module.registry.repository_arn
  repository_url     = module.registry.repository_url
  subnet_ids         = module.network.public_subnet_ids
  security_group_ids = [module.network.api_security_group_id]
  desired_count      = var.desired_count
  cpu                = tostring(var.task_cpu)
  memory             = tostring(var.task_memory)
  log_retention_days = var.log_retention_days
}

module "detection" {
  source                  = "./modules/detection"
  name                    = var.project_name
  kms_key_arn             = module.kms.key_arn
  alert_email             = var.alert_email
  app_log_group_name      = module.app_service.app_log_group_name
  log_retention_days      = var.log_retention_days
  hunting_queries_dir     = "${path.root}/../detections"
  correlation_queries_dir = "${path.root}/../detections/correlation"
}

module "cicd_identity" {
  source                    = "./modules/cicd_identity"
  name                      = var.project_name
  region                    = var.region
  github_repository         = var.github_repository
  github_owner_id           = var.github_owner_id
  github_repository_id      = var.github_repository_id
  github_deploy_branch      = var.github_deploy_branch
  github_environment        = var.github_environment
  create_oidc_provider      = var.create_github_oidc_provider
  repository_arn            = module.registry.repository_arn
  cluster_name              = module.app_service.cluster_name
  cluster_arn               = module.app_service.cluster_arn
  service_arn               = module.app_service.service_arn
  execution_role_arn        = module.app_service.execution_role_arn
  deployments_log_group_arn = module.detection.deployments_log_group_arn
  kms_key_arn               = module.kms.key_arn
  allowed_regions           = local.policy.allowed_regions
}

module "response" {
  source             = "./modules/response"
  name               = var.project_name
  kms_key_arn        = module.kms.key_arn
  app_log_group_name = module.app_service.app_log_group_name
  app_log_group_arn  = module.app_service.app_log_group_arn
  nacl_id            = module.network.nacl_id
  nacl_arn           = module.network.nacl_arn
  alert_topic_arn    = module.detection.alert_topic_arn
  trigger_alarm_arns = [module.detection.alarm_arns["brute_force"], module.detection.alarm_arns["injection_attempt"]]
  source_file        = "${path.root}/../lambda/auto_response/handler.py"
  build_dir          = "${path.root}/.build"
  mode               = var.auto_response_mode
  block_minutes      = var.block_minutes
  never_block_cidrs  = var.never_block_cidrs
  log_retention_days = var.log_retention_days
}

module "guardrails" {
  source             = "./modules/guardrails"
  name               = var.project_name
  alert_topic_arn    = module.detection.alert_topic_arn
  alert_email        = var.alert_email
  enable_aws_config  = var.enable_aws_config
  enable_guardduty   = var.enable_guardduty
  monthly_budget_usd = var.monthly_budget_usd
}
