locals {
  repository_full_name           = "${var.github_org}/${var.github_repo}"
  environment                    = var.environment
  cluster_name                   = coalesce(var.cluster_name, "ai-dev-${var.environment}-autopilot")
  network_name                   = coalesce(var.network_name, "ai-dev-${var.environment}")
  artifact_registry_repository   = coalesce(var.artifact_registry_repo, "ai-dev-platform-${var.environment}")
  runtime_service_account_id     = coalesce(var.runtime_service_account_id, "web-runtime-${var.environment}")
  api_gateway_runtime_service_account_id = coalesce(var.api_gateway_runtime_service_account_id, "api-gateway-runtime-${var.environment}")
  github_workload_identity_sa_id = coalesce(var.github_workload_identity_sa_id, "github-terraform-${var.environment}")
  workload_identity_pool_id      = coalesce(var.workload_identity_pool_id, "github-wif-pool-${var.environment}")
  workload_identity_provider_id  = coalesce(var.workload_identity_provider_id, "github-provider-${var.environment}")
  wif_attribute_condition        = "attribute.repository == '${local.repository_full_name}' && (attribute.ref == 'refs/heads/main' || (attribute.ref != null && attribute.ref.matches('^refs/pull/.*')))"
}

resource "google_project_service" "required" {
  for_each = toset([
    "artifactregistry.googleapis.com",
    "container.googleapis.com",
    "containeranalysis.googleapis.com",
    "iamcredentials.googleapis.com",
    "sts.googleapis.com",
    "compute.googleapis.com",
    "networkservices.googleapis.com",
    "trafficdirector.googleapis.com"
  ])

  project = var.project_id
  service = each.value

  disable_on_destroy = false
}

module "network" {
  source                  = "../../modules/network"
  project_id              = var.project_id
  region                  = var.region
  network_name            = local.network_name
  primary_cidr            = "10.64.0.0/20"
  pods_cidr               = "10.80.0.0/20"
  enable_secondary_ranges = true
  depends_on              = [google_project_service.required]
}

module "wif" {
  source               = "../../modules/wif"
  project_id           = var.project_id
  github_repository    = local.repository_full_name
  workload_identity_sa = local.github_workload_identity_sa_id
  pool_id              = local.workload_identity_pool_id
  provider_id          = local.workload_identity_provider_id
  attribute_condition  = local.wif_attribute_condition
  project_roles = [
    "roles/iam.serviceAccountTokenCreator",
    "roles/container.admin",
    "roles/resourcemanager.projectIamAdmin",
    "roles/artifactregistry.admin"
  ]
}

module "gke" {
  source            = "../../modules/gke"
  project_id        = var.project_id
  location          = var.location
  cluster_name      = local.cluster_name
  network_self_link = module.network.vpc_self_link
  subnet_self_link  = module.network.primary_subnet_self_link
  release_channel   = var.release_channel
}

resource "google_artifact_registry_repository" "containers" {
  location      = var.region
  project       = var.project_id
  repository_id = local.artifact_registry_repository
  description   = "Container images for AI Dev Platform"
  format        = "DOCKER"
  docker_config {
    immutable_tags = true
  }
  depends_on = [google_project_service.required]
}

resource "google_service_account" "runtime" {
  project      = var.project_id
  account_id   = local.runtime_service_account_id
  display_name = "${local.environment} web application runtime"
}

resource "google_project_iam_member" "runtime_permissions" {
  for_each = toset([
    "roles/logging.logWriter",
    "roles/monitoring.metricWriter",
    "roles/artifactregistry.reader"
  ])

  project = var.project_id
  role    = each.value
  member  = "serviceAccount:${google_service_account.runtime.email}"
}

resource "google_service_account" "api_gateway_runtime" {
  project      = var.project_id
  account_id   = local.api_gateway_runtime_service_account_id
  display_name = "${local.environment} api gateway runtime"
}

resource "google_project_iam_member" "api_gateway_runtime_permissions" {
  for_each = toset([
    "roles/logging.logWriter",
    "roles/monitoring.metricWriter",
    "roles/artifactregistry.reader"
  ])

  project = var.project_id
  role    = each.value
  member  = "serviceAccount:${google_service_account.api_gateway_runtime.email}"
}

output "github_service_account_email" {
  value       = module.wif.service_account_email
  description = "Service account email used by GitHub Actions via Workload Identity Federation"
}

output "workload_identity_pool_provider" {
  value       = module.wif.provider_name
  description = "Resource name of the WIF provider"
}

output "gke_cluster_name" {
  description = "GKE cluster name"
  value       = module.gke.name
}

output "gke_cluster_location" {
  description = "GKE cluster location"
  value       = module.gke.location
}

output "artifact_registry_repository" {
  description = "Artifact Registry repository ID"
  value       = google_artifact_registry_repository.containers.id
}

output "runtime_service_account_email" {
  description = "GCP service account used by the web runtime"
  value       = google_service_account.runtime.email
}

output "api_gateway_runtime_service_account_email" {
  description = "GCP service account used by the api-gateway runtime"
  value       = google_service_account.api_gateway_runtime.email
}

output "project_id" {
  description = "GCP project id for the environment"
  value       = var.project_id
}

output "region" {
  description = "Primary region for the environment"
  value       = var.region
}

output "location" {
  description = "Location for the Autopilot cluster"
  value       = var.location
}

output "artifact_registry_repository_id" {
  description = "Artifact Registry repository id"
  value       = local.artifact_registry_repository
}
