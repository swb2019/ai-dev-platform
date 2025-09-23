locals {
  repository_full_name = "${var.github_org}/${var.github_repo}"
}

resource "google_project_service" "required" {
  for_each = toset([
    "artifactregistry.googleapis.com",
    "container.googleapis.com",
    "containeranalysis.googleapis.com",
    "iamcredentials.googleapis.com",
    "sts.googleapis.com",
    "compute.googleapis.com"
  ])

  project = var.project_id
  service = each.value

  disable_on_destroy = false
}

module "network" {
  source                  = "../../modules/network"
  project_id              = var.project_id
  region                  = var.region
  network_name            = var.network_name
  primary_cidr            = "10.64.0.0/20"
  pods_cidr               = "10.80.0.0/20"
  enable_secondary_ranges = true
}

module "wif" {
  source            = "../../modules/wif"
  project_id        = var.project_id
  github_repository = local.repository_full_name
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
  cluster_name      = var.cluster_name
  network_self_link = module.network.vpc_self_link
  subnet_self_link  = module.network.primary_subnet_self_link
  release_channel   = var.release_channel
  github_sa_email   = module.wif.service_account_email
}

resource "google_artifact_registry_repository" "containers" {
  location      = var.region
  project       = var.project_id
  repository_id = var.artifact_registry_repo
  description   = "Container images for AI Dev Platform"
  format        = "DOCKER"
  docker_config {
    immutable_tags = true
  }
  depends_on = [google_project_service.required]
}

resource "google_service_account" "runtime" {
  project      = var.project_id
  account_id   = "web-runtime"
  display_name = "Web application runtime"
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
