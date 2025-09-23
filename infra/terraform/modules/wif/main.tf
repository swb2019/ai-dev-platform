terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.11"
    }
  }
}

locals {
  pool_id     = var.pool_id != null ? var.pool_id : "github-wif-pool"
  provider_id = var.provider_id != null ? var.provider_id : "github-provider"
}

resource "google_iam_workload_identity_pool" "this" {
  project                   = var.project_id
  location                  = "global"
  workload_identity_pool_id = local.pool_id
  display_name              = "GitHub Actions"
  description               = "OIDC federation for GitHub Actions to access ${var.project_id}"
}

resource "google_iam_workload_identity_pool_provider" "github" {
  project                            = var.project_id
  workload_identity_pool_id          = google_iam_workload_identity_pool.this.workload_identity_pool_id
  workload_identity_pool_provider_id = local.provider_id

  display_name = "GitHub OIDC"
  description  = "Federates GitHub Actions OIDC tokens"
  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }

  attribute_mapping = {
    "google.subject"       = "assertion.sub"
    "attribute.repository" = "assertion.repository"
    "attribute.workflow"   = "assertion.workflow"
    "attribute.ref"        = "assertion.ref"
  }

  attribute_condition = "attribute.repository == '${var.github_repository}'"
}

resource "google_service_account" "github" {
  project      = var.project_id
  account_id   = var.workload_identity_sa
  display_name = "GitHub Actions Terraform"
}

resource "google_service_account_iam_member" "github_wi" {
  service_account_id = google_service_account.github.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.this.name}/attribute.repository/${var.github_repository}"
}

resource "google_project_iam_member" "terraform_roles" {
  for_each = toset(var.project_roles)
  project  = var.project_id
  role     = each.value
  member   = "serviceAccount:${google_service_account.github.email}"
}

output "pool_name" {
  description = "Resource name of the workload identity pool"
  value       = google_iam_workload_identity_pool.this.name
}

output "provider_name" {
  description = "Resource name of the workload identity provider"
  value       = google_iam_workload_identity_pool_provider.github.name
}

output "service_account_email" {
  description = "GitHub Actions service account email"
  value       = google_service_account.github.email
}
