terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.11"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = "~> 5.11"
    }
  }
}

locals {
  identity_namespace = "${var.project_id}.svc.id.goog"
}

resource "google_service_account" "cluster_sa" {
  account_id   = "${var.cluster_name}-gke"
  display_name = "GKE control plane"
  project      = var.project_id
}

resource "google_container_cluster" "this" {
  provider = google-beta

  name     = var.cluster_name
  project  = var.project_id
  location = var.location

  network    = var.network_self_link
  subnetwork = var.subnet_self_link

  release_channel {
    channel = var.release_channel
  }

  workload_identity_config {
    workload_pool = local.identity_namespace
  }

  binary_authorization {
    evaluation_mode = "PROJECT_SINGLETON_POLICY_ENFORCE"
  }

  gateway_api_config {
    channel = "CHANNEL_STANDARD"
  }

  addons_config {
    http_load_balancing {
      disabled = false
    }
    gke_backup_agent_config {
      enabled = true
    }
  }

  enable_autopilot    = true
  deletion_protection = var.enable_deletion_protection

  logging_config {
    enable_components = ["SYSTEM_COMPONENTS", "WORKLOADS"]
  }

  monitoring_config {
    enable_components = ["SYSTEM_COMPONENTS"]
  }

  cost_management_config {
    enabled = true
  }

  maintenance_policy {
    daily_maintenance_window {
      start_time = var.maintenance_start_time
    }
  }
}

resource "google_service_account_iam_member" "github_wif" {
  count              = var.github_sa_email == null ? 0 : 1
  member             = "serviceAccount:${var.github_sa_email}"
  role               = "roles/container.admin"
  service_account_id = google_service_account.cluster_sa.name
}

output "name" {
  value       = google_container_cluster.this.name
  description = "Name of the GKE cluster"
}

output "endpoint" {
  value       = google_container_cluster.this.endpoint
  description = "Endpoint of the GKE cluster"
}

output "location" {
  value       = google_container_cluster.this.location
  description = "Location (region/zone) of the cluster"
}

output "workload_identity_pool" {
  description = "Workload Identity pool configured for the cluster"
  value       = local.identity_namespace
}

output "cluster_service_account_email" {
  description = "Service account email used by the cluster control plane"
  value       = google_service_account.cluster_sa.email
}
