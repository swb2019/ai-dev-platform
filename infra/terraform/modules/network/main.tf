terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.11"
    }
  }
}

resource "google_compute_network" "this" {
  name                    = "${var.network_name}-vpc"
  project                 = var.project_id
  auto_create_subnetworks = false
  routing_mode            = "GLOBAL"
}

resource "google_compute_subnetwork" "primary" {
  name                     = "${var.network_name}-primary"
  project                  = var.project_id
  ip_cidr_range            = var.primary_cidr
  region                   = var.region
  network                  = google_compute_network.this.id
  private_ip_google_access = true
}

resource "google_compute_subnetwork" "secondary" {
  count                    = var.enable_secondary_ranges ? 1 : 0
  name                     = "${var.network_name}-pods"
  project                  = var.project_id
  ip_cidr_range            = var.pods_cidr
  region                   = var.region
  network                  = google_compute_network.this.id
  purpose                  = "REGIONAL_MANAGED_PROXY"
  role                     = "ACTIVE"
  private_ip_google_access = false
}

resource "google_compute_router" "this" {
  name    = "${var.network_name}-router"
  project = var.project_id
  region  = var.region
  network = google_compute_network.this.id
}

resource "google_compute_router_nat" "this" {
  name                                = "${var.network_name}-nat"
  project                             = var.project_id
  region                              = var.region
  router                              = google_compute_router.this.name
  nat_ip_allocate_option              = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat  = "ALL_SUBNETWORKS_ALL_IP_RANGES"
  enable_endpoint_independent_mapping = true
}

output "vpc_self_link" {
  description = "Self link of the created VPC network"
  value       = google_compute_network.this.self_link
}

output "primary_subnet_self_link" {
  description = "Self link of the primary subnet"
  value       = google_compute_subnetwork.primary.self_link
}

output "pods_subnet_self_link" {
  description = "Self link of the secondary subnet (if created)"
  value       = try(google_compute_subnetwork.secondary[0].self_link, null)
}
