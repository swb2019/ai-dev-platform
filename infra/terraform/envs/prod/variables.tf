variable "project_id" {
  description = "GCP project ID"
  type        = string
}

variable "region" {
  description = "Primary region for regional resources"
  type        = string
  default     = "us-central1"
}

variable "location" {
  description = "Location for the GKE cluster (region or zone)"
  type        = string
  default     = "us-central1"
}

variable "github_org" {
  description = "GitHub organisation or user name"
  type        = string
}

variable "github_repo" {
  description = "Repository name"
  type        = string
}

variable "cluster_name" {
  description = "Name of the GKE Autopilot cluster"
  type        = string
  default     = "ai-dev-autopilot"
}

variable "network_name" {
  description = "Prefix used for VPC resources"
  type        = string
  default     = "ai-dev"
}

variable "release_channel" {
  description = "GKE release channel"
  type        = string
  default     = "REGULAR"
}

variable "artifact_registry_repo" {
  description = "Artifact Registry repository for container images"
  type        = string
}
