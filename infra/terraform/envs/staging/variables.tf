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

variable "environment" {
  description = "Deployment environment identifier"
  type        = string
  default     = "staging"
}

variable "cluster_name" {
  description = "Name of the GKE Autopilot cluster"
  type        = string
  default     = null
}

variable "network_name" {
  description = "Prefix used for VPC resources"
  type        = string
  default     = null
}

variable "release_channel" {
  description = "GKE release channel"
  type        = string
  default     = "REGULAR"
}

variable "artifact_registry_repo" {
  description = "Artifact Registry repository for container images"
  type        = string
  default     = null
}

variable "runtime_service_account_id" {
  description = "Service account ID for the application runtime"
  type        = string
  default     = null
}

variable "api_gateway_runtime_service_account_id" {
  description = "Service account ID for the api-gateway runtime"
  type        = string
  default     = null
}

variable "github_workload_identity_sa_id" {
  description = "Service account ID for GitHub Actions via Workload Identity Federation"
  type        = string
  default     = null
}

variable "workload_identity_pool_id" {
  description = "Custom Workload Identity Pool ID (optional)"
  type        = string
  default     = null
}

variable "workload_identity_provider_id" {
  description = "Custom Workload Identity Provider ID (optional)"
  type        = string
  default     = null
}
