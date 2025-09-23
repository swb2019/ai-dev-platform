variable "project_id" {
  description = "GCP project ID"
  type        = string
}

variable "location" {
  description = "Region or zone where the cluster is deployed"
  type        = string
}

variable "cluster_name" {
  description = "Name of the GKE cluster"
  type        = string
  default     = "ai-dev-cluster"
}

variable "network_self_link" {
  description = "Self link of the VPC network"
  type        = string
}

variable "subnet_self_link" {
  description = "Self link of the subnet used for nodes"
  type        = string
}

variable "release_channel" {
  description = "Release channel for GKE"
  type        = string
  default     = "REGULAR"
}

variable "maintenance_start_time" {
  description = "Daily maintenance window start time in RFC3339 format (e.g. 03:00)"
  type        = string
  default     = "03:00"
}

variable "enable_deletion_protection" {
  description = "Protect cluster from accidental deletion"
  type        = bool
  default     = true
}

variable "github_sa_email" {
  description = "Service account email tied to GitHub Workload Identity Federation (optional)"
  type        = string
  default     = null
}
