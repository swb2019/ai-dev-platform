variable "project_id" {
  description = "GCP project ID"
  type        = string
}

variable "region" {
  description = "Primary region for regional resources"
  type        = string
}

variable "network_name" {
  description = "Prefix used for network resources"
  type        = string
  default     = "ai-dev-platform"
}

variable "primary_cidr" {
  description = "CIDR block for the primary subnet"
  type        = string
  default     = "10.10.0.0/20"
}

variable "enable_secondary_ranges" {
  description = "Whether to create a secondary subnet range for GKE pods"
  type        = bool
  default     = true
}

variable "pods_cidr" {
  description = "CIDR block for the secondary pods subnet"
  type        = string
  default     = "10.20.0.0/20"
}
