variable "project_id" {
  description = "GCP project ID"
  type        = string
}

variable "github_repository" {
  description = "GitHub repository in the format org/repo"
  type        = string
}

variable "workload_identity_sa" {
  description = "Service account ID (without domain) for GitHub actions"
  type        = string
  default     = "github-terraform"
}

variable "project_roles" {
  description = "Project level IAM roles granted to the GitHub Actions service account"
  type        = list(string)
  default = [
    "roles/iam.serviceAccountTokenCreator",
    "roles/container.admin",
    "roles/resourcemanager.projectIamAdmin"
  ]
}

variable "pool_id" {
  description = "Optional custom workload identity pool ID"
  type        = string
  default     = null
}

variable "provider_id" {
  description = "Optional custom workload identity provider ID"
  type        = string
  default     = null
}

variable "attribute_condition" {
  description = "Optional custom attribute condition expression for the provider"
  type        = string
  default     = null
}
