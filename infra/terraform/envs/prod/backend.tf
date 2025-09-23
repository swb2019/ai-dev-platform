# Configure remote state outside of VCS for best practices.
# Supply backend configuration via `terraform init -backend-config=../backend.hcl`.
terraform {
  backend "gcs" {}
}
