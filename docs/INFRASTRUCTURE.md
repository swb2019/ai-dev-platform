# Infrastructure Architecture

Phase 3 introduces infrastructure-as-code that provisions all core Google Cloud resources with Terraform. The configuration follows a modules + environments pattern to keep reusable building blocks separate from environment-specific wiring.

```
infra/terraform/
├── modules/
│   ├── gke/                # Autopilot GKE cluster + control plane service account
│   ├── network/            # Dedicated VPC, subnets, Cloud NAT
│   └── wif/                # Workload Identity Federation (GitHub ↔ Google)
└── envs/
    └── prod/
        ├── backend.tf      # Remote state configuration (GCS)
        ├── main.tf         # Composes modules & supporting resources
        ├── providers.tf    # Provider constraints / versions
        ├── variables.tf    # Environment variables
        └── terraform.tfvars.example
```

Key resources provisioned:

- VPC + regional subnets with Cloud NAT for egress.
- Autopilot GKE cluster with Binary Authorization, Shielded Nodes, and Workload Identity enabled.
- Artifact Registry Docker repository for the application images.
- Workload Identity Federation pool/provider trusted for this GitHub repository, with a dedicated service account for Terraform.
- Application runtime service account for pods (`web-runtime`).

## Prerequisites

1. **Terraform state bucket** – create a GCS bucket (e.g. `gs://ai-dev-platform-terraform`) with versioning enabled.
2. **Enable GCP APIs** _(only required before the first Terraform apply)_:
   - `iam.googleapis.com`
   - `artifactregistry.googleapis.com`
   - `container.googleapis.com`
   - `containeranalysis.googleapis.com`
   - `sts.googleapis.com`
   - `iamcredentials.googleapis.com`
3. **GitHub → Google federation** – no manual setup is required; Terraform will create the Workload Identity pool/provider and the GitHub service account the first time you run `terraform apply`.

## Terraform workflow

1. Copy the example vars file and adjust values:
   ```sh
   cd infra/terraform/envs/prod
   cp terraform.tfvars.example terraform.tfvars
   # provide project_id, region, artifact registry repo, etc.
   ```
2. Provide backend configuration (`backend.auto.tfbackend` is generated automatically in CI). Locally you can create `backend.hcl` with:
   ```hcl
   bucket  = "your-terraform-state-bucket"
   prefix  = "ai-dev-platform/prod"
   project = "your-gcp-project-id"
   location = "us"
   ```
   Run `terraform init -backend-config=backend.hcl`.
3. Use `terraform plan` and `terraform apply` as normal. The modules expose useful outputs: workload identity provider name, GitHub service account email, cluster coordinates, and the runtime service account email.

> **Tip:** the included GitHub Actions workflow (`.github/workflows/terraform.yml`) performs `fmt`, `validate`, `plan`, and (on main) `apply` using Workload Identity Federation with no stored service account keys.

## GitHub secrets and variables

| Name                             | Type     | Purpose                                                                                     |
| -------------------------------- | -------- | ------------------------------------------------------------------------------------------- |
| `GCP_PROJECT_ID`                 | Secret   | Primary GCP project                                                                         |
| `GCP_REGION`                     | Secret   | Default region (e.g. `us-central1`)                                                         |
| `GCP_LOCATION`                   | Secret   | GKE cluster location (region/zone)                                                          |
| `GCP_TF_STATE_BUCKET`            | Secret   | Terraform state bucket name                                                                 |
| `GCP_TF_STATE_PREFIX`            | Secret   | Object prefix inside the bucket                                                             |
| `GCP_WORKLOAD_IDENTITY_PROVIDER` | Secret   | Resource name of the WIF provider (Terraform output)                                        |
| `GCP_TERRAFORM_SERVICE_ACCOUNT`  | Secret   | Email of the Terraform service account (Terraform output)                                   |
| `GCP_DEPLOY_SERVICE_ACCOUNT`     | Secret   | Email of the deployment service account (can reuse Terraform SA or create dedicated)        |
| `GCP_RUNTIME_SERVICE_ACCOUNT`    | Secret   | Email of the runtime GCP service account (Terraform output `runtime_service_account_email`) |
| `ARTIFACT_REGISTRY_REPOSITORY`   | Variable | Artifact Registry repo id (e.g. `ai-dev-platform`)                                          |
| `GKE_CLUSTER_NAME`               | Variable | Cluster name (Terraform output `gke_cluster_name`)                                          |

Populate secrets/variables after the first Terraform apply using the command:

```sh
terraform output -raw github_service_account_email
terraform output -raw workload_identity_pool_provider
terraform output -raw runtime_service_account_email
terraform output -raw gke_cluster_name
```

## Workload Identity Federation (WIF)

- **Terraform service account** (`github-terraform` by default) obtains temporary credentials through WIF for infrastructure changes.
- The GitHub Actions workflows authenticate via `google-github-actions/auth@v2` using the Workload Identity provider created by Terraform.
- The Kubernetes runtime service account (`web-runtime`) is annotated with the GCP service account email from Terraform output, enabling pods to request workload identity tokens without storing keys.

## Artifact Registry & Deployment

Terraform provisions the Docker repository. The deployment workflow builds the Next.js container, pushes it to `${region}-docker.pkg.dev/${project}/${ARTIFACT_REGISTRY_REPOSITORY}/web`, and updates the Kubernetes manifests using Kustomize.

Ensure you grant the deployment service account (`GCP_DEPLOY_SERVICE_ACCOUNT`) the roles:

- `roles/artifactregistry.writer`
- `roles/container.clusterAdmin` or minimum `roles/container.developer`
- `roles/iam.serviceAccountTokenCreator`

These permissions allow GitHub Actions to push images and interact with GKE without long-lived keys.

## Next steps

- Configure GitHub environment protection if manual approvals are desired before Terraform applies.
- Extend Terraform by adding modules for databases, load balancers, or secrets management as Phase 4 requirements emerge.
- Use `terraform docs` or `terraform providers schema` to keep module documentation in sync as configuration evolves.
