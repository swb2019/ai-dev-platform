# Deployment Pipeline

The deployment workflow (`.github/workflows/deploy.yml`) delivers the `apps/web` container to the GKE Autopilot cluster provisioned by Terraform.

## High-level flow

1. Authenticate to Google Cloud using Workload Identity Federation (no static keys).
2. Build the production image from `apps/web/Dockerfile`.
3. Push the image to Artifact Registry (`${region}-docker.pkg.dev/${project}/${ARTIFACT_REGISTRY_REPOSITORY}/web`).
4. Update the Kubernetes overlay with the new image and runtime service account annotation.
5. Retrieve GKE credentials and apply the manifests with `kubectl apply -k`.
6. Wait until the deployment rolls out successfully.

## Required repository secrets & variables

| Name                             | Type     | Purpose                                               |
| -------------------------------- | -------- | ----------------------------------------------------- |
| `GCP_PROJECT_ID`                 | Secret   | Target GCP project                                    |
| `GCP_REGION`                     | Secret   | Artifact Registry region (e.g. `us-central1`)         |
| `GCP_LOCATION`                   | Secret   | GKE location (region or zone)                         |
| `GCP_WORKLOAD_IDENTITY_PROVIDER` | Secret   | Workload Identity provider resource name              |
| `GCP_DEPLOY_SERVICE_ACCOUNT`     | Secret   | Service account email used by the deployment workflow |
| `GCP_RUNTIME_SERVICE_ACCOUNT`    | Secret   | Service account email for annotated Kubernetes SA     |
| `ARTIFACT_REGISTRY_REPOSITORY`   | Variable | Artifact Registry repo id created by Terraform        |
| `GKE_CLUSTER_NAME`               | Variable | Cluster name created by Terraform                     |

The deployment service account requires at least:

- `roles/artifactregistry.writer`
- `roles/container.clusterAdmin` _(or granular `roles/container.developer` + `roles/container.admin` depending on access model)_
- `roles/iam.serviceAccountTokenCreator`

## Kubernetes manifests

- Base manifests live in `deploy/k8s/base` and describe the namespace, service account, deployment, and service.
- Overlays (currently `deploy/k8s/overlays/prod`) adjust replica count, apply the GCP service account annotation, and set the concrete image tag.
- The workflow installs `kustomize`, edits the overlay to use the freshly built image, applies the manifests, and waits for rollout completion.

## Manual promotion or rollback

- To deploy a previous image, re-run the workflow with `workflow_dispatch` and override the `IMAGE_TAG` input (add an input to the workflow dispatch trigger if desired).
- Rollbacks can also be executed with `kubectl rollout undo deployment/web -n ai-dev-platform` once credentials are fetched using `get-gke-credentials`.

## Local testing

- Use `kustomize build deploy/k8s/overlays/prod` to render manifests locally.
- `docker build -f apps/web/Dockerfile .` to ensure the image builds before pushing to Artifact Registry.

## Observability hooks

The deployment uses the runtime service account annotated for Workload Identity, allowing pods to access Google Cloud APIs securely. Extend the deployment by attaching additional IAM roles to `google_project_iam_member.runtime_permissions` in Terraform as features require (e.g., Pub/Sub, Secret Manager).
