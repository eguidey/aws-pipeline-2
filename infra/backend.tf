# Remote state in S3 with native locking (Terraform 1.10+). Each environment has its own
# state key, supplied at init time:
#   terraform init -backend-config=environments/prod.backend.hcl
# Create the bucket first with infra/bootstrap (see docs/REBUILD.md).
terraform {
  backend "s3" {}
}
