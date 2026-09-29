resource "aws_ecr_repository" "api" {
  name                 = var.name
  image_tag_mutability = "MUTABLE" # a tag always points at the exact image that was scanned
  force_delete         = true        # lets `terraform destroy` clean up in a lab

  image_scanning_configuration {
    scan_on_push = true # third opinion alongside Trivy and Grype in the pipeline
  }

  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = var.kms_key_arn
  }
}

resource "aws_ecr_lifecycle_policy" "api" {
  repository = aws_ecr_repository.api.name
  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "Keep the most recent images"
      selection = {
        tagStatus   = "any"
        countType   = "imageCountMoreThan"
        countNumber = var.images_to_keep
      }
      action = { type = "expire" }
    }]
  })
}
