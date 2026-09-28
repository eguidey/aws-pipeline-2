variable "name" {
  description = "Repository name."
  type        = string
}

variable "kms_key_arn" {
  description = "KMS key used to encrypt images."
  type        = string
}

variable "images_to_keep" {
  description = "How many images to retain (older ones expire)."
  type        = number
  default     = 10
}
