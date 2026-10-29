terraform {
  required_version = ">= 1.6"

  # Pinned to a major version so a future breaking release can't change
  # behaviour unexpectedly. Commit .terraform.lock.hcl after `terraform init`.
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Project = "secure-ai-workload"
      Stage   = "insecure-baseline"
    }
  }
}
