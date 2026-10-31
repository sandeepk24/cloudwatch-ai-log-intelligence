terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.80"
    }
  }

  # Replace with a remote backend before applying in a shared account.
  # Do not hardcode bucket names or account IDs in this repository.
  backend "local" {}
}
