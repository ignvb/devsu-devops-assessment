terraform {

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.9.0"
    }

    random = {
      source  = "hashicorp/random"
      version = "~> 3.5.1"
    }

    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0.4"
    }

  }

  required_version = "~> 1.5"
}

provider "aws" {
  region  = "us-east-1"
  profile = "aws-ignvb"
}
