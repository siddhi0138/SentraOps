terraform {
  required_version = ">= 1.5"

  required_providers {
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.13"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.31"
    }
    local = {
      source  = "hashicorp/local"
      version = "~> 2.5"
    }
    null = {
      source  = "hashicorp/null"
      version = "~> 3.2"
    }
  }
}

# `kind create cluster` merges a "kind-<name>" context into the default
# kubeconfig and switches to it - pointing providers at that well-known
# path/context (rather than a computed attribute from a cluster resource)
# sidesteps Terraform's "providers can't depend on resources" restriction.
provider "kubernetes" {
  config_path    = pathexpand("~/.kube/config")
  config_context = "kind-${var.cluster_name}"
}

provider "helm" {
  kubernetes {
    config_path    = pathexpand("~/.kube/config")
    config_context = "kind-${var.cluster_name}"
  }
}
