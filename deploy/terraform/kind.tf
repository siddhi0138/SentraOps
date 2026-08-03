resource "local_file" "kind_config" {
  filename = "${path.module}/.kind-config.generated.yaml"
  content = templatefile("${path.module}/templates/kind-config.yaml.tpl", {
    cluster_name = var.cluster_name
  })
}

# Terraform's local-exec defaults to cmd.exe on Windows, which mishandles
# this project's paths in a way bash doesn't (confirmed by reproducing the
# exact same `kind create cluster --config <path>` call successfully outside
# Terraform, in bash, with the identical path string cmd.exe choked on) -
# every provisioner below runs through bash explicitly instead.
locals {
  bash_interpreter = ["bash", "-c"]
}

resource "null_resource" "kind_cluster" {
  triggers = {
    cluster_name = var.cluster_name
    config_path  = local_file.kind_config.filename
  }

  provisioner "local-exec" {
    interpreter = local.bash_interpreter
    command     = "kind get clusters | grep -qx \"${var.cluster_name}\" || kind create cluster --name ${var.cluster_name} --config \"${local_file.kind_config.filename}\" --wait 120s"
  }

  provisioner "local-exec" {
    when        = destroy
    interpreter = ["bash", "-c"]
    command     = "kind delete cluster --name ${self.triggers.cluster_name}"
  }
}

# kind's nodes only see images pulled from a registry - a locally built image
# has to be explicitly loaded into the cluster's node, and rebuilt/reloaded
# on every apply since there's no registry to version-tag against here.
resource "null_resource" "build_backend_image" {
  depends_on = [null_resource.kind_cluster]
  triggers   = { always_run = timestamp() }

  provisioner "local-exec" {
    interpreter = local.bash_interpreter
    command     = "docker build -t cybersentinel-backend:${var.backend_image_tag} \"${path.module}/../../backend\""
  }
}

resource "null_resource" "load_backend_image" {
  depends_on = [null_resource.build_backend_image]
  triggers   = { always_run = timestamp() }

  provisioner "local-exec" {
    interpreter = local.bash_interpreter
    command     = "kind load docker-image cybersentinel-backend:${var.backend_image_tag} --name ${var.cluster_name}"
  }
}

resource "null_resource" "build_frontend_image" {
  depends_on = [null_resource.kind_cluster]
  triggers   = { always_run = timestamp() }

  provisioner "local-exec" {
    interpreter = local.bash_interpreter
    command     = "docker build -t cybersentinel-frontend:${var.frontend_image_tag} --build-arg VITE_API_BASE_URL=${var.frontend_api_base_url} \"${path.module}/../../frontend\""
  }
}

resource "null_resource" "load_frontend_image" {
  depends_on = [null_resource.build_frontend_image]
  triggers   = { always_run = timestamp() }

  provisioner "local-exec" {
    interpreter = local.bash_interpreter
    command     = "kind load docker-image cybersentinel-frontend:${var.frontend_image_tag} --name ${var.cluster_name}"
  }
}
