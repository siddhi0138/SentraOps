resource "helm_release" "cybersentinel" {
  depends_on = [null_resource.load_backend_image, null_resource.load_frontend_image]

  name             = "cybersentinel"
  chart            = "${path.module}/../helm/cybersentinel"
  namespace        = "cybersentinel"
  create_namespace = true
  timeout          = 300

  values = [
    yamlencode({
      backend = {
        image = {
          repository = "cybersentinel-backend"
          tag        = var.backend_image_tag
        }
      }
      frontend = {
        image = {
          repository = "cybersentinel-frontend"
          tag        = var.frontend_image_tag
        }
      }
    })
  ]

  set_sensitive {
    name  = "secrets.postgresPassword"
    value = var.postgres_password
  }

  set_sensitive {
    name  = "secrets.neo4jPassword"
    value = var.neo4j_password
  }

  set_sensitive {
    name  = "secrets.jwtSecretKey"
    value = var.jwt_secret_key
  }

  set_sensitive {
    name  = "secrets.groqApiKey"
    value = var.groq_api_key
  }
}
