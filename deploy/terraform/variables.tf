variable "cluster_name" {
  description = "Name of the local kind cluster"
  type        = string
  default     = "cybersentinel"
}

variable "backend_image_tag" {
  description = "Tag to build/load the backend image as"
  type        = string
  default     = "local"
}

variable "frontend_image_tag" {
  description = "Tag to build/load the frontend image as"
  type        = string
  default     = "local"
}

variable "frontend_api_base_url" {
  description = "API base URL baked into the frontend bundle at build time - must match wherever the backend NodePort is reachable from a browser"
  type        = string
  default     = "http://localhost:8000"
}

variable "postgres_password" {
  type      = string
  default   = "cybersentinel"
  sensitive = true
}

variable "neo4j_password" {
  type      = string
  default   = "cybersentinel"
  sensitive = true
}

variable "jwt_secret_key" {
  description = "Set a real random value for anything beyond local demo use"
  type        = string
  default     = "dev-only-insecure-secret-key-change-me-in-production"
  sensitive   = true
}

variable "groq_api_key" {
  description = "Real Groq API key - required for the AI features to work, not required for the platform to deploy"
  type        = string
  default     = ""
  sensitive   = true
}
