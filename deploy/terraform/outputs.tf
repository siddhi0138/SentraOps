output "kubectl_context" {
  value = "kind-${var.cluster_name}"
}

output "frontend_url" {
  value = "http://localhost:5173"
}

output "backend_url" {
  value = "http://localhost:8000"
}

output "prometheus_url" {
  value = "http://localhost:9090"
}

output "grafana_url" {
  value = "http://localhost:3001"
}
