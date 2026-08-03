kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
name: ${cluster_name}
nodes:
  - role: control-plane
    extraPortMappings:
      - containerPort: 30080
        hostPort: 8000
        protocol: TCP
      - containerPort: 30081
        hostPort: 5173
        protocol: TCP
      - containerPort: 30090
        hostPort: 9090
        protocol: TCP
      - containerPort: 30001
        hostPort: 3001
        protocol: TCP
