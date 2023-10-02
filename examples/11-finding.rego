package rules.khulnasoft_011.tf

import data.khulnasoft

metadata := {
  "id": "EXAMPLE-011",
  "title": "Kubernetes pod is connected to ingress",
  "kind": "finding",
  "category": "public_exposure",
}

pods := khulnasoft.resources("kubernetes_pod")

deny[info] {
  pod := pods[_]
  service := khulnasoft.relates(pod, "kubernetes_pod.service")[_]
  ingress := khulnasoft.relates(service, "kubernetes_service_v1.ingress")[_]

  info := {
    "resource": pod,
    "graph": [
      {
        "source": ingress,
        "label": "exposes",
        "target": service,
      },
      {
        "source": service,
        "label": "exposes",
        "target": pod,
      },
    ]
  }
}
