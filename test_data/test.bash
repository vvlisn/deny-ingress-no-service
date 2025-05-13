kwctl annotate --metadata-path metadata.yml policy.wasm -o annotated-policy.wasm



kwctl run \
  --allow-context-aware \
  -r test_data/ingress-with-service.json \
  --settings-json '{
    "signatures": [
      {
        "enforce_service_exists": "true",
        "disable_cache": "true"
      }
    ]
  }' \
  --record-host-capabilities-interactions replay-session.yml \
  annotated-policy.wasm



kwctl run \
  --allow-context-aware \
  -r test_data/ingress-no-service.json \
  --settings-json '{
    "signatures": [
      {
        "enforce_service_exists": "true"
      }
    ]
  }' \
  --record-host-capabilities-interactions replay-session.yml \
  annotated-policy.wasm


kwctl run \
  --allow-context-aware \
  -r test_data/ingress-with-service.json \
  --settings-json '{
    "signatures": [
      {
        "enforce_service_exists": "true"
      }
    ]
  }' \
  --replay-host-capabilities-interactions replay-session.yml \
  annotated-policy.wasm


gh release create v0.0.1 \
  --draft \
  --title "v0.0.1" \
  --notes "Initial release of deny-ingress-no-service policy

Features:
- Validates that Ingress resources only reference existing Services
- Configurable service existence enforcement
- Support for caching host capabilities calls"



cat <<EOF | kubectl apply -f -
apiVersion: policies.kubewarden.io/v1
kind: ClusterAdmissionPolicy
metadata:
  name: deny-ingress-no-service
spec:
  module: registry://ghcr.io/vvlisn/policies/deny-ingress-no-service:v0.0.1
  rules:
  - apiGroups: ["networking.k8s.io"]
    apiVersions: ["v1"]
    resources: ["ingresses"]
    operations:
    - CREATE
    - UPDATE
  mutating: false
  # 添加上下文感知资源配置
  contextAwareResources:
  - apiVersion: v1
    kind: Service
  settings:
    enforce_service_exists: true
EOF