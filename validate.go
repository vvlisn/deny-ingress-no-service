package main

import (
	"encoding/json"
	"fmt"
	"strings"

	onelog "github.com/francoispqt/onelog"
	networkingv1 "github.com/kubewarden/k8s-objects/api/networking/v1"
	kubewarden "github.com/kubewarden/policy-sdk-go"
	"github.com/kubewarden/policy-sdk-go/pkg/capabilities"
	kubewarden_protocol "github.com/kubewarden/policy-sdk-go/protocol"
)

const httpBadRequestStatusCode = 400

func validate(payload []byte) ([]byte, error) {
	// 从传入的 payload 创建 ValidationRequest 实例。
	validationRequest := kubewarden_protocol.ValidationRequest{}
	err := json.Unmarshal(payload, &validationRequest)
	if err != nil {
		return kubewarden.RejectRequest(
			kubewarden.Message(err.Error()),
			kubewarden.Code(httpBadRequestStatusCode))
	}

	// 从 ValidationRequest 对象创建 Settings 实例。
	settings, err := NewSettingsFromValidationReq(&validationRequest)
	if err != nil {
		return kubewarden.RejectRequest(
			kubewarden.Message(err.Error()),
			kubewarden.Code(httpBadRequestStatusCode))
	}

	// 3. 反序列化出 Ingress 对象
	ingress, err := getIngress(validationRequest.Request.Object)
	if err != nil {
		return kubewarden.RejectRequest(
			kubewarden.Message(fmt.Sprintf("Cannot decode Ingress: %s", err)),
			kubewarden.Code(httpBadRequestStatusCode))
	}

	logger.DebugWithFields("validating ingress object", func(e onelog.Entry) {
		e.String("name", ingress.Metadata.Name)
		e.String("namespace", ingress.Metadata.Namespace)
	})

	// 4. 如果用户关闭了 enforce 或在排除列表中（此处假设已有相应方法），直接通过
	if !settings.IsEnforcementEnabled() {
		return kubewarden.AcceptRequest()
	}

	// 5. 提取所有后端 Service 名称
	svcNames := extractServiceNames(ingress)

	// 6. 逐个检查 Service 是否存在
	for _, svc := range svcNames {
		ok, err := serviceExists(&validationRequest, svc)
		if err != nil {
			return kubewarden.RejectRequest(
				kubewarden.Message(fmt.Sprintf("Error checking Service '%s': %s", svc, err)),
				kubewarden.NoCode)
		}
		if !ok {
			return kubewarden.RejectRequest(
				kubewarden.Message(fmt.Sprintf(
					"Service '%s' does not exist in namespace '%s'",
					svc, ingress.Metadata.Namespace)),
				kubewarden.NoCode)
		}
	}

	// 全部校验通过
	return kubewarden.AcceptRequest()
}

// getIngress 从 RAW JSON 中解析出 Ingress 对象
// getIngress 将 json.RawMessage（即 []byte）直接反序列化为 Ingress
func getIngress(rawJSON json.RawMessage) (*networkingv1.Ingress, error) {
	ing := &networkingv1.Ingress{}
	if err := json.Unmarshal(rawJSON, ing); err != nil {
		return nil, err
	}
	return ing, nil
}

// extractServiceNames 从 Ingress Spec 中收集所有 backend.service.name 并去重
func extractServiceNames(ing *networkingv1.Ingress) []string {
	names := make([]string, 0)
	seen := map[string]struct{}{}

	spec := ing.Spec

	// defaultBackend
	if spec.DefaultBackend != nil && spec.DefaultBackend.Service != nil {
		if svcPtr := spec.DefaultBackend.Service.Name; svcPtr != nil && *svcPtr != "" {
			svc := *svcPtr
			if _, exists := seen[svc]; !exists {
				seen[svc] = struct{}{}
				names = append(names, svc)
			}
		}
	}

	// rules[].http.paths[].backend.service
	for _, rule := range spec.Rules {
		if rule.HTTP == nil {
			continue
		}
		for _, path := range rule.HTTP.Paths {
			if path.Backend.Service != nil {
				if svcPtr := path.Backend.Service.Name; svcPtr != nil && *svcPtr != "" {
					svc := *svcPtr
					if _, exists := seen[svc]; !exists {
						seen[svc] = struct{}{}
						names = append(names, svc)
					}
				}
			}
		}
	}

	return names
}

// serviceExists 调用 Kubewarden Capabilities 检查 Service 是否存在
func serviceExists(
	validationReq *kubewarden_protocol.ValidationRequest,
	serviceName string,
) (bool, error) {
	// 1. Create a Host to talk to the policy server :contentReference[oaicite:2]{index=2}
	host := capabilities.NewHost()

	// 2. Build the get_resource payload as specified by the host-capabilities spec :contentReference[oaicite:3]{index=3}
	req := map[string]string{
		"api_version": "v1",
		"kind":        "Service",
		"namespace":   validationReq.Request.Namespace,
		"name":        serviceName,
	}
	reqBytes, err := json.Marshal(req)
	if err != nil {
		return false, fmt.Errorf("failed to marshal get_resource request: %w", err)
	}

	// 3. Invoke the host capability: binding="kubewarden", namespace="kubernetes", operation="get_resource"
	respBytes, err := host.Client.HostCall(
		"kubewarden",
		"kubernetes",
		"get_resource",
		reqBytes,
	) // WapcClient.HostCall(binding, namespace, operation, payload) :contentReference[oaicite:4]{index=4}
	if err != nil {
		// 4a. NotFound error       s are normal “missing” cases
		if strings.Contains(err.Error(), "not found") {
			return false, nil
		}
		// 4b. Any other error is unexpected
		return false, fmt.Errorf("host call failed: %w", err)
	}

	// 5. If we got a response payload, the resource exists
	//    (we could unmarshal respBytes to inspect fields if needed)
	if len(respBytes) > 0 {
		return true, nil
	}
	// Edge case: empty payload—treat as missing
	return false, nil
}
