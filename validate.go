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

// 全局 host 实例，用于 capabilities 调用
var host = capabilities.NewHost()

func validate(payload []byte) ([]byte, error) {
	// 从传入的 payload 创建 ValidationRequest 实例
	validationRequest := kubewarden_protocol.ValidationRequest{}
	err := json.Unmarshal(payload, &validationRequest)
	if err != nil {
		return kubewarden.RejectRequest(
			kubewarden.Message(err.Error()),
			kubewarden.Code(httpBadRequestStatusCode))
	}

	// 从 ValidationRequest 对象创建 Settings 实例
	settings, err := NewSettingsFromValidationReq(&validationRequest)
	if err != nil {
		return kubewarden.RejectRequest(
			kubewarden.Message(err.Error()),
			kubewarden.Code(httpBadRequestStatusCode))
	}

	// 反序列化出 Ingress 对象
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

	// 如果 IsEnforcementEnabled 返回 false，说明不需要检查，直接通过
	if !settings.IsEnforcementEnabled() {
		return kubewarden.AcceptRequest()
	}

	// 提取所有后端 Service 名称
	svcNames := extractServiceNames(ingress)
	if len(svcNames) == 0 {
		// 没有服务需要验证，直接通过
		return kubewarden.AcceptRequest()
	}

	// 逐个检查 Service 是否存在
	for _, svc := range svcNames {
		ok, err := serviceExists(ingress, settings, svc)
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
func getIngress(rawJSON json.RawMessage) (*networkingv1.Ingress, error) {
	if len(rawJSON) == 0 {
		return nil, fmt.Errorf("empty ingress object")
	}
	ing := &networkingv1.Ingress{}
	if err := json.Unmarshal(rawJSON, ing); err != nil {
		return nil, err
	}
	return ing, nil
}

// extractServiceNames 从 Ingress Spec 中收集所有 backend.service.name 并去重
func extractServiceNames(ing *networkingv1.Ingress) []string {
	if ing == nil || ing.Spec == nil {
		return nil
	}

	// 估算初始容量：defaultBackend(1) + rules * paths(预估2个path)
	initialCap := 1
	if ing.Spec.Rules != nil {
		initialCap += len(ing.Spec.Rules) * 2
	}
	names := make([]string, 0, initialCap)
	seen := make(map[string]struct{}, initialCap)

	spec := ing.Spec

	// defaultBackend
	if spec.DefaultBackend != nil && spec.DefaultBackend.Service != nil {
		if svcPtr := spec.DefaultBackend.Service.Name; svcPtr != nil && *svcPtr != "" {
			svc := *svcPtr
			seen[svc] = struct{}{}
			names = append(names, svc)
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
func serviceExists(ingress *networkingv1.Ingress, settings Settings, serviceName string) (bool, error) {
	// 参数验证
	if ingress == nil || ingress.Metadata == nil {
		return false, fmt.Errorf("ingress object or metadata cannot be nil")
	}
	if serviceName == "" {
		return false, fmt.Errorf("service name cannot be empty")
	}

	// 构造请求
	req := map[string]interface{}{
		"api_version":   "v1",
		"kind":          "Service",
		"namespace":     ingress.Metadata.Namespace,
		"name":          serviceName,
		"disable_cache": settings.DisableCache,
	}

	logger.DebugWithFields("get_resource host call request", func(e onelog.Entry) {
		e.String("api_version", req["api_version"].(string))
		e.String("kind", req["kind"].(string))
		e.String("namespace", req["namespace"].(string))
		e.String("name", req["name"].(string))
		e.Bool("disable_cache", req["disable_cache"].(bool))
	})

	reqBytes, err := json.Marshal(req)
	if err != nil {
		return false, fmt.Errorf("failed to marshal get_resource request: %w", err)
	}

	// 调用 host capabilities
	respBytes, err := host.Client.HostCall(
		"kubewarden",
		"kubernetes",
		"get_resource",
		reqBytes,
	)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return false, nil
		}
		return false, fmt.Errorf("host call failed: %w", err)
	}

	return len(respBytes) > 0, nil
}
