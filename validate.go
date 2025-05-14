package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	onelog "github.com/francoispqt/onelog"
	kubewarden "github.com/kubewarden/policy-sdk-go"
	"github.com/kubewarden/policy-sdk-go/pkg/capabilities"
	kubewarden_protocol "github.com/kubewarden/policy-sdk-go/protocol"
	"github.com/tidwall/gjson"
)

const httpBadRequestStatusCode = 400

//nolint:gochecknoglobals // host 是 Kubewarden SDK 推荐的全局变量使用方式
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

	// 解析 Ingress 对象
	ingressJSON := validationRequest.Request.Object
	if len(ingressJSON) == 0 {
		return kubewarden.RejectRequest(
			kubewarden.Message("empty ingress object"),
			kubewarden.Code(httpBadRequestStatusCode))
	}

	// 使用 gjson 解析 metadata
	metadata := gjson.GetBytes(ingressJSON, "metadata")
	if !metadata.Exists() {
		return kubewarden.RejectRequest(
			kubewarden.Message("ingress metadata not found"),
			kubewarden.Code(httpBadRequestStatusCode))
	}

	name := metadata.Get("name").String()
	namespace := metadata.Get("namespace").String()

	logger.DebugWithFields("validating ingress object", func(e onelog.Entry) {
		e.String("name", name)
		e.String("namespace", namespace)
	})

	// 如果不需要检查，直接通过
	if !settings.IsEnforcementEnabled() {
		return kubewarden.AcceptRequest()
	}

	// 提取所有后端 Service 名称
	svcNames := extractServiceNamesWithGjson(ingressJSON)
	if len(svcNames) == 0 {
		// 没有服务需要验证，直接通过
		return kubewarden.AcceptRequest()
	}

	// 逐个检查 Service 是否存在
	for _, svc := range svcNames {
		serviceOK, serviceErr := serviceExistsWithGjson(namespace, settings, svc)
		if serviceErr != nil {
			return kubewarden.RejectRequest(
				kubewarden.Message(fmt.Sprintf("Error checking Service '%s': %s", svc, serviceErr)),
				kubewarden.NoCode)
		}
		if !serviceOK {
			return kubewarden.RejectRequest(
				kubewarden.Message(fmt.Sprintf(
					"Service '%s' does not exist in namespace '%s'",
					svc, namespace)),
				kubewarden.NoCode)
		}
	}

	// 全部校验通过
	return kubewarden.AcceptRequest()
}

// extractServiceNamesWithGjson 使用 gjson 从 Ingress JSON 中提取所有 Service 名称.
func extractServiceNamesWithGjson(ingressJSON []byte) []string {
	seen := make(map[string]struct{})

	// 获取默认后端服务名称
	defaultBackend := gjson.GetBytes(ingressJSON, "spec.defaultBackend.service.name")
	if defaultBackend.Exists() && defaultBackend.String() != "" {
		seen[defaultBackend.String()] = struct{}{}
	}

	// 获取所有路径规则中的服务名称
	spec := gjson.GetBytes(ingressJSON, "spec")
	if spec.Exists() {
		spec.Get("rules").ForEach(func(_, rule gjson.Result) bool {
			if http := rule.Get("http"); http.Exists() {
				http.Get("paths").ForEach(func(_, path gjson.Result) bool {
					if svcName := path.Get("backend.service.name"); svcName.Exists() && svcName.String() != "" {
						seen[svcName.String()] = struct{}{}
					}
					return true
				})
			}
			return true
		})
	}

	// 转换为切片
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	return names
}

// serviceExistsWithGjson 使用 gjson 检查 Service 是否存在.
func serviceExistsWithGjson(namespace string, settings Settings, serviceName string) (bool, error) {
	if namespace == "" {
		return false, errors.New("namespace cannot be empty")
	}
	if serviceName == "" {
		return false, errors.New("service name cannot be empty")
	}

	// 构造请求
	req := map[string]interface{}{
		"api_version":   "v1",
		"kind":          "Service",
		"namespace":     namespace,
		"name":          serviceName,
		"disable_cache": settings.DisableCache,
	}

	//nolint:errcheck // Entry methods return self for chaining
	logger.DebugWithFields("checking service existence", func(e onelog.Entry) {
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
