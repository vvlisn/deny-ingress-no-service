package main

import (
	"encoding/json"
	"fmt"
	"testing"

	networkingv1 "github.com/kubewarden/k8s-objects/api/networking/v1"
	metav1 "github.com/kubewarden/k8s-objects/apimachinery/pkg/apis/meta/v1"
	kubewarden_protocol "github.com/kubewarden/policy-sdk-go/protocol"
	kubewarden_testing "github.com/kubewarden/policy-sdk-go/testing"
)

// 模拟 host capabilities 调用的响应
type mockWapcClient struct{}

func (c *mockWapcClient) HostCall(binding, namespace, operation string, payload []byte) ([]byte, error) {
	if binding == "kubewarden" && namespace == "kubernetes" && operation == "get_resource" {
		// 解析请求
		req := map[string]string{}
		if err := json.Unmarshal(payload, &req); err != nil {
			return nil, err
		}

		// 根据服务名返回不同响应
		if req["name"] == "my-service" {
			// 返回一个模拟的 service 对象
			return []byte(`{"kind":"Service","apiVersion":"v1"}`), nil
		}
		// 对于不存在的服务返回错误
		return nil, fmt.Errorf("not found")
	}
	return nil, fmt.Errorf("unexpected host call")
}

func setupTestEnv() {
	// 设置全局 host 的模拟客户端
	host.Client = &mockWapcClient{}
}

func TestEmptySettingsLeadsToApproval(t *testing.T) {
	setupTestEnv()
	settings := Settings{} // 默认值为 true，应该检查 service
	ingress := networkingv1.Ingress{
		Metadata: &metav1.ObjectMeta{
			Name:      "test-ingress",
			Namespace: "default",
		},
		Spec: &networkingv1.IngressSpec{
			DefaultBackend: &networkingv1.IngressBackend{
				Service: &networkingv1.IngressServiceBackend{
					Name: strPtr("my-service"), // 使用存在的服务
				},
			},
		},
	}

	payload, err := kubewarden_testing.BuildValidationRequest(&ingress, &settings)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	responsePayload, err := validate(payload)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	var response kubewarden_protocol.ValidationResponse
	if err = json.Unmarshal(responsePayload, &response); err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	if response.Accepted != true {
		t.Errorf("Unexpected rejection: msg %s - code %d", *response.Message, *response.Code)
	}
}

func TestApprovalWithDisabledValidation(t *testing.T) {
	setupTestEnv()
	settings := Settings{
		EnforceServiceExists: false, // 设置为 false 来禁用验证
	}
	ingress := networkingv1.Ingress{
		Metadata: &metav1.ObjectMeta{
			Name:      "test-ingress",
			Namespace: "default",
		},
		Spec: &networkingv1.IngressSpec{
			DefaultBackend: &networkingv1.IngressBackend{
				Service: &networkingv1.IngressServiceBackend{
					Name: strPtr("non-existent-service"),
					Port: &networkingv1.ServiceBackendPort{
						Number: 80,
					},
				},
			},
		},
	}

	payload, err := kubewarden_testing.BuildValidationRequest(&ingress, &settings)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	responsePayload, err := validate(payload)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	var response kubewarden_protocol.ValidationResponse
	if err = json.Unmarshal(responsePayload, &response); err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	if response.Accepted != true {
		t.Error("Unexpected rejection when validation is disabled")
	}
}

func TestApprovalWhenServicesExist(t *testing.T) {
	setupTestEnv()
	settings := Settings{
		EnforceServiceExists: true, // 启用验证，检查 service 是否存在
	}
	ingress := networkingv1.Ingress{
		Metadata: &metav1.ObjectMeta{
			Name:      "test-ingress",
			Namespace: "default",
		},
		Spec: &networkingv1.IngressSpec{
			DefaultBackend: &networkingv1.IngressBackend{
				Service: &networkingv1.IngressServiceBackend{
					Name: strPtr("my-service"), // 此服务在 mock 中存在
				},
			},
		},
	}

	payload, err := kubewarden_testing.BuildValidationRequest(&ingress, &settings)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	responsePayload, err := validate(payload)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	var response kubewarden_protocol.ValidationResponse
	if err = json.Unmarshal(responsePayload, &response); err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	if response.Accepted != true {
		t.Error("Unexpected rejection when services exist")
	}
}

func TestRejectionWhenServiceNotFound(t *testing.T) {
	setupTestEnv()
	settings := Settings{
		EnforceServiceExists: true, // 启用验证，检查 service 是否存在
	}
	ingress := networkingv1.Ingress{
		Metadata: &metav1.ObjectMeta{
			Name:      "test-ingress",
			Namespace: "default",
		},
		Spec: &networkingv1.IngressSpec{
			DefaultBackend: &networkingv1.IngressBackend{
				Service: &networkingv1.IngressServiceBackend{
					Name: strPtr("non-existent-service"), // 此服务在 mock 中不存在
				},
			},
		},
	}

	payload, err := kubewarden_testing.BuildValidationRequest(&ingress, &settings)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	responsePayload, err := validate(payload)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	var response kubewarden_protocol.ValidationResponse
	if err = json.Unmarshal(responsePayload, &response); err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	if response.Accepted != false {
		t.Error("Expected rejection when service does not exist")
	}

	expectedMessage := "Service 'non-existent-service' does not exist in namespace 'default'"
	if response.Message == nil {
		t.Errorf("expected response to have a message")
	}
	if *response.Message != expectedMessage {
		t.Errorf("Got '%s' instead of '%s'", *response.Message, expectedMessage)
	}
}

func TestEmptyIngressValidation(t *testing.T) {
	// 测试没有任何 backend 配置的 Ingress
	// 创建一个没有 DefaultBackend 的 Ingress
	ingress := networkingv1.Ingress{
		Metadata: &metav1.ObjectMeta{
			Name:      "empty-ingress",
			Namespace: "default",
		},
		Spec: &networkingv1.IngressSpec{
			// 没有 DefaultBackend
		},
	}

	// 使用默认设置，期望通过验证
	settings := Settings{}
	payload, err := kubewarden_testing.BuildValidationRequest(&ingress, &settings)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	responsePayload, err := validate(payload)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	var response kubewarden_protocol.ValidationResponse
	if err = json.Unmarshal(responsePayload, &response); err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	if response.Accepted != true {
		t.Errorf("Unexpected rejection for empty ingress: msg %s - code %d", *response.Message, *response.Code)
	}
}

func TestComplexIngressRules(t *testing.T) {
	setupTestEnv()
	settings := Settings{
		EnforceServiceExists: true, // 启用验证，检查 service 是否存在
	}
	ingress := networkingv1.Ingress{
		Metadata: &metav1.ObjectMeta{
			Name:      "complex-ingress",
			Namespace: "default",
		},
		Spec: &networkingv1.IngressSpec{
			// 1. 默认后端
			DefaultBackend: &networkingv1.IngressBackend{
				Service: &networkingv1.IngressServiceBackend{
					Name: strPtr("my-service"), // 存在的服务
					Port: &networkingv1.ServiceBackendPort{
						Number: 80,
					},
				},
			},
			// 2. 多个路径规则
			Rules: []*networkingv1.IngressRule{
				{
					Host: "foo.bar.com",
					HTTP: &networkingv1.HTTPIngressRuleValue{
						Paths: []*networkingv1.HTTPIngressPath{
							{
								Path:     "/foo",
								PathType: strPtr("Prefix"),
								Backend: &networkingv1.IngressBackend{
									Service: &networkingv1.IngressServiceBackend{
										Name: strPtr("my-service"),
										Port: &networkingv1.ServiceBackendPort{
											Number: 8080,
										},
									},
								},
							},
							{
								Path:     "/bar",
								PathType: strPtr("Prefix"),
								Backend: &networkingv1.IngressBackend{
									Service: &networkingv1.IngressServiceBackend{
										Name: strPtr("non-existent-service"),
										Port: &networkingv1.ServiceBackendPort{
											Number: 8080,
										},
									},
								},
							},
						},
					},
				},
				{
					Host: "another.example.com",
					HTTP: &networkingv1.HTTPIngressRuleValue{
						Paths: []*networkingv1.HTTPIngressPath{
							{
								Path:     "/",
								PathType: strPtr("Prefix"),
								Backend: &networkingv1.IngressBackend{
									Service: &networkingv1.IngressServiceBackend{
										Name: strPtr("my-service"),
										Port: &networkingv1.ServiceBackendPort{
											Number: 9090,
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	payload, err := kubewarden_testing.BuildValidationRequest(&ingress, &settings)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	responsePayload, err := validate(payload)
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	var response kubewarden_protocol.ValidationResponse
	if err = json.Unmarshal(responsePayload, &response); err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	// 因为包含不存在的服务，应该被拒绝
	if response.Accepted {
		t.Error("Expected complex Ingress to be rejected due to non-existent service")
	}

	expectedMessage := "Service 'non-existent-service' does not exist in namespace 'default'"
	if response.Message == nil {
		t.Errorf("expected response to have a message")
	}
	if *response.Message != expectedMessage {
		t.Errorf("Got '%s' instead of '%s'", *response.Message, expectedMessage)
	}

	// 测试服务去重功能
	// 设置验证禁用以便我们可以提取服务名而不被拒绝
	settings.EnforceServiceExists = false
	payload, _ = kubewarden_testing.BuildValidationRequest(&ingress, &settings)
	validationRequest := kubewarden_protocol.ValidationRequest{}
	_ = json.Unmarshal(payload, &validationRequest)
	ing, _ := getIngress(validationRequest.Request.Object)

	serviceNames := extractServiceNames(ing)
	// 虽然 my-service 被引用了3次，但应该只出现一次
	expectedServices := []string{"my-service", "non-existent-service"}
	if len(serviceNames) != len(expectedServices) {
		t.Errorf("Expected %d unique services, got %d", len(expectedServices), len(serviceNames))
	}
	// 验证服务列表中包含所有期望的服务
	servicesMap := make(map[string]bool)
	for _, name := range serviceNames {
		servicesMap[name] = true
	}
	for _, expected := range expectedServices {
		if !servicesMap[expected] {
			t.Errorf("Expected service '%s' not found in extracted services", expected)
		}
	}
}

// strPtr 返回字符串指针的辅助函数
func strPtr(s string) *string {
	return &s
}
