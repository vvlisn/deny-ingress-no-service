package main

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	kubewarden_protocol "github.com/kubewarden/policy-sdk-go/protocol"
)

// 模拟 host capabilities 调用的响应.
type mockWapcClient struct{}

func (c *mockWapcClient) HostCall(binding, namespace, operation string, payload []byte) ([]byte, error) {
	if binding == "kubewarden" && namespace == "kubernetes" && operation == "get_resource" {
		// 解析请求
		req := map[string]interface{}{}
		if err := json.Unmarshal(payload, &req); err != nil {
			return nil, err
		}

		// 根据服务名返回不同响应
		if name, ok := req["name"].(string); ok && name == "my-service" {
			// 返回一个模拟的 service 对象
			return []byte(`{"kind":"Service","apiVersion":"v1"}`), nil
		}
		// 对于不存在的服务返回错误
		return nil, errors.New("not found")
	}
	return nil, errors.New("unexpected host call")
}

func setupTestEnv() {
	// 设置全局 host 的模拟客户端
	host.Client = &mockWapcClient{}
}

func validateTest(
	t *testing.T,
	request kubewarden_protocol.ValidationRequest,
) (*kubewarden_protocol.ValidationResponse, error) {
	t.Helper()

	payload, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	responsePayload, err := validate(payload)
	if err != nil {
		return nil, err
	}

	var response kubewarden_protocol.ValidationResponse
	if unmarshalErr := json.Unmarshal(responsePayload, &response); unmarshalErr != nil {
		return nil, unmarshalErr
	}

	return &response, nil
}

func TestIngressValidation(t *testing.T) {
	setupTestEnv()

	tests := []struct {
		name        string
		settings    string
		ingress     string
		shouldAllow bool
	}{
		{
			name:     "accept with default settings and existing service",
			settings: `{}`,
			ingress: `{
				"apiVersion": "networking.k8s.io/v1",
				"kind": "Ingress",
				"metadata": {
					"name": "test-ingress",
					"namespace": "default"
				},
				"spec": {
					"defaultBackend": {
						"service": {
							"name": "my-service",
							"port": {"number": 80}
						}
					}
				}
			}`,
			shouldAllow: true,
		},
		{
			name:     "accept when validation is disabled",
			settings: `{"enforce_service_exists": false}`,
			ingress: `{
				"apiVersion": "networking.k8s.io/v1",
				"kind": "Ingress",
				"metadata": {
					"name": "test-ingress",
					"namespace": "default"
				},
				"spec": {
					"defaultBackend": {
						"service": {
							"name": "non-existent-service",
							"port": {"number": 80}
						}
					}
				}
			}`,
			shouldAllow: true,
		},
		{
			name:     "reject when service does not exist",
			settings: `{"enforce_service_exists": true}`,
			ingress: `{
				"apiVersion": "networking.k8s.io/v1",
				"kind": "Ingress",
				"metadata": {
					"name": "test-ingress",
					"namespace": "default"
				},
				"spec": {
					"defaultBackend": {
						"service": {
							"name": "non-existent-service",
							"port": {"number": 80}
						}
					}
				}
			}`,
			shouldAllow: false,
		},
		{
			name:     "accept empty ingress",
			settings: `{"enforce_service_exists": true}`,
			ingress: `{
				"apiVersion": "networking.k8s.io/v1",
				"kind": "Ingress",
				"metadata": {
					"name": "empty-ingress",
					"namespace": "default"
				},
				"spec": {}
			}`,
			shouldAllow: true,
		},
		{
			name:     "reject complex ingress with non-existent service",
			settings: `{"enforce_service_exists": true}`,
			ingress: `{
				"apiVersion": "networking.k8s.io/v1",
				"kind": "Ingress",
				"metadata": {
					"name": "complex-ingress",
					"namespace": "default"
				},
				"spec": {
					"defaultBackend": {
						"service": {
							"name": "my-service",
							"port": {"number": 80}
						}
					},
					"rules": [
						{
							"host": "foo.bar.com",
							"http": {
								"paths": [
									{
										"path": "/foo",
										"pathType": "Prefix",
										"backend": {
											"service": {
												"name": "my-service",
												"port": {"number": 8080}
											}
										}
									},
									{
										"path": "/bar",
										"pathType": "Prefix",
										"backend": {
											"service": {
												"name": "non-existent-service",
												"port": {"number": 8080}
											}
										}
									}
								]
							}
						}
					]
				}
			}`,
			shouldAllow: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := kubewarden_protocol.ValidationRequest{
				Request: kubewarden_protocol.KubernetesAdmissionRequest{
					Object: json.RawMessage(test.ingress),
				},
				Settings: json.RawMessage(test.settings),
			}

			response, err := validateTest(t, request)
			if err != nil {
				t.Errorf("Unexpected error: %+v", err)
				return
			}

			if response.Accepted != test.shouldAllow {
				t.Errorf("Expected validation to return %v, got %v. Message: %s",
					test.shouldAllow, response.Accepted, *response.Message)
			}

			// 对于期望拒绝的用例，检查错误消息
			if !test.shouldAllow && strings.Contains(test.name, "non-existent-service") {
				expectedMessage := "Service 'non-existent-service' does not exist in namespace 'default'"
				if response.Message == nil || *response.Message != expectedMessage {
					t.Errorf("Expected message '%s', got '%v'", expectedMessage, response.Message)
				}
			}
		})
	}
}

// TestServiceNameExtraction 测试从 Ingress JSON 中提取服务名的功能.
func TestServiceNameExtraction(t *testing.T) {
	tests := []struct {
		name     string
		json     string
		expected []string
	}{
		{
			name: "empty ingress",
			json: `{
				"spec": {}
			}`,
			expected: nil,
		},
		{
			name: "default backend only",
			json: `{
				"spec": {
					"defaultBackend": {
						"service": {
							"name": "default-svc"
						}
					}
				}
			}`,
			expected: []string{"default-svc"},
		},
		{
			name: "multiple rules with duplication",
			json: `{
				"spec": {
					"defaultBackend": {
						"service": {
							"name": "default-svc"
						}
					},
					"rules": [
						{
							"http": {
								"paths": [
									{
										"backend": {
											"service": {
												"name": "service-a"
											}
										}
									},
									{
										"backend": {
											"service": {
												"name": "default-svc"
											}
										}
									}
								]
							}
						}
					]
				}
			}`,
			expected: []string{"default-svc", "service-a"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// 使用 gjson 提取服务名
			names := extractServiceNamesWithGjson([]byte(tc.json))

			// 验证服务数量
			if len(names) != len(tc.expected) {
				t.Errorf("Expected %d services, got %d", len(tc.expected), len(names))
			}

			// 验证所有期望的服务名都存在
			namesMap := make(map[string]bool)
			for _, name := range names {
				namesMap[name] = true
			}
			for _, expected := range tc.expected {
				if !namesMap[expected] {
					t.Errorf("Expected service '%s' not found in extracted services", expected)
				}
			}
		})
	}
}
