package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/kubewarden/policy-sdk-go/pkg/capabilities"
	"github.com/kubewarden/policy-sdk-go/pkg/capabilities/mocks"
	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v2"
)

// Exchange 用于生成 replay 文件的记录条目
type Exchange struct {
	Type     string `yaml:"type"`    // 固定 "Exchange"
	Request  string `yaml:"request"` // waPC 请求
	Response struct {
		Type    string `yaml:"type"`              // "Success" 或 "Failure"
		Payload string `yaml:"payload,omitempty"` // 成功时的 JSON 文本
		Message string `yaml:"message,omitempty"` // 失败时的错误消息
	} `yaml:"response"`
}

// serviceExistsWithHost 调用 HostCall 判断 Service 是否存在
func serviceExistsWithHost(host capabilities.Host, namespace, svcName string) (bool, error) {
	req := map[string]interface{}{
		"api_version":   "v1",
		"kind":          "Service",
		"namespace":     namespace,
		"name":          svcName,
		"disable_cache": true,
	}
	payload, _ := json.Marshal(req)
	resp, err := host.Client.HostCall("kubewarden", "kubernetes", "get_resource", payload)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return false, nil
		}
		return false, err
	}
	return len(resp) > 0, nil
}

// writeYAMLSession 将交互记录写为 YAML 数组
func writeYAMLSession(exchanges []Exchange, path string) error {
	data, err := yaml.Marshal(exchanges)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func TestGenerateReplayYAML(t *testing.T) {
	namespace := "default"
	var exchanges []Exchange

	// 1. 模拟“my-service 存在”场景
	{
		mockClient := &mocks.MockWapcClient{}
		host := capabilities.Host{Client: mockClient}

		// 预期请求
		req := map[string]interface{}{
			"api_version":   "v1",
			"kind":          "Service",
			"namespace":     namespace,
			"name":          "my-service",
			"disable_cache": true,
		}
		reqBytes, _ := json.Marshal(req)
		// 假响应载荷
		fakePayload := []byte(`{"apiVersion":"v1","kind":"Service","metadata":{"name":"my-service","namespace":"default"}}`)

		// 设置 mock
		mockClient.On("HostCall",
			"kubewarden", "kubernetes", "get_resource", reqBytes,
		).Return(fakePayload, nil)

		// 验证逻辑行为
		exists, err := serviceExistsWithHost(host, namespace, "my-service")
		assert.NoError(t, err)
		assert.True(t, exists)
		mockClient.AssertExpectations(t)

		// 追加 Exchange 记录
		ex := Exchange{
			Type: "Exchange",
			Request: fmt.Sprintf(
				"!KubernetesGetResource\napi_version: v1\nkind: Service\nnamespace: %s\nname: my-service\ndisable_cache: true\n",
				namespace),
		}
		ex.Response.Type = "Success"
		ex.Response.Payload = string(fakePayload)
		exchanges = append(exchanges, ex)
	}

	// 2. 模拟“non-existent-service 不存在”场景
	{
		mockClient := &mocks.MockWapcClient{}
		host := capabilities.Host{Client: mockClient}

		req := map[string]interface{}{
			"api_version":   "v1",
			"kind":          "Service",
			"namespace":     namespace,
			"name":          "non-existent-service",
			"disable_cache": true,
		}
		reqBytes, _ := json.Marshal(req)

		mockClient.On("HostCall",
			"kubewarden", "kubernetes", "get_resource", reqBytes,
		).Return(nil, errors.New("not found"))

		exists, err := serviceExistsWithHost(host, namespace, "non-existent-service")
		assert.NoError(t, err)
		assert.False(t, exists)
		mockClient.AssertExpectations(t)

		ex := Exchange{
			Type: "Exchange",
			Request: fmt.Sprintf(
				"!KubernetesGetResource\napi_version: v1\nkind: Service\nnamespace: %s\nname: non-existent-service\ndisable_cache: true\n",
				namespace),
		}
		ex.Response.Type = "Failure"
		ex.Response.Message = "not found"
		exchanges = append(exchanges, ex)
	}

	// 3. 写入 YAML 文件
	err := writeYAMLSession(exchanges, "test_data/mock_host_capabilities.yml")
	assert.NoError(t, err)
}
