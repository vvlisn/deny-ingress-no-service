package main

import (
	"testing"

	kubewarden_protocol "github.com/kubewarden/policy-sdk-go/protocol"
)

// helper: 构造一个 ValidationRequest，内嵌 rawSettings
func makeValidationRequest(rawSettings []byte) *kubewarden_protocol.ValidationRequest {
	return &kubewarden_protocol.ValidationRequest{
		Settings: rawSettings,
		// 其他字段在 Settings 测试中无需关心
	}
}

// 测试：未提供配置时，默认 EnforceServiceExists == true
func TestNewSettingsWithNoValueProvided(t *testing.T) {
	// 模拟用户未在 CRD 中填 settings（empty payload）
	vr := makeValidationRequest([]byte(``))

	settings, err := NewSettingsFromValidationReq(vr)
	if err != nil {
		t.Fatalf("Unexpected error creating settings: %v", err)
	}

	if !settings.EnforceServiceExists {
		t.Errorf("Expected EnforceServiceExists to default to true, got false")
	}
	if !settings.IsEnforcementEnabled() {
		t.Errorf("Expected IsEnforcementEnabled() to return true by default")
	}
	if valid, err := settings.Valid(); !valid || err != nil {
		t.Errorf("Expected settings.Valid() to pass, got valid=%v, err=%v", valid, err)
	}
}

// 测试：提供 explicit JSON 配置（false），应覆盖默认值
func TestNewSettingsWithExplicitFalse(t *testing.T) {
	vr := makeValidationRequest([]byte(`{"enforce_service_exists": false}`))

	settings, err := NewSettingsFromValidationReq(vr)
	if err != nil {
		t.Fatalf("Unexpected error creating settings: %v", err)
	}

	if settings.EnforceServiceExists {
		t.Errorf("Expected EnforceServiceExists to be false when explicitly set, got true")
	}
	if settings.IsEnforcementEnabled() {
		t.Errorf("Expected IsEnforcementEnabled() to return false when disabled")
	}
	if valid, err := settings.Valid(); !valid || err != nil {
		t.Errorf("Expected settings.Valid() to pass, got valid=%v, err=%v", valid, err)
	}
}

// 测试 validateSettings 函数：
// 1) 空 payload 应 AcceptSettings
// 2) JSON 格式错误应 RejectSettings
func TestValidateSettingsEntryPoint(t *testing.T) {
	// 1. AcceptSettings on empty settings
	acceptResp, err := validateSettings([]byte(``))
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	// validateSettings 返回的 JSON 中 code 为 200
	// kubewarden.AcceptSettings() 底层是空 payload + HTTP 200
	if string(acceptResp) == "" {
		t.Errorf("Expected non-empty response for AcceptSettings()")
	}

	// 2. RejectSettings on invalid JSON
	rejectResp, err := validateSettings([]byte(`{invalid json}`))
	if err != nil {
		// validateSettings 会返回 nil error and a RejectSettings payload
		t.Fatalf("Expected validateSettings to handle error internally, got err=%v", err)
	}
	if string(rejectResp) == string(acceptResp) {
		t.Errorf("Expected a different payload for RejectSettings() vs AcceptSettings()")
	}
}
