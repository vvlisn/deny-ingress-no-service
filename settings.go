package main

import (
	"encoding/json"
	"fmt"

	kubewarden "github.com/kubewarden/policy-sdk-go"
	kubewarden_protocol "github.com/kubewarden/policy-sdk-go/protocol"
)

const defaultEnforceServiceExists = true

// Settings 定义了策略中的所有可配置项
type Settings struct {
	// 是否强制校验 Ingress 引用的 Service 是否存在
	EnforceServiceExists bool `json:"enforce_service_exists"`
}

// NewSettingsFromValidationReq 从 ValidationRequest 中提取设置，
// 并在用户未提供时应用默认值
func NewSettingsFromValidationReq(validationReq *kubewarden_protocol.ValidationRequest) (Settings, error) {
	// 1. 用默认值初始化
	settings := Settings{
		EnforceServiceExists: defaultEnforceServiceExists,
	}
	// 2. 如果用户在 CRD 中提供了 settings，就合并
	if len(validationReq.Settings) > 0 {
		if err := json.Unmarshal(validationReq.Settings, &settings); err != nil {
			return Settings{}, fmt.Errorf("cannot parse settings JSON: %w", err)
		}
	}
	return settings, nil
}

// Valid 对 Settings 本身做合法性校验
func (s *Settings) Valid() (bool, error) {
	// 目前只有一个 bool 字段，无需更复杂的验证
	return true, nil
}

// IsEnforcementEnabled 返回最终是否要启用 Service 存在校验
func (s *Settings) IsEnforcementEnabled() bool {
	return s.EnforceServiceExists
}

// validateSettings 由 Kubewarden 在策略加载时调用，
// 只负责反序列化并校验 Settings，不做默认值合并
func validateSettings(payload []byte) ([]byte, error) {
	var settings Settings
	if err := json.Unmarshal(payload, &settings); err != nil {
		return kubewarden.RejectSettings(
			kubewarden.Message(fmt.Sprintf("Provided settings are not valid: %v", err)),
		)
	}

	valid, err := settings.Valid()
	if err != nil {
		return kubewarden.RejectSettings(
			kubewarden.Message(fmt.Sprintf("Settings validation failed: %v", err)),
		)
	}
	if !valid {
		return kubewarden.RejectSettings(
			kubewarden.Message("Settings validation failed"),
		)
	}

	return kubewarden.AcceptSettings()
}
