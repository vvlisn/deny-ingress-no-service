package main

import (
	"encoding/json"
	"errors"
	"fmt"

	kubewarden "github.com/kubewarden/policy-sdk-go"
	kubewarden_protocol "github.com/kubewarden/policy-sdk-go/protocol"
)

// ErrEmptySignatures 表示嵌套设置中的签名列表为空。
var ErrEmptySignatures = errors.New("nested settings contains empty signatures")

const defaultEnforceServiceExists = true
const defaultDisableCache = false

// Settings 定义了策略中的所有可配置项。
type Settings struct {
	// 是否强制校验 Ingress 引用的 Service 是否存在。
	EnforceServiceExists bool `json:"enforce_service_exists"`
	// 是否禁用 Host Capabilities 的缓存。
	DisableCache bool `json:"disable_cache"`
}

// IncomingSettings matches the structure of the settings provided by kwctl run.
type IncomingSettings struct {
	Signatures []Settings `json:"signatures"`
}

// tryUnmarshalFlatSettings 尝试将设置解析为扁平结构。
func tryUnmarshalFlatSettings(raw []byte) (*Settings, error) {
	var settings Settings
	if err := json.Unmarshal(raw, &settings); err != nil {
		return nil, err
	}
	return &settings, nil
}

// tryUnmarshalNestedSettings 尝试将设置解析为嵌套结构。
func tryUnmarshalNestedSettings(raw []byte) (*Settings, error) {
	var nested IncomingSettings
	if err := json.Unmarshal(raw, &nested); err != nil {
		return nil, err
	}
	if len(nested.Signatures) == 0 {
		return nil, ErrEmptySignatures
	}
	return &nested.Signatures[0], nil
}

// NewSettingsFromValidationReq 从 ValidationRequest 中提取设置，
// 并在用户未提供时应用默认值。
func NewSettingsFromValidationReq(validationReq *kubewarden_protocol.ValidationRequest) (Settings, error) {
	// 1. 使用默认值初始化
	settings := Settings{
		EnforceServiceExists: defaultEnforceServiceExists,
		DisableCache:         defaultDisableCache,
	}

	// 如果没有自定义设置，直接返回默认值
	if len(validationReq.Settings) == 0 {
		return settings, nil
	}

	// 2. 尝试以扁平格式解析（向后兼容）
	if flatSettings, err := tryUnmarshalFlatSettings(validationReq.Settings); err == nil && flatSettings != nil {
		return *flatSettings, nil
	}

	// 3. 尝试以嵌套格式解析
	if nestedSettings, err := tryUnmarshalNestedSettings(validationReq.Settings); err != nil {
		return Settings{}, fmt.Errorf("cannot parse settings JSON: %w", err)
	} else if nestedSettings != nil {
		return *nestedSettings, nil
	}

	// 4. 如果两种格式都无法解析，返回默认值
	return settings, nil
}

// Valid 对 Settings 本身做合法性校验。
func (s *Settings) Valid() (bool, error) {
	// 目前只有一个 bool 字段，无需更复杂的验证
	return true, nil
}

// IsEnforcementEnabled 返回最终是否要启用 Service 存在校验。
func (s *Settings) IsEnforcementEnabled() bool {
	return s.EnforceServiceExists
}

// validateSettings 由 Kubewarden 在策略加载时调用，
// 只负责反序列化并校验 Settings，不做默认值合并。
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
