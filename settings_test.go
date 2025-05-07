package main

import (
	"encoding/json"
	"testing"
)

// 测试未提供配置时的默认值
func TestParsingSettingsWithNoValueProvided(t *testing.T) {
	rawSettings := []byte(`{}`)
	settings := &Settings{}
	if err := json.Unmarshal(rawSettings, settings); err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	// 默认值应为 true
	if !settings.IsEnforcementEnabled() {
		t.Errorf("Expected EnforceServiceExists to be true by default")
	}

	// 校验应通过
	valid, err := settings.Valid()
	if !valid {
		t.Errorf("Settings should be valid")
	}
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}
}

// 测试 EnforceServiceExists 的行为
func TestEnforceServiceExists(t *testing.T) {
	// 场景1：启用检查
	settings := Settings{
		EnforceServiceExists: true,
	}

	if !settings.IsEnforcementEnabled() {
		t.Errorf("Service enforcement should be enabled when EnforceServiceExists is true")
	}

	// 场景2：禁用检查
	settings = Settings{
		EnforceServiceExists: false,
	}

	if settings.IsEnforcementEnabled() {
		t.Errorf("Service enforcement should be disabled when EnforceServiceExists is false")
	}
}

// 测试提供配置时的解析
func TestParsingSettingsWithValueProvided(t *testing.T) {
	rawSettings := []byte(`{"enforce_service_exists": false}`)
	settings := &Settings{}
	if err := json.Unmarshal(rawSettings, settings); err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}

	// 用户配置应覆盖默认值
	if settings.EnforceServiceExists {
		t.Errorf("Expected EnforceServiceExists to be false")
	}

	// 校验应通过
	valid, err := settings.Valid()
	if !valid {
		t.Errorf("Settings should be valid")
	}
	if err != nil {
		t.Errorf("Unexpected error: %+v", err)
	}
}
