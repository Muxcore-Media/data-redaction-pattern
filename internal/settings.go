package internal

import (
	"fmt"
	"strings"

	"github.com/Muxcore-Media/core/pkg/contracts"
)

func (m *Module) Settings() []contracts.SettingDef {
	return m.settingsDefs()
}

func (m *Module) UpdateSetting(key, value string) error {
	return m.updateSetting(key, value)
}

func (m *Module) settingsDefs() []contracts.SettingDef {
	m.mu.RLock()
	extra := strings.Join(m.extraKeys, ",")
	m.mu.RUnlock()
	return []contracts.SettingDef{
		{
			Key:         "extra_keys",
			Label:       "Extra Sensitive Keys",
			Type:        contracts.SettingTypeString,
			Value:       extra,
			Default:     "",
			Description: "Comma-separated extra field-name substrings to redact (REDACTION_EXTRA_KEYS), in addition to built-in sensitive names",
			Group:       "Redaction",
		},
	}
}

func (m *Module) updateSetting(key, value string) error {
	switch key {
	case "extra_keys", "REDACTION_EXTRA_KEYS":
		m.mu.Lock()
		m.extraKeys = parseCSVLower(value)
		m.rebuildDefaultKeysLocked()
		m.mu.Unlock()
		return nil
	default:
		return fmt.Errorf("unknown setting %q", key)
	}
}

func parseCSVLower(v string) []string {
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.ToLower(strings.TrimSpace(p))
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func (m *Module) rebuildDefaultKeysLocked() {
	keys := make([]string, 0, len(m.baseKeys)+len(m.extraKeys))
	keys = append(keys, m.baseKeys...)
	keys = append(keys, m.extraKeys...)
	m.defaultKeys = keys
}
