package internal

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"unicode"
)

const (
	defaultMaxPayloadBytes = 4 << 20 // 4 MiB
	maxRegexPatternLen     = 512
	maxRulesCount          = 128
)

const redactedString = "***REDACTED***"

var (
	extraDefaultKeys  = []string{"email", "ip", "ip_address"}
	builtinRegexRules = []string{
		`/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/`,
		`/\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b/`,
	}
)

type ruleKind int

const (
	ruleFieldPrefix ruleKind = iota
	rulePath
	ruleRegex
)

type compiledRule struct {
	kind ruleKind
	raw  string
	re   *regexp.Regexp
	path string // for path rules, without "path:" prefix
}

func keyMatchesToken(key, token string) bool {
	keyLower := strings.ToLower(key)
	token = strings.ToLower(token)
	if keyLower == token {
		return true
	}
	for _, seg := range splitKeySegments(key) {
		if strings.ToLower(seg) == token {
			return true
		}
	}
	return false
}

func splitKeySegments(key string) []string {
	parts := strings.Split(key, "_")
	segs := make([]string, 0, len(parts))
	for _, part := range parts {
		if part == "" {
			continue
		}
		segs = append(segs, splitCamelCase(part)...)
	}
	return segs
}

func splitCamelCase(s string) []string {
	if s == "" {
		return nil
	}
	runes := []rune(s)
	start := 0
	var parts []string
	for i := 1; i < len(runes); i++ {
		if unicode.IsUpper(runes[i]) && (unicode.IsLower(runes[i-1]) || unicode.IsDigit(runes[i-1])) {
			parts = append(parts, string(runes[start:i]))
			start = i
		}
	}
	parts = append(parts, string(runes[start:]))
	return parts
}

func regexMatches(ctx context.Context, re *regexp.Regexp, s string) bool {
	if err := ctx.Err(); err != nil {
		return false
	}
	type result struct {
		ok bool
	}
	ch := make(chan result, 1)
	go func() {
		ch <- result{re.MatchString(s)}
	}()
	select {
	case <-ctx.Done():
		return false
	case r := <-ch:
		return r.ok
	}
}

func valueMatchesRegexRules(ctx context.Context, s string, rules []compiledRule) bool {
	for _, rule := range rules {
		if rule.kind != ruleRegex {
			continue
		}
		if regexMatches(ctx, rule.re, s) {
			return true
		}
	}
	return false
}

func compileRules(raw []string) ([]compiledRule, error) {
	if len(raw) > maxRulesCount {
		return nil, fmt.Errorf("too many rules (%d > %d)", len(raw), maxRulesCount)
	}
	rules := make([]compiledRule, 0, len(raw))
	for _, r := range raw {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}

		if strings.HasPrefix(r, "field:") {
			rules = append(rules, compiledRule{
				kind: ruleFieldPrefix,
				raw:  strings.ToLower(strings.TrimPrefix(r, "field:")),
			})
		} else if strings.HasPrefix(r, "path:") {
			path := strings.TrimPrefix(r, "path:")
			rules = append(rules, compiledRule{
				kind: rulePath,
				raw:  r,
				path: path,
			})
		} else if len(r) > 2 && r[0] == '/' && strings.LastIndex(r, "/") > 0 {
			inner := r[1 : len(r)-1]
			if len(inner) > maxRegexPatternLen {
				return nil, fmt.Errorf("regex pattern too long (%d > %d)", len(inner), maxRegexPatternLen)
			}
			re, err := regexp.Compile(inner)
			if err != nil {
				return nil, fmt.Errorf("invalid regex %q: %w", r, err)
			}
			rules = append(rules, compiledRule{
				kind: ruleRegex,
				raw:  r,
				re:   re,
			})
		} else {
			rules = append(rules, compiledRule{
				kind: ruleFieldPrefix,
				raw:  strings.ToLower(r),
			})
		}
	}
	return rules, nil
}

func redactMap(data map[string]any, defaultKeys []string, rules []compiledRule, ctx context.Context) map[string]any {
	return redactMapWithPath(data, defaultKeys, rules, "", ctx)
}

func redactMapWithPath(data map[string]any, defaultKeys []string, rules []compiledRule, parentPath string, ctx context.Context) map[string]any {
	out := make(map[string]any, len(data))
	for k, v := range data {
		currentPath := k
		if parentPath != "" {
			currentPath = parentPath + "." + k
		}

		redact := false

		for _, dk := range defaultKeys {
			if keyMatchesToken(k, dk) {
				redact = true
				break
			}
		}
		if !redact {
			for _, rule := range rules {
				if matchesRule(k, v, rule, currentPath, ctx) {
					redact = true
					break
				}
			}
		}

		if redact {
			out[k] = redactedString
		} else {
			out[k] = redactValueWithPath(v, defaultKeys, rules, currentPath, ctx)
		}
	}
	return out
}

func matchesRule(key string, val any, rule compiledRule, currentPath string, ctx context.Context) bool {
	switch rule.kind {
	case ruleFieldPrefix:
		return keyMatchesToken(key, rule.raw)
	case rulePath:
		return currentPath == rule.path
	case ruleRegex:
		s, ok := val.(string)
		if !ok {
			return false
		}
		return regexMatches(ctx, rule.re, s)
	}
	return false
}

func redactValueWithPath(v any, defaultKeys []string, rules []compiledRule, parentPath string, ctx context.Context) any {
	switch val := v.(type) {
	case map[string]any:
		return redactMapWithPath(val, defaultKeys, rules, parentPath, ctx)
	case []any:
		out := make([]any, len(val))
		for i, item := range val {
			out[i] = redactArrayElement(item, defaultKeys, rules, parentPath, ctx)
		}
		return out
	default:
		return v
	}
}

func redactArrayElement(item any, defaultKeys []string, rules []compiledRule, parentPath string, ctx context.Context) any {
	switch v := item.(type) {
	case map[string]any:
		return redactMapWithPath(v, defaultKeys, rules, parentPath, ctx)
	case []any:
		return redactValueWithPath(v, defaultKeys, rules, parentPath, ctx)
	case string:
		if valueMatchesRegexRules(ctx, v, rules) {
			return redactedString
		}
		return v
	default:
		return item
	}
}
