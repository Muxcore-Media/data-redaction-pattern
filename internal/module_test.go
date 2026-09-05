package internal

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	dataredactionv1 "github.com/Muxcore-Media/core/proto/gen/muxcore/dataredaction/v1"
)

func TestModuleInfo(t *testing.T) {
	m := NewModule(Config{})
	info := m.Info()
	if info.ID == "" {
		t.Error("module ID must not be empty")
	}
	if info.Version == "" {
		t.Error("module version must not be empty")
	}
	if info.MinCoreVersion == "" {
		t.Error("MinCoreVersion must not be empty")
	}
	if len(info.Contracts) == 0 {
		t.Error("Contracts must not be empty")
	}
	if info.Contracts[0].Interface != "DataRedactionProvider" {
		t.Errorf("expected DataRedactionProvider contract, got %s", info.Contracts[0].Interface)
	}
	if len(info.Capabilities) == 0 {
		t.Error("Capabilities must not be empty")
	}
	if info.Capabilities[0] != "data.redaction" {
		t.Errorf("expected data.redaction capability, got %s", info.Capabilities[0])
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestDefaultRedactsSensitiveKeys(t *testing.T) {
	m := NewModule(Config{})
	ctx := context.Background()

	input := mustJSON(t, map[string]any{
		"password": "my-secret",
		"username": "alice",
		"api_key":  "sk-1234",
		"token":    "eyJhbGci",
	})

	resp, err := m.Redact(ctx, &dataredactionv1.RedactRequest{Data: input})
	if err != nil {
		t.Fatal(err)
	}

	var result map[string]any
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		t.Fatal(err)
	}

	if result["password"] != redactedString {
		t.Errorf("expected password redacted, got %v", result["password"])
	}
	if result["api_key"] != redactedString {
		t.Errorf("expected api_key redacted, got %v", result["api_key"])
	}
	if result["token"] != redactedString {
		t.Errorf("expected token redacted, got %v", result["token"])
	}
	if result["username"] != "alice" {
		t.Errorf("expected username=alice, got %v", result["username"])
	}
}

func TestDefaultRedactsNestedSensitiveKeys(t *testing.T) {
	m := NewModule(Config{})
	ctx := context.Background()

	input := mustJSON(t, map[string]any{
		"user": map[string]any{
			"name":     "alice",
			"password": "secret123",
			"email":    "alice@example.com",
		},
	})

	resp, err := m.Redact(ctx, &dataredactionv1.RedactRequest{Data: input})
	if err != nil {
		t.Fatal(err)
	}

	var result map[string]any
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		t.Fatal(err)
	}

	user := result["user"].(map[string]any)
	if user["password"] != redactedString {
		t.Errorf("expected nested password redacted, got %v", user["password"])
	}
	if user["email"] != redactedString {
		t.Errorf("expected nested email redacted, got %v", user["email"])
	}
	if user["name"] != "alice" {
		t.Errorf("expected nested name=alice, got %v", user["name"])
	}
}

func TestFieldRule(t *testing.T) {
	m := NewModule(Config{})
	ctx := context.Background()

	input := mustJSON(t, map[string]any{
		"email":      "alice@example.com",
		"user_email": "bob@example.com",
		"name":       "alice",
	})

	resp, err := m.Redact(ctx, &dataredactionv1.RedactRequest{
		Data:  input,
		Rules: []string{"field:email"},
	})
	if err != nil {
		t.Fatal(err)
	}

	var result map[string]any
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		t.Fatal(err)
	}

	if result["email"] != redactedString {
		t.Errorf("expected email redacted, got %v", result["email"])
	}
	if result["user_email"] != redactedString {
		t.Errorf("expected user_email redacted, got %v", result["user_email"])
	}
	if result["name"] != "alice" {
		t.Errorf("expected name=alice, got %v", result["name"])
	}
}

func TestPathRule(t *testing.T) {
	m := NewModule(Config{})
	ctx := context.Background()

	input := mustJSON(t, map[string]any{
		"user": map[string]any{
			"address": map[string]any{
				"street": "123 Main St",
				"zip":    "90210",
			},
		},
		"other": "data",
	})

	resp, err := m.Redact(ctx, &dataredactionv1.RedactRequest{
		Data:  input,
		Rules: []string{"path:user.address.street"},
	})
	if err != nil {
		t.Fatal(err)
	}

	var result map[string]any
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		t.Fatal(err)
	}

	if result["other"] != "data" {
		t.Errorf("expected other=data, got %v", result["other"])
	}

	addr := result["user"].(map[string]any)["address"].(map[string]any)
	if addr["street"] != redactedString {
		t.Errorf("expected street redacted, got %v", addr["street"])
	}
	if addr["zip"] != "90210" {
		t.Errorf("expected zip=90210, got %v", addr["zip"])
	}
}

func TestRegexRule(t *testing.T) {
	m := NewModule(Config{})
	ctx := context.Background()

	input := mustJSON(t, map[string]any{
		"phone": "555-123-4567",
		"name":  "alice",
	})

	resp, err := m.Redact(ctx, &dataredactionv1.RedactRequest{
		Data:  input,
		Rules: []string{"/\\d{3}-\\d{3}-\\d{4}/"},
	})
	if err != nil {
		t.Fatal(err)
	}

	var result map[string]any
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		t.Fatal(err)
	}

	if result["phone"] != redactedString {
		t.Errorf("expected phone redacted, got %v", result["phone"])
	}
	if result["name"] != "alice" {
		t.Errorf("expected name=alice, got %v", result["name"])
	}
}

func TestNonMapValuePreserved(t *testing.T) {
	m := NewModule(Config{})
	ctx := context.Background()

	input := mustJSON(t, []string{"a", "b", "c"})

	resp, err := m.Redact(ctx, &dataredactionv1.RedactRequest{Data: input})
	if err == nil {
		t.Fatalf("expected error for non-object input, got %s", resp.Data)
	}
}

func TestArrayRedact(t *testing.T) {
	m := NewModule(Config{})
	ctx := context.Background()

	inputObj := map[string]any{"items": []any{
		map[string]any{"name": "alice", "password": "secret1"},
		map[string]any{"name": "bob", "password": "secret2"},
	}}
	resp, err := m.Redact(ctx, &dataredactionv1.RedactRequest{Data: mustJSON(t, inputObj)})
	if err != nil {
		t.Fatal(err)
	}

	var result map[string]any
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		t.Fatal(err)
	}

	items := result["items"].([]any)
	for i, item := range items {
		obj := item.(map[string]any)
		if obj["password"] != redactedString {
			t.Errorf("item %d: expected password redacted, got %v", i, obj["password"])
		}
		if obj["name"] == redactedString {
			t.Errorf("item %d: name should not be redacted", i)
		}
	}
}

func TestSupportedRules(t *testing.T) {
	m := NewModule(Config{})
	ctx := context.Background()
	resp, err := m.SupportedRules(ctx, &dataredactionv1.SupportedRulesRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.RuleTypes) == 0 {
		t.Fatal("expected at least one rule type description")
	}
	foundDefaults := false
	for _, rt := range resp.RuleTypes {
		if strings.HasPrefix(rt, "default_keys:") {
			foundDefaults = true
			if !strings.Contains(rt, "password") {
				t.Errorf("default_keys missing password: %q", rt)
			}
		}
	}
	if !foundDefaults {
		t.Fatal("expected default_keys in SupportedRules response")
	}
}

func TestPathRuleWithNestedArray(t *testing.T) {
	m := NewModule(Config{})
	ctx := context.Background()

	input := mustJSON(t, map[string]any{
		"users": []any{
			map[string]any{"name": "alice", "ssn": "123-45-6789"},
		},
	})

	resp, err := m.Redact(ctx, &dataredactionv1.RedactRequest{
		Data:  input,
		Rules: []string{"/\\d{3}-\\d{2}-\\d{4}/"},
	})
	if err != nil {
		t.Fatal(err)
	}

	var result map[string]any
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		t.Fatal(err)
	}

	users := result["users"].([]any)
	ssn := users[0].(map[string]any)["ssn"].(string)
	if ssn != redactedString {
		t.Errorf("expected ssn redacted in nested array, got %v", ssn)
	}
}

func TestMultipleRules(t *testing.T) {
	m := NewModule(Config{})
	ctx := context.Background()

	input := mustJSON(t, map[string]any{
		"credit_card": "4111-1111-1111-1111",
		"email":       "alice@example.com",
		"name":        "alice",
	})

	resp, err := m.Redact(ctx, &dataredactionv1.RedactRequest{
		Data:  input,
		Rules: []string{"field:credit_card", "/@/"},
	})
	if err != nil {
		t.Fatal(err)
	}

	var result map[string]any
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		t.Fatal(err)
	}

	if result["credit_card"] != redactedString {
		t.Errorf("expected credit_card redacted by field rule, got %v", result["credit_card"])
	}
	if result["email"] != redactedString {
		t.Errorf("expected email redacted by regex rule, got %v", result["email"])
	}
	if result["name"] != "alice" {
		t.Errorf("expected name=alice, got %v", result["name"])
	}
}

func TestLifecycle(t *testing.T) {
	t.Setenv("MUXCORE_INSECURE_DISABLE_TLS", "true")
	m := NewModule(Config{GRPCAddr: ":0"})
	ctx := context.Background()

	if err := m.Health(ctx); err == nil {
		t.Fatal("expected health error before Init")
	}
	if err := m.Init(ctx); err != nil {
		t.Fatal(err)
	}
	if err := m.Health(ctx); err == nil {
		t.Fatal("expected health error after Init before Start")
	}
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := m.Health(ctx); err != nil {
		t.Fatal("expected health to pass after start")
	}
	if err := m.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if err := m.Health(ctx); err == nil {
		t.Fatal("expected health error after stop")
	}
}

func TestHealth(t *testing.T) {
	m := NewModule(Config{})
	ctx := context.Background()
	if err := m.Health(ctx); err == nil {
		t.Fatal("expected health error before init")
	}
}

func TestGRPCRoundTrip(t *testing.T) {
	t.Setenv("MUXCORE_INSECURE_DISABLE_TLS", "true")
	m := NewModule(Config{GRPCAddr: "127.0.0.1:0"})
	ctx := context.Background()
	if err := m.Init(ctx); err != nil {
		t.Fatal(err)
	}
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Stop(ctx) })

	conn, err := grpc.NewClient(m.GRPCListenAddr(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	rpc := dataredactionv1.NewDataRedactionServiceClient(conn)
	raw, _ := json.Marshal(map[string]any{"password": "secret", "title": "Movie"})
	redactResp, err := rpc.Redact(ctx, &dataredactionv1.RedactRequest{Data: raw})
	if err != nil {
		t.Fatal(err)
	}
	var redacted map[string]any
	if err := json.Unmarshal(redactResp.GetData(), &redacted); err != nil {
		t.Fatal(err)
	}
	if redacted["password"] != redactedString {
		t.Fatalf("password=%v", redacted["password"])
	}

	rulesResp, err := rpc.SupportedRules(ctx, &dataredactionv1.SupportedRulesRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rulesResp.GetRuleTypes()) == 0 {
		t.Fatal("expected rule types")
	}
}

func TestSettingsExtraKeysLive(t *testing.T) {
	m := NewModule(Config{GRPCAddr: "127.0.0.1:0"})
	defs := m.Settings()
	if len(defs) != 2 || defs[0].Key != "extra_keys" || defs[1].Key != "extra_rules" {
		t.Fatalf("Settings=%+v", defs)
	}
	raw, _ := json.Marshal(map[string]any{"employee_badge": "B-99", "name": "alice"})
	resp, err := m.Redact(context.Background(), &dataredactionv1.RedactRequest{Data: raw})
	if err != nil {
		t.Fatal(err)
	}
	var before map[string]any
	_ = json.Unmarshal(resp.GetData(), &before)
	if before["employee_badge"] != "B-99" {
		t.Fatalf("expected unredacted before extra keys, got %#v", before["employee_badge"])
	}
	if err := m.UpdateSetting("extra_keys", "badge"); err != nil {
		t.Fatal(err)
	}
	resp, err = m.Redact(context.Background(), &dataredactionv1.RedactRequest{Data: raw})
	if err != nil {
		t.Fatal(err)
	}
	var after map[string]any
	_ = json.Unmarshal(resp.GetData(), &after)
	if after["employee_badge"] != redactedString {
		t.Fatalf("expected redacted badge field, got %#v", after["employee_badge"])
	}
	if after["name"] != "alice" {
		t.Fatalf("name should remain, got %#v", after["name"])
	}
}

func TestArrayRegexRedaction(t *testing.T) {
	m := NewModule(Config{})
	ctx := context.Background()

	input := mustJSON(t, map[string]any{
		"phones": []any{"555-123-4567", "alice"},
	})

	resp, err := m.Redact(ctx, &dataredactionv1.RedactRequest{
		Data:  input,
		Rules: []string{"/\\d{3}-\\d{3}-\\d{4}/"},
	})
	if err != nil {
		t.Fatal(err)
	}

	var result map[string]any
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		t.Fatal(err)
	}

	phones := result["phones"].([]any)
	if phones[0] != redactedString {
		t.Errorf("expected phone redacted in array, got %v", phones[0])
	}
	if phones[1] != "alice" {
		t.Errorf("expected alice preserved, got %v", phones[1])
	}
}

func TestNestedArrayRegexRedaction(t *testing.T) {
	m := NewModule(Config{})
	ctx := context.Background()

	input := mustJSON(t, map[string]any{
		"groups": []any{
			[]any{"555-123-4567"},
		},
	})

	resp, err := m.Redact(ctx, &dataredactionv1.RedactRequest{
		Data:  input,
		Rules: []string{"/\\d{3}-\\d{3}-\\d{4}/"},
	})
	if err != nil {
		t.Fatal(err)
	}

	var result map[string]any
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		t.Fatal(err)
	}

	inner := result["groups"].([]any)[0].([]any)
	if inner[0] != redactedString {
		t.Errorf("expected nested array phone redacted, got %v", inner[0])
	}
}

func TestAuthorPreservedAuthorizationRedacted(t *testing.T) {
	m := NewModule(Config{})
	ctx := context.Background()

	input := mustJSON(t, map[string]any{
		"author":        "Jane Austen",
		"authorization": "Bearer secret",
	})

	resp, err := m.Redact(ctx, &dataredactionv1.RedactRequest{Data: input})
	if err != nil {
		t.Fatal(err)
	}

	var result map[string]any
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		t.Fatal(err)
	}

	if result["author"] != "Jane Austen" {
		t.Errorf("author should be preserved, got %v", result["author"])
	}
	if result["authorization"] != redactedString {
		t.Errorf("authorization should be redacted, got %v", result["authorization"])
	}
}

func TestExtraRulesSetting(t *testing.T) {
	m := NewModule(Config{})
	ctx := context.Background()

	input := mustJSON(t, map[string]any{"note": "call 555-123-4567"})
	if err := m.UpdateSetting("extra_rules", "/\\d{3}-\\d{3}-\\d{4}/"); err != nil {
		t.Fatal(err)
	}

	resp, err := m.Redact(ctx, &dataredactionv1.RedactRequest{Data: input})
	if err != nil {
		t.Fatal(err)
	}

	var result map[string]any
	_ = json.Unmarshal(resp.Data, &result)
	if result["note"] != redactedString {
		t.Fatalf("note=%v", result["note"])
	}
}

func TestExtraRulesEnvBootstrap(t *testing.T) {
	t.Setenv("REDACTION_EXTRA_RULES", "path:payload.path")
	m := NewModule(Config{})
	ctx := context.Background()

	input := mustJSON(t, map[string]any{
		"payload": map[string]any{"path": "hidden"},
		"other":   "visible",
	})
	resp, err := m.Redact(ctx, &dataredactionv1.RedactRequest{Data: input})
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	_ = json.Unmarshal(resp.Data, &result)
	payload := result["payload"].(map[string]any)
	if payload["path"] != redactedString {
		t.Fatalf("path=%v", payload["path"])
	}
}

func TestExtraKeysEnvBootstrap(t *testing.T) {
	t.Setenv("REDACTION_EXTRA_KEYS", "badge")
	m := NewModule(Config{})
	ctx := context.Background()

	input := mustJSON(t, map[string]any{"employee_badge": "B-99"})
	resp, err := m.Redact(ctx, &dataredactionv1.RedactRequest{Data: input})
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	_ = json.Unmarshal(resp.Data, &result)
	if result["employee_badge"] != redactedString {
		t.Fatalf("employee_badge=%v", result["employee_badge"])
	}
}

func TestUnknownUpdateSetting(t *testing.T) {
	m := NewModule(Config{})
	if err := m.UpdateSetting("unknown_key", "x"); err == nil {
		t.Fatal("expected error for unknown setting")
	}
}

func TestBareFieldRule(t *testing.T) {
	m := NewModule(Config{})
	ctx := context.Background()

	input := mustJSON(t, map[string]any{
		"user_name": "alice",
		"name":      "bob",
		"nickname":  "carol",
	})
	resp, err := m.Redact(ctx, &dataredactionv1.RedactRequest{
		Data:  input,
		Rules: []string{"name"},
	})
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	_ = json.Unmarshal(resp.Data, &result)
	if result["name"] != redactedString {
		t.Fatalf("name=%v", result["name"])
	}
	if result["user_name"] != redactedString {
		t.Fatalf("user_name=%v", result["user_name"])
	}
	if result["nickname"] != "carol" {
		t.Fatalf("nickname=%v", result["nickname"])
	}
}

func TestOversizedPayload(t *testing.T) {
	m := NewModule(Config{})
	ctx := context.Background()
	big := make([]byte, defaultMaxPayloadBytes+1)
	for i := range big {
		big[i] = 'a'
	}
	_, err := m.Redact(ctx, &dataredactionv1.RedactRequest{Data: big})
	if err == nil {
		t.Fatal("expected error for oversized payload")
	}
}

func TestInvalidRegex(t *testing.T) {
	m := NewModule(Config{})
	ctx := context.Background()
	input := mustJSON(t, map[string]any{"x": "y"})
	_, err := m.Redact(ctx, &dataredactionv1.RedactRequest{
		Data:  input,
		Rules: []string{"/(/"},
	})
	if err == nil {
		t.Fatal("expected error for invalid regex")
	}
}

func TestSupportedRulesExtraKeysAndRules(t *testing.T) {
	t.Setenv("REDACTION_EXTRA_KEYS", "badge")
	t.Setenv("REDACTION_EXTRA_RULES", "path:foo.bar")
	m := NewModule(Config{})
	ctx := context.Background()

	resp, err := m.SupportedRules(ctx, &dataredactionv1.SupportedRulesRequest{})
	if err != nil {
		t.Fatal(err)
	}
	var extraKeys, extraRules bool
	for _, rt := range resp.RuleTypes {
		if strings.HasPrefix(rt, "extra_keys:") && strings.Contains(rt, "badge") {
			extraKeys = true
		}
		if strings.HasPrefix(rt, "extra_rules:") && strings.Contains(rt, "path:foo.bar") {
			extraRules = true
		}
	}
	if !extraKeys {
		t.Fatal("expected extra_keys in SupportedRules")
	}
	if !extraRules {
		t.Fatal("expected extra_rules in SupportedRules")
	}
}

func TestKeyMatchesToken(t *testing.T) {
	cases := []struct {
		key, token string
		want       bool
	}{
		{"password", "password", true},
		{"user_password", "password", true},
		{"author", "auth", false},
		{"authorization", "auth", false},
		{"authorization", "authorization", true},
		{"apiKey", "api", true},
		{"apiKey", "key", true},
	}
	for _, tc := range cases {
		got := keyMatchesToken(tc.key, tc.token)
		if got != tc.want {
			t.Errorf("keyMatchesToken(%q, %q) = %v, want %v", tc.key, tc.token, got, tc.want)
		}
	}
}

func TestInfoHTTPAddrEmpty(t *testing.T) {
	m := NewModule(Config{GRPCAddr: "127.0.0.1:9655"})
	if m.Info().HTTPAddr != "" {
		t.Fatalf("HTTPAddr=%q, want empty", m.Info().HTTPAddr)
	}
}

func TestDefaultGRPCAddrLoopback(t *testing.T) {
	m := NewModule(Config{})
	if m.grpcAddr != "127.0.0.1:9655" {
		t.Fatalf("grpcAddr=%q want 127.0.0.1:9655", m.grpcAddr)
	}
}
