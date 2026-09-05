package internal

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/Muxcore-Media/core/pkg/contracts"
	dataredactionv1 "github.com/Muxcore-Media/core/proto/gen/muxcore/dataredaction/v1"
	modulesdk "github.com/Muxcore-Media/core/sdk/go/module"
	"github.com/Muxcore-Media/data-redaction-pattern/internal/grpctls"
)

type Module struct {
	dataredactionv1.UnimplementedDataRedactionServiceServer

	mu          sync.RWMutex
	baseKeys    []string
	extraKeys   []string
	extraRules  []string
	defaultKeys []string

	id       string
	grpcAddr string
	grpcSrv  *grpc.Server
	lis      net.Listener
}

type Config struct {
	ID       string
	GRPCAddr string
}

func NewModule(cfg Config) *Module {
	if cfg.ID == "" {
		cfg.ID = "data-redaction-pattern"
	}
	if cfg.GRPCAddr == "" {
		cfg.GRPCAddr = "127.0.0.1:9655"
	}
	if v := os.Getenv("REDACTION_GRPC_ADDR"); v != "" {
		cfg.GRPCAddr = v
	}
	cfg.GRPCAddr = resolveGRPCAddr(cfg.GRPCAddr)

	mod := &Module{
		id:       cfg.ID,
		grpcAddr: cfg.GRPCAddr,
	}

	for _, key := range contracts.SensitiveLogFieldNames() {
		mod.baseKeys = append(mod.baseKeys, strings.ToLower(key))
	}
	mod.baseKeys = append(mod.baseKeys, extraDefaultKeys...)
	if v := os.Getenv("REDACTION_EXTRA_KEYS"); v != "" {
		mod.extraKeys = parseCSVLower(v)
	}
	if v := os.Getenv("REDACTION_EXTRA_RULES"); v != "" {
		mod.extraRules = parseCSVTrim(v)
	}
	mod.rebuildDefaultKeysLocked()

	return mod
}

func (m *Module) Info() contracts.ModuleInfo {
	return contracts.ModuleInfo{
		ID:           m.id,
		Name:         "Data Redaction Pattern",
		Version:      "0.1.5",
		Roles:        []string{"infrastructure"},
		Description:  "Field-name prefix, path, and regex based PII redaction provider",
		Author:       "MuxCore",
		Capabilities: []string{contracts.CapabilityDataRedaction, "settings"},
		Contracts: []contracts.ContractDeclaration{
			{
				Repo:      "github.com/Muxcore-Media/core/pkg/contracts",
				Interface: "DataRedactionProvider",
				Version:   "v0.5.0",
			},
		},
		MinCoreVersion: "0.5.0",
	}
}

func (m *Module) Init(ctx context.Context) error {
	lis, err := net.Listen("tcp", m.grpcAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", m.grpcAddr, err)
	}
	m.lis = lis
	slog.Info("data-redaction-pattern initialized", "addr", m.grpcAddr)
	return nil
}

func (m *Module) Start(ctx context.Context) error {
	var grpcOpts []grpc.ServerOption
	tlsCfg, err := grpctls.ServerConfig()
	if err != nil {
		return fmt.Errorf("gRPC TLS: %w", err)
	}
	if tlsCfg != nil {
		grpcOpts = append(grpcOpts, grpc.Creds(credentials.NewTLS(tlsCfg)))
		slog.Info("data-redaction-pattern gRPC TLS enabled", "addr", m.grpcAddr)
	} else {
		slog.Warn("data-redaction-pattern gRPC listening without TLS (dev only)",
			"addr", m.grpcAddr,
			"hint", "unset MUXCORE_INSECURE_DISABLE_TLS for production",
		)
	}
	srv := grpc.NewServer(grpcOpts...)
	lis := m.lis
	m.grpcSrv = srv
	dataredactionv1.RegisterDataRedactionServiceServer(srv, m)
	modulesdk.RegisterSettings(srv, m.id, m)

	go func() {
		slog.Info("data-redaction-pattern gRPC service started", "addr", m.grpcAddr)
		if err := srv.Serve(lis); err != nil {
			slog.Error("data-redaction-pattern gRPC serve error", "error", err)
		}
	}()
	return nil
}

func (m *Module) Stop(ctx context.Context) error {
	if m.grpcSrv != nil {
		m.grpcSrv.GracefulStop()
		m.grpcSrv = nil
	}
	if m.lis != nil {
		_ = m.lis.Close()
		m.lis = nil
	}
	slog.Info("data-redaction-pattern stopped")
	return nil
}

func (m *Module) Health(ctx context.Context) error {
	if m.lis == nil || m.grpcSrv == nil {
		return fmt.Errorf("gRPC server not serving")
	}
	return nil
}

// GRPCListenAddr returns the bound TCP address after Init.
func (m *Module) GRPCListenAddr() string {
	if m.lis != nil {
		return m.lis.Addr().String()
	}
	return ""
}

func (m *Module) Redact(ctx context.Context, req *dataredactionv1.RedactRequest) (*dataredactionv1.RedactResponse, error) {
	if len(req.GetData()) > defaultMaxPayloadBytes {
		return nil, fmt.Errorf("payload exceeds max size (%d > %d bytes)", len(req.GetData()), defaultMaxPayloadBytes)
	}

	var data map[string]any
	if err := json.Unmarshal(req.GetData(), &data); err != nil {
		return nil, fmt.Errorf("decode input data: %w", err)
	}

	m.mu.RLock()
	extraRules := append([]string(nil), m.extraRules...)
	keys := append([]string(nil), m.defaultKeys...)
	m.mu.RUnlock()

	allRules := append(append([]string(nil), builtinRegexRules...), extraRules...)
	allRules = append(allRules, req.GetRules()...)

	rules, err := compileRules(allRules)
	if err != nil {
		return nil, fmt.Errorf("compile rules: %w", err)
	}

	redacted := redactMap(data, keys, rules, ctx)

	out, err := json.Marshal(redacted)
	if err != nil {
		return nil, fmt.Errorf("encode redacted data: %w", err)
	}

	return &dataredactionv1.RedactResponse{Data: out}, nil
}

func (m *Module) SupportedRules(ctx context.Context, req *dataredactionv1.SupportedRulesRequest) (*dataredactionv1.SupportedRulesResponse, error) {
	m.mu.RLock()
	base := append([]string(nil), m.baseKeys...)
	extra := append([]string(nil), m.extraKeys...)
	rules := append([]string(nil), m.extraRules...)
	m.mu.RUnlock()

	ruleTypes := []string{
		"field:<name>     — redact keys whose segment matches <name> (case-insensitive)",
		"path:<a.b.c>     — redact nested path a → b → c",
		"/<regex>/        — redact values matching <regex>",
		"default_keys: " + strings.Join(base, ", "),
	}
	if len(extra) > 0 {
		ruleTypes = append(ruleTypes, "extra_keys: "+strings.Join(extra, ", "))
	}
	if len(rules) > 0 {
		ruleTypes = append(ruleTypes, "extra_rules: "+strings.Join(rules, ", "))
	}
	ruleTypes = append(ruleTypes, "builtin_regex: "+strings.Join(builtinRegexRules, ", "))

	return &dataredactionv1.SupportedRulesResponse{RuleTypes: ruleTypes}, nil
}

// resolveGRPCAddr prefers loopback when plaintext is explicitly enabled and the
// bind address would otherwise listen on all interfaces.
func resolveGRPCAddr(addr string) string {
	if !grpctls.InsecureAllowed() {
		return addr
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		if strings.HasPrefix(addr, ":") {
			return "127.0.0.1" + addr
		}
		return addr
	}
	if host == "" || host == "0.0.0.0" {
		return "127.0.0.1:" + port
	}
	return addr
}

var _ contracts.Module = (*Module)(nil)
