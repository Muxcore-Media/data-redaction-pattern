package client_test

import (
	"context"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/Muxcore-Media/core/pkg/contracts"
	"github.com/Muxcore-Media/data-redaction-pattern/internal"
	"github.com/Muxcore-Media/data-redaction-pattern/pkg/client"
)

func startModule(t *testing.T) (*internal.Module, context.Context) {
	t.Helper()
	t.Setenv("MUXCORE_INSECURE_DISABLE_TLS", "true")
	m := internal.NewModule(internal.Config{GRPCAddr: "127.0.0.1:0"})
	ctx := context.Background()
	if err := m.Init(ctx); err != nil {
		t.Fatal(err)
	}
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Stop(ctx) })
	return m, ctx
}

func dialClient(t *testing.T, m *internal.Module) *client.Client {
	t.Helper()
	conn, err := grpc.NewClient(m.GRPCListenAddr(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return client.New(conn)
}

func TestClientRedact(t *testing.T) {
	m, ctx := startModule(t)
	cl := dialClient(t, m)

	out, err := cl.Redact(ctx, map[string]any{
		"password": "secret",
		"name":     "alice",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out["password"] != "***REDACTED***" {
		t.Fatalf("password=%v", out["password"])
	}
	if out["name"] != "alice" {
		t.Fatalf("name=%v", out["name"])
	}
}

var _ contracts.DataRedactionProvider = (*client.Client)(nil)
