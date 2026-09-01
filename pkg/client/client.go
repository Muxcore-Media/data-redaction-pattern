package client

import (
	"context"
	"encoding/json"
	"fmt"

	"google.golang.org/grpc"

	"github.com/Muxcore-Media/core/pkg/contracts"
	dataredactionv1 "github.com/Muxcore-Media/core/proto/gen/muxcore/dataredaction/v1"
)

// Client implements contracts.DataRedactionProvider over DataRedactionService gRPC.
type Client struct {
	rpc dataredactionv1.DataRedactionServiceClient
}

// New returns a DataRedactionProvider backed by conn.
func New(conn grpc.ClientConnInterface) *Client {
	return &Client{rpc: dataredactionv1.NewDataRedactionServiceClient(conn)}
}

var _ contracts.DataRedactionProvider = (*Client)(nil)

// Redact returns a copy of data with sensitive values replaced per rules.
func (c *Client) Redact(ctx context.Context, data map[string]any, rules []string) (map[string]any, error) {
	raw, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("marshal input: %w", err)
	}
	resp, err := c.rpc.Redact(ctx, &dataredactionv1.RedactRequest{
		Data:  raw,
		Rules: rules,
	})
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(resp.GetData(), &out); err != nil {
		return nil, fmt.Errorf("unmarshal redacted data: %w", err)
	}
	return out, nil
}
