package main_test

import (
	"context"
	"testing"

	"github.com/loganprice/treeguard/internal/cli"
)

func TestMainSmoke(t *testing.T) {
	ctx := context.Background()
	cmd := cli.NewRootCmd(ctx)
	if cmd == nil {
		t.Fatal("NewRootCmd() returned nil")
	}
	if cmd.Use != "treeguard" {
		t.Errorf("cmd.Use = %s, want treeguard", cmd.Use)
	}
}
