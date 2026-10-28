package cli

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/loganprice/treeguard/internal/registry"
)

func TestCLIPackCmdTableDriven(t *testing.T) {
	ctx := context.Background()
	tmpCache := t.TempDir()
	registry.DefaultClient = registry.NewClient(tmpCache)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("package rules.test\ndeny[f] { f := \"ok\" }\n"))
	}))
	defer server.Close()

	registry.DefaultClient.Aliases["test-pack"] = server.URL + "/rule.rego"

	tests := []struct {
		name       string
		args       []string
		wantSubstr string
		wantErr    bool
	}{
		{
			name:       "pack list (initially empty)",
			args:       []string{"list"},
			wantSubstr: "Default Registry Aliases",
			wantErr:    false,
		},
		{
			name:       "pack pull mock url",
			args:       []string{"pull", server.URL + "/rule.rego"},
			wantSubstr: "Successfully pulled rule pack",
			wantErr:    false,
		},
		{
			name:       "pack list after pull",
			args:       []string{"list"},
			wantSubstr: "Cached Rule Packs",
			wantErr:    false,
		},
		{
			name:       "pack update all",
			args:       []string{"update"},
			wantSubstr: "Rule pack update complete",
			wantErr:    false,
		},
		{
			name:       "pack clean",
			args:       []string{"clean"},
			wantSubstr: "Cleared rule pack cache",
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := newPackCmd(ctx)
			buf := new(bytes.Buffer)
			cmd.SetOut(buf)
			cmd.SetErr(buf)
			cmd.SetArgs(tt.args)

			err := cmd.Execute()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Execute() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantSubstr != "" {
				if !strings.Contains(buf.String(), tt.wantSubstr) {
					t.Errorf("output missing %q\nGot:\n%s", tt.wantSubstr, buf.String())
				}
			}
		})
	}
}
