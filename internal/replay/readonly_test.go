package replay_test

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/aflock-ai/aflock/internal/policy"
	"github.com/aflock-ai/aflock/pkg/aflock"
)

func TestReadOnlyImplicitAllow(t *testing.T) {
	pol := &aflock.Policy{
		Files: &aflock.FilesPolicy{
			Allow:    []string{"src/**"},
			Deny:     []string{"**/.env"},
			ReadOnly: []string{"package.json"},
		},
	}

	eval := policy.NewEvaluator(pol, "/tmp/project")

	tests := []struct {
		name     string
		tool     string
		filePath string
		wantDec  aflock.PermissionDecision
	}{
		{"Read readOnly file", "Read", "/tmp/project/package.json", aflock.DecisionAllow},
		{"Write readOnly file", "Write", "/tmp/project/package.json", aflock.DecisionDeny},
		{"Edit readOnly file", "Edit", "/tmp/project/package.json", aflock.DecisionDeny},
		{"Read allowed file", "Read", "/tmp/project/src/app.js", aflock.DecisionAllow},
		{"Read denied file", "Read", "/tmp/project/.env", aflock.DecisionDeny},
		{"Read unlisted file", "Read", "/tmp/project/random.txt", aflock.DecisionDeny},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input, _ := json.Marshal(map[string]string{"file_path": tt.filePath})
			dec, reason := eval.EvaluatePreToolUse(tt.tool, input)
			if dec != tt.wantDec {
				t.Errorf("got %s (%s), want %s", dec, reason, tt.wantDec)
			}
			fmt.Printf("  %-25s %-6s → %s\n", tt.name, tt.tool, dec)
		})
	}
}
