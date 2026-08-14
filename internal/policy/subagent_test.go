package policy

import (
	"strings"
	"testing"

	"github.com/aflock-ai/aflock/pkg/aflock"
)

func TestCheckSubagentMisconfig(t *testing.T) {
	tests := []struct {
		name        string
		policy      *aflock.Policy
		wantWarn    bool
		wantContain []string // substrings expected in msg when warning
	}{
		{
			name: "task in allow with other denies, no sublayouts -> warn",
			policy: &aflock.Policy{
				Name:  "p",
				Tools: &aflock.ToolsPolicy{Allow: []string{"Read", "Task"}, Deny: []string{"Edit"}},
			},
			wantWarn:    true,
			wantContain: []string{"Task"},
		},
		{
			name: "agent in allow -> warn (Task alone in deny does not cover Agent)",
			policy: &aflock.Policy{
				Name:  "p",
				Tools: &aflock.ToolsPolicy{Allow: []string{"Read", "Agent"}, Deny: []string{"Task"}},
			},
			wantWarn:    true,
			wantContain: []string{"Agent"},
		},
		{
			name: "task allowed but sublayouts declared -> silent (constrained delegation)",
			policy: &aflock.Policy{
				Name:       "p",
				Tools:      &aflock.ToolsPolicy{Allow: []string{"Read", "Task"}},
				Sublayouts: []aflock.Sublayout{{Name: "general-purpose"}},
			},
			wantWarn: false,
		},
		{
			name: "deny both task and agent -> silent",
			policy: &aflock.Policy{
				Name:  "p",
				Tools: &aflock.ToolsPolicy{Allow: []string{"Read", "Task", "Agent"}, Deny: []string{"Task", "Agent"}},
			},
			wantWarn: false,
		},
		{
			name: "empty allow list, task not denied -> warn both",
			policy: &aflock.Policy{
				Name:  "p",
				Tools: &aflock.ToolsPolicy{Deny: []string{"Edit"}},
			},
			wantWarn:    true,
			wantContain: []string{"Task", "Agent"},
		},
		{
			name: "glob deny '*' covers both spawn tools -> silent",
			policy: &aflock.Policy{
				Name:  "p",
				Tools: &aflock.ToolsPolicy{Allow: []string{"Read", "Task", "Agent"}, Deny: []string{"*"}},
			},
			wantWarn: false,
		},
		{
			name:     "nil policy -> silent",
			policy:   nil,
			wantWarn: false,
		},
		{
			name:        "no tools section and no sublayouts -> warn (unconstrained)",
			policy:      &aflock.Policy{Name: "p"},
			wantWarn:    true,
			wantContain: []string{"Task", "Agent"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			warn, msg := CheckSubagentMisconfig(tt.policy)
			if warn != tt.wantWarn {
				t.Fatalf("CheckSubagentMisconfig() warn = %v, want %v (msg=%q)", warn, tt.wantWarn, msg)
			}
			if !warn {
				if msg != "" {
					t.Errorf("expected empty msg when not warning, got %q", msg)
				}
				return
			}
			for _, want := range tt.wantContain {
				if !strings.Contains(msg, want) {
					t.Errorf("msg %q does not contain %q", msg, want)
				}
			}
		})
	}
}
