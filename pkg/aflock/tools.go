package aflock

import "slices"

// SubagentSpawnTools lists the Claude Code tool names that spawn a subagent.
//
// A spawned subagent runs with native tools (Bash/Write/Edit) that route
// through Claude Code's harness rather than through aflock, so its actions are
// outside aflock's real-time enforcement plane (issue #100). "Task" and "Agent"
// are matched as distinct tool names: denying one does NOT deny the other.
var SubagentSpawnTools = []string{"Task", "Agent"}

// IsSubagentSpawn reports whether toolName is a subagent-spawning tool.
func IsSubagentSpawn(toolName string) bool {
	return slices.Contains(SubagentSpawnTools, toolName)
}
