// Package policy provides policy evaluation for hook decisions.
package policy

import (
	"path/filepath"
	"slices"
	"strings"
	"unicode"
)

// BashAnalysis holds the result of analyzing a bash command string.
type BashAnalysis struct {
	// SubCommands are the individual commands extracted by splitting on shell
	// metacharacters (;, &&, ||). Each is trimmed of whitespace.
	SubCommands []string

	// PipelineSegments are the individual commands in a pipeline (split on |).
	// For "echo foo | grep bar", this yields ["echo foo", "grep bar"].
	PipelineSegments []string

	// HasPipeToExec is true when the command pipes output into an execution
	// sink like bash, sh, zsh, eval, or source.
	HasPipeToExec bool

	// HasObfuscation is true when the command uses encoding/decoding patterns
	// that suggest obfuscation: base64, rev piped to exec, hex decoding, etc.
	HasObfuscation bool

	// HasInterpreterExec is true when the command invokes an interpreter with
	// inline code (python -c, ruby -e, perl -e, node -e, etc.).
	HasInterpreterExec bool

	// HasVariableIndirection is true when the command uses shell variable
	// expansion that could hide file paths or command names.
	HasVariableIndirection bool

	// HasSubshellExec is true when the command contains subshell execution
	// via $(...) or backticks.
	HasSubshellExec bool

	// HasEval is true when the command uses eval.
	HasEval bool
}

// BashAnalyzer performs static analysis on bash command strings to detect
// bypass attempts such as command chaining, obfuscation, and indirection.
type BashAnalyzer struct{}

// NewBashAnalyzer creates a new BashAnalyzer.
func NewBashAnalyzer() *BashAnalyzer {
	return &BashAnalyzer{}
}

// Analyze performs static analysis on a bash command string and returns
// structured information about its components and potential bypass indicators.
func (a *BashAnalyzer) Analyze(command string) *BashAnalysis {
	result := &BashAnalysis{}

	// Extract sub-commands by splitting on ;, &&, ||
	result.SubCommands = splitShellCommands(command)

	// Extract pipeline segments by splitting on |
	result.PipelineSegments = splitPipeline(command)

	// Detect pipe-to-exec patterns
	result.HasPipeToExec = detectPipeToExec(command)

	// Detect obfuscation patterns
	result.HasObfuscation = detectObfuscation(command)

	// Detect interpreter inline execution
	result.HasInterpreterExec = detectInterpreterExec(command)

	// Detect variable indirection
	result.HasVariableIndirection = detectVariableIndirection(command)

	// Detect subshell execution
	result.HasSubshellExec = detectSubshellExec(command)

	// Detect eval usage
	result.HasEval = detectEval(command)

	return result
}

// IsSuspicious returns true if the command shows any bypass indicators.
func (a *BashAnalysis) IsSuspicious() bool {
	return a.HasPipeToExec ||
		a.HasObfuscation ||
		a.HasInterpreterExec ||
		a.HasVariableIndirection ||
		a.HasSubshellExec ||
		a.HasEval
}

// splitShellCommands splits a command string on shell command separators
// (; && ||) to extract individual sub-commands. It respects quoting so
// that separators inside quotes are not treated as delimiters.
func splitShellCommands(command string) []string {
	var commands []string
	var current strings.Builder
	inSingleQuote := false
	inDoubleQuote := false
	escaped := false

	runes := []rune(command)
	for i := 0; i < len(runes); i++ {
		r := runes[i]

		if escaped {
			current.WriteRune(r)
			escaped = false
			continue
		}

		if r == '\\' && !inSingleQuote {
			escaped = true
			current.WriteRune(r)
			continue
		}

		if r == '\'' && !inDoubleQuote {
			inSingleQuote = !inSingleQuote
			current.WriteRune(r)
			continue
		}

		if r == '"' && !inSingleQuote {
			inDoubleQuote = !inDoubleQuote
			current.WriteRune(r)
			continue
		}

		// Outside quotes, check for separators
		if !inSingleQuote && !inDoubleQuote {
			// Check for && or ||
			if i+1 < len(runes) {
				next := runes[i+1]
				if (r == '&' && next == '&') || (r == '|' && next == '|') {
					cmd := strings.TrimSpace(current.String())
					if cmd != "" {
						commands = append(commands, cmd)
					}
					current.Reset()
					i++ // skip second character of && or ||
					continue
				}
			}

			// Check for ;
			if r == ';' {
				cmd := strings.TrimSpace(current.String())
				if cmd != "" {
					commands = append(commands, cmd)
				}
				current.Reset()
				continue
			}
		}

		current.WriteRune(r)
	}

	// Flush remaining
	if cmd := strings.TrimSpace(current.String()); cmd != "" {
		commands = append(commands, cmd)
	}

	return commands
}

// splitPipeline splits a command on single pipe (|) characters, ignoring ||.
// Respects quoting.
func splitPipeline(command string) []string {
	var segments []string
	var current strings.Builder
	inSingleQuote := false
	inDoubleQuote := false
	escaped := false

	runes := []rune(command)
	for i := 0; i < len(runes); i++ {
		r := runes[i]

		if escaped {
			current.WriteRune(r)
			escaped = false
			continue
		}

		if r == '\\' && !inSingleQuote {
			escaped = true
			current.WriteRune(r)
			continue
		}

		if r == '\'' && !inDoubleQuote {
			inSingleQuote = !inSingleQuote
			current.WriteRune(r)
			continue
		}

		if r == '"' && !inSingleQuote {
			inDoubleQuote = !inDoubleQuote
			current.WriteRune(r)
			continue
		}

		if !inSingleQuote && !inDoubleQuote && r == '|' {
			// Check it's not ||
			if i+1 < len(runes) && runes[i+1] == '|' {
				// || — write both and skip
				current.WriteRune(r)
				current.WriteRune(runes[i+1])
				i++
				continue
			}
			seg := strings.TrimSpace(current.String())
			if seg != "" {
				segments = append(segments, seg)
			}
			current.Reset()
			continue
		}

		current.WriteRune(r)
	}

	if seg := strings.TrimSpace(current.String()); seg != "" {
		segments = append(segments, seg)
	}

	return segments
}

// detectPipeToExec checks if the command pipes output into an execution sink.
// Patterns: ... | bash, ... | sh, ... | zsh, ... | /bin/sh, ... | source, ... | xargs sh -c
func detectPipeToExec(command string) bool {
	segments := splitPipeline(command)
	if len(segments) < 2 {
		return false
	}

	// Check if any non-first segment is an execution sink
	execSinks := []string{
		"bash", "sh", "zsh", "ksh", "csh", "tcsh", "fish", "dash",
		"/bin/bash", "/bin/sh", "/bin/zsh", "/usr/bin/bash", "/usr/bin/sh",
		"/usr/bin/env bash", "/usr/bin/env sh",
		"source /dev/stdin",
	}

	for _, seg := range segments[1:] {
		seg = strings.TrimSpace(seg)
		cmdName := extractCommandName(seg)

		for _, sink := range execSinks {
			if cmdName == sink || seg == sink {
				return true
			}
		}

		// xargs with shell execution
		lower := strings.ToLower(seg)
		if strings.HasPrefix(lower, "xargs") && containsAnyWord(lower, []string{"sh", "bash", "zsh"}) {
			return true
		}
	}

	return false
}

// detectObfuscation checks for command obfuscation patterns.
func detectObfuscation(command string) bool {
	lower := strings.ToLower(command)

	// Base64 decode patterns: base64 -d, base64 --decode, base64 -D (macOS)
	if containsAny(lower, []string{"base64 -d", "base64 --decode", "base64 -D"}) {
		return true
	}

	// xxd reverse (hex decode): xxd -r
	if strings.Contains(lower, "xxd -r") {
		return true
	}

	// rev piped to execution (string reversal): ... | rev | bash
	segments := splitPipeline(command)
	for i := 0; i < len(segments)-1; i++ {
		if extractCommandName(strings.TrimSpace(segments[i])) == "rev" {
			// rev followed by anything is suspicious, but especially exec sinks
			return true
		}
	}
	// Also check: echo ... | rev (rev at end could still be decoded later)
	if len(segments) >= 2 && extractCommandName(strings.TrimSpace(segments[len(segments)-1])) == "rev" {
		// Only if there's also a pipe to exec later or this feeds into bash
		// For simplicity, rev in a pipeline is always suspicious
		return true
	}

	// printf with octal/hex escapes piped somewhere: printf '\x63\x61\x74'
	if strings.Contains(lower, "printf") && (strings.Contains(command, "\\x") || strings.Contains(command, "\\0")) {
		if len(segments) > 1 {
			return true
		}
	}

	// Python/Perl chr() encoding: chr(99)+chr(97)+chr(116) = "cat"
	if strings.Contains(lower, "chr(") && strings.Count(lower, "chr(") >= 3 {
		return true
	}

	// Hex string decode patterns: echo -e with \x
	if strings.Contains(lower, "echo -e") && strings.Contains(command, "\\x") {
		return true
	}

	return false
}

// detectInterpreterExec checks if the command invokes a language interpreter
// with inline code that could embed denied commands.
func detectInterpreterExec(command string) bool {
	// Check each sub-command (after splitting on ; && ||)
	subCmds := splitShellCommands(command)

	interpreterFlags := map[string][]string{
		"python":  {"-c"},
		"python2": {"-c"},
		"python3": {"-c"},
		"ruby":    {"-e"},
		"perl":    {"-e", "-E"},
		"node":    {"-e", "--eval"},
		"php":     {"-r"},
		"lua":     {"-e"},
		"awk":     {""}, // awk itself can execute arbitrary code
		"gawk":    {""},
	}

	for _, cmd := range subCmds {
		cmd = strings.TrimSpace(cmd)
		cmdName := extractCommandName(cmd)

		if flags, ok := interpreterFlags[cmdName]; ok {
			// awk/gawk are always considered interpreter exec
			if cmdName == "awk" || cmdName == "gawk" {
				// Only flag if it appears to run a complex command (contains system/popen/getline)
				if containsAny(strings.ToLower(cmd), []string{"system(", "popen(", "getline", "| "}) {
					return true
				}
				continue
			}

			for _, flag := range flags {
				if strings.Contains(cmd, " "+flag+" ") || strings.HasSuffix(cmd, " "+flag) {
					return true
				}
			}
		}
	}

	return false
}

// detectVariableIndirection checks for shell variable usage that could hide
// file paths or command names from pattern matching.
func detectVariableIndirection(command string) bool {
	// Look for variable assignment followed by usage with a command
	// Patterns: X=path && cmd $X, VAR=value; cat $VAR, export X=val
	subCmds := splitShellCommands(command)
	if len(subCmds) < 2 {
		return false
	}

	// Check if any sub-command is a variable assignment
	hasAssignment := false
	for _, cmd := range subCmds {
		cmd = strings.TrimSpace(cmd)
		// Variable assignment: VAR=value or export VAR=value
		if isVariableAssignment(cmd) {
			hasAssignment = true
			break
		}
	}

	if !hasAssignment {
		return false
	}

	// Check if any subsequent sub-command uses variable expansion
	for _, cmd := range subCmds {
		cmd = strings.TrimSpace(cmd)
		if isVariableAssignment(cmd) {
			continue
		}
		if strings.Contains(cmd, "$") {
			return true
		}
	}

	return false
}

// detectSubshellExec checks for subshell execution via $(...) or backticks.
func detectSubshellExec(command string) bool {
	// $(...) — command substitution
	if strings.Contains(command, "$(") {
		return true
	}

	// Backtick command substitution
	if strings.Contains(command, "`") {
		return true
	}

	return false
}

// detectEval checks for eval usage.
func detectEval(command string) bool {
	subCmds := splitShellCommands(command)
	for _, cmd := range subCmds {
		cmdName := extractCommandName(strings.TrimSpace(cmd))
		if cmdName == "eval" {
			return true
		}
	}

	// Also check pipeline segments — eval can appear after pipes too
	segments := splitPipeline(command)
	for _, seg := range segments {
		cmdName := extractCommandName(strings.TrimSpace(seg))
		if cmdName == "eval" {
			return true
		}
	}

	return false
}

// extractCommandName extracts the first word (command name) from a command string,
// stripping leading env var assignments (e.g., "FOO=bar cmd" → "cmd").
func extractCommandName(cmd string) string {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return ""
	}

	// Skip leading variable assignments (FOO=bar BAZ=qux cmd ...)
	for f := range strings.FieldsSeq(cmd) {
		if !strings.Contains(f, "=") || strings.HasPrefix(f, "-") || strings.HasPrefix(f, "$") {
			return f
		}
		varName, _, _ := strings.Cut(f, "=")
		if varName != "" && isValidVarName(varName) {
			continue // Skip this assignment, look at next field
		}
		return f
	}

	return ""
}

// isValidVarName checks if s is a valid shell variable name.
func isValidVarName(s string) bool {
	for i, r := range s {
		if i == 0 && !unicode.IsLetter(r) && r != '_' {
			return false
		}
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_' {
			return false
		}
	}
	return true
}

// isVariableAssignment checks if a command string is a shell variable assignment.
func isVariableAssignment(cmd string) bool {
	cmd = strings.TrimSpace(cmd)

	// Handle "export VAR=value"
	if after, ok := strings.CutPrefix(cmd, "export "); ok {
		cmd = strings.TrimSpace(after)
	}

	// Check for VAR=value pattern
	varName, _, ok := strings.Cut(cmd, "=")
	if !ok {
		return false
	}

	// Variable name must be valid: starts with letter/underscore, contains only alnum/underscore
	if varName == "" {
		return false
	}
	for i, r := range varName {
		if i == 0 && !unicode.IsLetter(r) && r != '_' {
			return false
		}
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_' {
			return false
		}
	}

	return true
}

// containsAny checks if s contains any of the substrings.
func containsAny(s string, subs []string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// containsAnyWord checks if s contains any of the words as whole words.
func containsAnyWord(s string, words []string) bool {
	for f := range strings.FieldsSeq(s) {
		if slices.Contains(words, f) {
			return true
		}
	}
	return false
}

// fileReadingCommands is the set of common commands that read file contents.
// Used to extract file arguments from Bash commands for deny-list checking.
var fileReadingCommands = map[string]bool{
	"cat": true, "head": true, "tail": true, "less": true, "more": true,
	"xxd": true, "strings": true, "od": true, "hexdump": true, "file": true,
	"wc": true, "stat": true, "base64": true, "tac": true, "nl": true,
	"sort": true, "uniq": true, "cut": true,
	"grep": true, "sed": true, "awk": true, "gawk": true,
	"cp": true, "mv": true, "jq": true, "diff": true,
	"dd": true, "tar": true, "zip": true, "curl": true,
}

// ExtractFileArgs extracts file path arguments from a bash command string.
// It splits the command into sub-commands and pipeline segments, then parses
// each for file-reading commands and collects their file arguments.
func (a *BashAnalyzer) ExtractFileArgs(command string) []string {
	seen := make(map[string]bool)
	var result []string

	addPath := func(p string) {
		if p != "" && !seen[p] {
			seen[p] = true
			result = append(result, p)
		}
	}

	// Process sub-commands (split on ;, &&, ||)
	for _, subCmd := range splitShellCommands(command) {
		// Also process pipeline segments within each sub-command
		for _, seg := range splitPipeline(subCmd) {
			for _, p := range extractFileArgsFromSingleCmd(seg) {
				addPath(p)
			}
		}
	}

	return result
}

// extractFileArgsFromSingleCmd extracts file arguments from a single command
// (no pipes, no chaining). It checks if the command is a file-reading command
// and collects non-flag arguments as file paths.
func extractFileArgsFromSingleCmd(cmd string) []string {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return nil
	}

	cmdName := extractCommandName(cmd)
	if cmdName == "" {
		return nil
	}

	// Check if the base name (without path) is a file-reading command
	if !fileReadingCommands[filepath.Base(cmdName)] {
		return nil
	}

	// Collect non-flag arguments as file paths
	var paths []string
	fields := strings.Fields(cmd)
	pastCommand := false
	for _, f := range fields {
		// Skip variable assignments and command name
		if !pastCommand {
			if strings.Contains(f, "=") && !strings.HasPrefix(f, "-") && !strings.HasPrefix(f, "$") {
				continue // skip env var assignment
			}
			pastCommand = true
			continue // skip the command name itself
		}
		// Skip flags (e.g., -n, --lines, -20)
		if strings.HasPrefix(f, "-") {
			continue
		}
		// Skip shell redirections and special chars
		if f == ">" || f == ">>" || f == "<" || f == "2>" || f == "2>>" || f == "&>" {
			continue
		}
		paths = append(paths, f)
	}

	return paths
}
