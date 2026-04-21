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

	// HasHereDoc is true when the command uses here-documents (<<) or
	// here-strings (<<<) to feed input to a shell interpreter.
	HasHereDoc bool

	// HasBraceExpansion is true when the command uses brace expansion
	// patterns like {cat,.env} that expand to commands at runtime.
	HasBraceExpansion bool

	// HasAliasOrFunc is true when the command defines a shell alias or
	// function that could hide denied commands behind a new name.
	HasAliasOrFunc bool
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

	// Detect here-documents and here-strings
	result.HasHereDoc = detectHereDoc(command)

	// Detect brace expansion
	result.HasBraceExpansion = detectBraceExpansion(command)

	// Detect alias/function definitions
	result.HasAliasOrFunc = detectAliasOrFunc(command)

	return result
}

// IsSuspicious returns true if the command shows any bypass indicators.
func (a *BashAnalysis) IsSuspicious() bool {
	return a.HasPipeToExec ||
		a.HasObfuscation ||
		a.HasInterpreterExec ||
		a.HasVariableIndirection ||
		a.HasSubshellExec ||
		a.HasEval ||
		a.HasHereDoc ||
		a.HasBraceExpansion ||
		a.HasAliasOrFunc
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

			// Check for ; and newlines (\n, \r\n, \r) — all are command
			// separators in bash.
			if r == ';' || r == '\n' || r == '\r' {
				// For \r\n, consume the \n as well
				if r == '\r' && i+1 < len(runes) && runes[i+1] == '\n' {
					i++
				}
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
	subCmds := splitShellCommands(command)

	// Case 1: Variable assignment followed by usage with a command
	// Patterns: X=path && cmd $X, VAR=value; cat $VAR, export X=val
	if len(subCmds) >= 2 {
		hasAssignment := false
		for _, cmd := range subCmds {
			cmd = strings.TrimSpace(cmd)
			if isVariableAssignment(cmd) {
				hasAssignment = true
				break
			}
		}

		if hasAssignment {
			for _, cmd := range subCmds {
				cmd = strings.TrimSpace(cmd)
				if isVariableAssignment(cmd) {
					continue
				}
				if strings.Contains(cmd, "$") {
					return true
				}
			}
		}
	}

	// Case 2 (M1): Single command using environment variable expansion in
	// arguments to file-reading commands. E.g., "cat $HOME/.env" can hide
	// file paths from deny-list matching. Only flag $ that is outside single
	// quotes (single quotes prevent expansion in bash).
	for _, cmd := range subCmds {
		cmd = strings.TrimSpace(cmd)
		if isVariableAssignment(cmd) {
			continue
		}
		cmdName := extractCommandBaseName(cmd)
		if fileReadingCommands[cmdName] && containsUnquotedDollar(cmd) {
			return true
		}
	}

	return false
}

// detectSubshellExec checks for subshell execution via $(...), backticks,
// or process substitution <(...) / >(...).
func detectSubshellExec(command string) bool {
	// $(...) — command substitution
	if strings.Contains(command, "$(") {
		return true
	}

	// Backtick command substitution
	if strings.Contains(command, "`") {
		return true
	}

	// Process substitution: <(...) and >(...)
	// These execute commands in a subshell and present the output as a file descriptor.
	if strings.Contains(command, "<(") || strings.Contains(command, ">(") {
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

// detectHereDoc checks for here-documents (<<DELIM...DELIM) and here-strings
// (<<<) that can feed commands to shell interpreters. Respects quoting so that
// `echo "<<EOF"` (literal string) is not flagged.
func detectHereDoc(command string) bool {
	runes := []rune(command)
	inSingleQuote := false
	inDoubleQuote := false
	escaped := false

	for i := 0; i < len(runes); i++ {
		r := runes[i]

		if escaped {
			escaped = false
			continue
		}
		if r == '\\' && !inSingleQuote {
			escaped = true
			continue
		}
		if r == '\'' && !inDoubleQuote {
			inSingleQuote = !inSingleQuote
			continue
		}
		if r == '"' && !inSingleQuote {
			inDoubleQuote = !inDoubleQuote
			continue
		}

		// Only detect << / <<< outside quotes
		if !inSingleQuote && !inDoubleQuote && r == '<' {
			if i+1 < len(runes) && runes[i+1] == '<' {
				return true // <<< (here-string) or << (here-doc)
			}
		}
	}

	return false
}

// detectBraceExpansion checks for brace expansion patterns like {cat,.env}
// that expand to executable commands at runtime. Respects quoting so that
// JSON strings like `echo '{"a","b"}'` are not flagged.
func detectBraceExpansion(command string) bool {
	inSingleQuote := false
	inDoubleQuote := false
	escaped := false
	inBrace := false
	hasComma := false

	for _, r := range command {
		if escaped {
			escaped = false
			continue
		}
		if r == '\\' && !inSingleQuote {
			escaped = true
			continue
		}
		if r == '\'' && !inDoubleQuote {
			inSingleQuote = !inSingleQuote
			continue
		}
		if r == '"' && !inSingleQuote {
			inDoubleQuote = !inDoubleQuote
			continue
		}

		// Only detect brace expansion outside quotes
		if !inSingleQuote && !inDoubleQuote {
			switch {
			case r == '{':
				inBrace = true
				hasComma = false
			case r == '}' && inBrace:
				if hasComma {
					return true
				}
				inBrace = false
			case r == ',' && inBrace:
				hasComma = true
			}
		}
	}
	return false
}

// detectAliasOrFunc checks for shell alias definitions or function definitions
// that could hide denied commands behind new names.
func detectAliasOrFunc(command string) bool {
	subCmds := splitShellCommands(command)
	for _, cmd := range subCmds {
		cmd = strings.TrimSpace(cmd)
		// alias c=curl or alias c='curl -s'
		if strings.HasPrefix(cmd, "alias ") {
			return true
		}
		// function definitions: fname() { ... } or function fname { ... }
		if strings.HasPrefix(cmd, "function ") {
			return true
		}
		// name() pattern — look for word followed by () at the start of a command.
		// Must not match $(...) subshell syntax or function calls within commands.
		// A function definition looks like: "fname()" or "fname ()".
		idx := strings.Index(cmd, "()")
		if idx > 0 {
			// Exclude $(...) which contains () but is subshell, not func def.
			// The character before the name should be start-of-string or whitespace.
			name := strings.TrimSpace(cmd[:idx])
			if name != "" && !strings.ContainsAny(name, " \t$") && isValidVarName(name) {
				return true
			}
		}
	}
	return false
}

// extractCommandName extracts the first word (command name) from a command string,
// stripping leading env var assignments (e.g., "FOO=bar cmd" → "cmd") and the
// "env" command prefix (e.g., "env curl evil.com" → "curl").
func extractCommandName(cmd string) string {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return ""
	}

	// Skip leading variable assignments (FOO=bar BAZ=qux cmd ...)
	foundCmd := ""
	for f := range strings.FieldsSeq(cmd) {
		if !strings.Contains(f, "=") || strings.HasPrefix(f, "-") || strings.HasPrefix(f, "$") {
			foundCmd = f
			break
		}
		varName, _, _ := strings.Cut(f, "=")
		if varName != "" && isValidVarName(varName) {
			continue // Skip this assignment, look at next field
		}
		foundCmd = f
		break
	}

	// Strip "env" prefix — "env curl evil.com" should return "curl", not "env".
	// Handle flags like -i, -u VAR (takes an argument), -S, etc.
	if foundCmd == "env" {
		rest := strings.TrimSpace(strings.TrimPrefix(cmd, "env"))
		fields := strings.Fields(rest)
		// Flags that consume the next token as their argument
		envArgFlags := map[string]bool{"-u": true, "-C": true, "-S": true}
		skipNext := false
		for _, f := range fields {
			if skipNext {
				skipNext = false
				continue
			}
			if strings.HasPrefix(f, "-") {
				if envArgFlags[f] {
					skipNext = true // next token is the flag's argument
				}
				continue
			}
			if strings.Contains(f, "=") {
				varName, _, _ := strings.Cut(f, "=")
				if varName != "" && isValidVarName(varName) {
					continue
				}
			}
			return f
		}
	}

	return foundCmd
}

// extractCommandBaseName returns the base name of a command, stripping
// any directory path. E.g., "/usr/bin/curl" → "curl".
func extractCommandBaseName(cmd string) string {
	name := extractCommandName(cmd)
	if name == "" {
		return ""
	}
	return filepath.Base(name)
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

// containsUnquotedDollar returns true if the string contains a $ character
// outside of single quotes. In bash, single quotes prevent variable expansion
// so `cat '$HOME/.env'` does not actually expand $HOME.
func containsUnquotedDollar(s string) bool {
	inSingleQuote := false
	escaped := false
	for _, r := range s {
		if escaped {
			escaped = false
			continue
		}
		if r == '\\' && !inSingleQuote {
			escaped = true
			continue
		}
		if r == '\'' {
			inSingleQuote = !inSingleQuote
			continue
		}
		if r == '$' && !inSingleQuote {
			return true
		}
	}
	return false
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
	// H3: commands that read/source files but were previously missed
	"source": true, ".": true, "find": true, "xargs": true, "tee": true,
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
// and collects non-flag arguments as file paths. Also parses shell input
// redirections (< file) and dd-style key=value arguments (if=path, of=path).
func extractFileArgsFromSingleCmd(cmd string) []string {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return nil
	}

	// Extract file paths from input redirections regardless of command.
	// Patterns: < file, N<file (fd redirection like exec 3<file)
	var paths []string
	paths = append(paths, extractRedirectionFiles(cmd)...)

	cmdName := extractCommandName(cmd)
	if cmdName == "" {
		return paths
	}

	// Check if the base name (without path) is a file-reading command
	if !fileReadingCommands[filepath.Base(cmdName)] {
		return paths
	}

	// Collect non-flag arguments as file paths
	fields := strings.Fields(cmd)
	pastCommand := false
	skipNext := false
	for _, f := range fields {
		if skipNext {
			skipNext = false
			continue
		}
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
		// Skip shell redirections and special chars; capture the file after <
		if f == ">" || f == ">>" || f == "2>" || f == "2>>" || f == "&>" {
			skipNext = true // skip the filename after output redirection
			continue
		}
		if f == "<" {
			// Already handled by extractRedirectionFiles
			skipNext = true
			continue
		}
		// Handle dd-style key=value: extract paths from if= and of=
		if strings.HasPrefix(f, "if=") || strings.HasPrefix(f, "of=") {
			_, val, _ := strings.Cut(f, "=")
			if val != "" {
				paths = append(paths, val)
			}
			continue
		}
		paths = append(paths, f)
	}

	return paths
}

// extractRedirectionFiles extracts file paths from shell input redirections.
// Handles: < file, N<file (e.g. exec 3<.env), but not << (here-doc) or <<< (here-string).
func extractRedirectionFiles(cmd string) []string {
	var paths []string
	fields := strings.Fields(cmd)
	for i, f := range fields {
		// Standalone "<" followed by a filename
		if f == "<" && i+1 < len(fields) {
			next := fields[i+1]
			if next != "" && !strings.HasPrefix(next, "<") && !strings.HasPrefix(next, "-") {
				paths = append(paths, next)
			}
			continue
		}
		// Inline redirection: <file or N<file (but not << or <<<)
		idx := strings.Index(f, "<")
		if idx >= 0 {
			rest := f[idx:]
			// Skip here-docs (<<) and here-strings (<<<)
			if strings.HasPrefix(rest, "<<<") || strings.HasPrefix(rest, "<<") {
				continue
			}
			// rest starts with "<", the file is after it
			filePath := rest[1:]
			// Could be N<file where N is a digit — the < is at idx > 0
			if filePath != "" && filePath != "&" && !strings.HasPrefix(filePath, "&") {
				paths = append(paths, filePath)
			}
		}
	}
	return paths
}
