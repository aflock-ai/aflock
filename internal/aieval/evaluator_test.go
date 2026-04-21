package aieval

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// ---- parseEvalResponse tests ----

func TestParseEvalResponse_JSONPass(t *testing.T) {
	status, reason := parseEvalResponse(`{"status": "PASS", "reason": "Code looks good"}`)
	if status != "PASS" {
		t.Errorf("status = %q, want PASS", status)
	}
	if reason != "Code looks good" {
		t.Errorf("reason = %q, want 'Code looks good'", reason)
	}
}

func TestParseEvalResponse_JSONFail(t *testing.T) {
	status, reason := parseEvalResponse(`{"status": "FAIL", "reason": "Missing error handling"}`)
	if status != "FAIL" {
		t.Errorf("status = %q, want FAIL", status)
	}
	if reason != "Missing error handling" {
		t.Errorf("reason = %q", reason)
	}
}

func TestParseEvalResponse_JSONWithCodeFence(t *testing.T) {
	input := "```json\n{\"status\": \"PASS\", \"reason\": \"All tests pass\"}\n```"
	status, _ := parseEvalResponse(input)
	if status != "PASS" {
		t.Errorf("status = %q, want PASS", status)
	}
}

// Issue #61 / M8: parseEvalResponse no longer falls back to substring scanning
// — anything that isn't strict JSON returns FAIL. The three tests below were
// originally written for the gameable substring path. They now assert the
// fail-closed behavior.

func TestParseEvalResponse_PlainTextPassFailsClosed(t *testing.T) {
	status, _ := parseEvalResponse("The code is production-ready. PASS.")
	if status != "FAIL" {
		t.Errorf("status = %q, want FAIL (substring scan removed in M8)", status)
	}
}

func TestParseEvalResponse_PlainTextFailFailsClosed(t *testing.T) {
	status, _ := parseEvalResponse("The code has critical bugs. FAIL.")
	if status != "FAIL" {
		t.Errorf("status = %q, want FAIL (no substring scan)", status)
	}
}

func TestParseEvalResponse_InconclusiveFailsClosed(t *testing.T) {
	status, _ := parseEvalResponse("I'm not sure about this code.")
	if status != "FAIL" {
		t.Errorf("status = %q, want FAIL (no JSON contract → fail closed)", status)
	}
}

func TestParseEvalResponse_CaseInsensitive(t *testing.T) {
	status, _ := parseEvalResponse(`{"status": "pass", "reason": "ok"}`)
	if status != "PASS" {
		t.Errorf("status = %q, want PASS", status)
	}
}

// ---- Backend detection tests ----

func TestGetBackend(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"", "anthropic"},
		{"anthropic", "anthropic"},
		{"Anthropic", "anthropic"},
		{"ollama", "ollama"},
		{"Ollama", "ollama"},
		{"OLLAMA", "ollama"},
		{"unknown", "anthropic"},
	}
	for _, tt := range tests {
		got := getBackend(tt.input)
		if got != tt.want {
			t.Errorf("getBackend(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestGetModelForBackend(t *testing.T) {
	if m := getModelForBackend("", "anthropic"); m != defaultAnthropicModel {
		t.Errorf("got %q, want %q", m, defaultAnthropicModel)
	}
	if m := getModelForBackend("", "ollama"); m != defaultOllamaModel {
		t.Errorf("got %q, want %q", m, defaultOllamaModel)
	}
	if m := getModelForBackend("custom-model", "ollama"); m != "custom-model" {
		t.Errorf("got %q, want custom-model", m)
	}
}

// ---- Anthropic mock tests ----

func mockAnthropicServer(t *testing.T, status, reason string) *httptest.Server {
	t.Helper()
	// httptest binds to 127.0.0.1; the SSRF guard added in issue #61 / M9
	// blocks loopback at dial time. Opt in for tests, the same escape hatch
	// users set when running a self-hosted Anthropic-compatible proxy.
	t.Setenv("AFLOCK_AIEVAL_ALLOW_INTERNAL", "1")
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-api-key") == "" {
			http.Error(w, "missing api key", http.StatusUnauthorized)
			return
		}
		responseText := `{"status": "` + status + `", "reason": "` + reason + `"}`
		resp := map[string]any{
			"content":     []map[string]any{{"type": "text", "text": responseText}},
			"usage":       map[string]any{"input_tokens": 150, "output_tokens": 30},
			"stop_reason": "end_turn",
		}
		json.NewEncoder(w).Encode(resp)
	}))
}

func TestEvaluate_EmptyPolicies(t *testing.T) {
	results, err := Evaluate(context.Background(), nil, []byte(`{}`))
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("Expected 0 results, got %d", len(results))
	}
}

func TestEvaluate_NoAPIKey_Anthropic(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "")
	policies := []Policy{{Name: "test", Prompt: "check it", Backend: "anthropic"}}
	_, err := Evaluate(context.Background(), policies, []byte(`{}`))
	if err == nil {
		t.Fatal("Expected error for missing API key")
	}
}

func TestEvaluate_Anthropic_Pass(t *testing.T) {
	server := mockAnthropicServer(t, "PASS", "Code is production-ready")
	defer server.Close()

	origURL := anthropicURL
	defer func() { anthropicURL = origURL }()
	anthropicURL = server.URL

	t.Setenv("ANTHROPIC_API_KEY", "test-key-123")

	policies := []Policy{{Name: "quality", Prompt: "PASS if ok", Backend: "anthropic"}}
	results, err := Evaluate(context.Background(), policies, []byte(`{"actions": []}`))
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !results[0].Passed {
		t.Errorf("Expected pass, got: %+v", results[0])
	}
	if results[0].Backend != "anthropic" {
		t.Errorf("Backend = %q, want anthropic", results[0].Backend)
	}
	if results[0].TokensIn == 0 {
		t.Error("Expected non-zero token count")
	}
}

func TestEvaluate_Anthropic_Fail(t *testing.T) {
	server := mockAnthropicServer(t, "FAIL", "Missing error handling")
	defer server.Close()

	origURL := anthropicURL
	defer func() { anthropicURL = origURL }()
	anthropicURL = server.URL

	t.Setenv("ANTHROPIC_API_KEY", "test-key-123")

	policies := []Policy{{Name: "errors", Prompt: "check errors", Backend: "anthropic"}}
	results, err := Evaluate(context.Background(), policies, []byte(`{}`))
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if results[0].Passed {
		t.Error("Expected fail")
	}
	if results[0].Status != "FAIL" {
		t.Errorf("Status = %q, want FAIL", results[0].Status)
	}
}

// ---- Ollama mock tests ----

func mockOllamaServer(t *testing.T, status, reason string) *httptest.Server {
	t.Helper()
	// httptest binds to 127.0.0.1; the SSRF guard added in issue #61 / M9
	// blocks loopback by default. Opt in for tests, which is the same escape
	// hatch documented for local Ollama deployments.
	t.Setenv("AFLOCK_AIEVAL_ALLOW_INTERNAL", "1")
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/generate" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		responseJSON := fmt.Sprintf(`{"status": "%s", "reason": "%s"}`, status, reason)
		resp := map[string]any{"response": responseJSON}
		json.NewEncoder(w).Encode(resp)
	}))
}

func TestEvaluate_Ollama_Pass(t *testing.T) {
	server := mockOllamaServer(t, "PASS", "All checks passed")
	defer server.Close()

	policies := []Policy{{
		Name:     "quality",
		Prompt:   "PASS if ok",
		Backend:  "ollama",
		Endpoint: server.URL,
	}}
	results, err := Evaluate(context.Background(), policies, []byte(`{"actions": []}`))
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(results))
	}
	if !results[0].Passed {
		t.Errorf("Expected pass, got: %+v", results[0])
	}
	if results[0].Backend != "ollama" {
		t.Errorf("Backend = %q, want ollama", results[0].Backend)
	}
	if results[0].Model != defaultOllamaModel {
		t.Errorf("Model = %q, want %q", results[0].Model, defaultOllamaModel)
	}
}

func TestEvaluate_Ollama_Fail(t *testing.T) {
	server := mockOllamaServer(t, "FAIL", "Security issue found")
	defer server.Close()

	policies := []Policy{{
		Name:     "security",
		Prompt:   "check security",
		Backend:  "ollama",
		Endpoint: server.URL,
	}}
	results, err := Evaluate(context.Background(), policies, []byte(`{}`))
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if results[0].Passed {
		t.Error("Expected fail")
	}
	if results[0].Status != "FAIL" {
		t.Errorf("Status = %q, want FAIL", results[0].Status)
	}
}

func TestEvaluate_Ollama_NoAPIKeyNeeded(t *testing.T) {
	server := mockOllamaServer(t, "PASS", "ok")
	defer server.Close()

	// Explicitly unset API key — Ollama should work without it
	t.Setenv("ANTHROPIC_API_KEY", "")

	policies := []Policy{{Name: "test", Prompt: "check", Backend: "ollama", Endpoint: server.URL}}
	results, err := Evaluate(context.Background(), policies, []byte(`{}`))
	if err != nil {
		t.Fatalf("Ollama should not require API key: %v", err)
	}
	if !results[0].Passed {
		t.Error("Expected pass")
	}
}

func TestEvaluate_Ollama_CustomModel(t *testing.T) {
	server := mockOllamaServer(t, "PASS", "ok")
	defer server.Close()

	policies := []Policy{{Name: "test", Prompt: "check", Backend: "ollama", Model: "mistral:7b", Endpoint: server.URL}}
	results, err := Evaluate(context.Background(), policies, []byte(`{}`))
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if results[0].Model != "mistral:7b" {
		t.Errorf("Model = %q, want mistral:7b", results[0].Model)
	}
}

func TestEvaluate_Ollama_ServerDown(t *testing.T) {
	t.Setenv("AFLOCK_AIEVAL_ALLOW_INTERNAL", "1")
	policies := []Policy{{
		Name:     "test",
		Prompt:   "check",
		Backend:  "ollama",
		Endpoint: "http://localhost:1", // nothing listening
	}}
	results, err := Evaluate(context.Background(), policies, []byte(`{}`))
	if err != nil {
		t.Fatalf("Should not return fatal error: %v", err)
	}
	if results[0].Status != "ERROR" {
		t.Errorf("Status = %q, want ERROR", results[0].Status)
	}
}

func TestEvaluate_Ollama_InvalidEndpoint(t *testing.T) {
	policies := []Policy{{Name: "test", Prompt: "check", Backend: "ollama", Endpoint: "ftp://evil.com"}}
	results, err := Evaluate(context.Background(), policies, []byte(`{}`))
	if err != nil {
		t.Fatalf("Should not return fatal error: %v", err)
	}
	if results[0].Status != "ERROR" {
		t.Errorf("Status = %q, want ERROR", results[0].Status)
	}
}

// ---- Mixed backend tests ----

func TestEvaluate_MixedBackends(t *testing.T) {
	anthropicServer := mockAnthropicServer(t, "PASS", "anthropic ok")
	defer anthropicServer.Close()
	ollamaServer := mockOllamaServer(t, "FAIL", "ollama found issue")
	defer ollamaServer.Close()

	origURL := anthropicURL
	defer func() { anthropicURL = origURL }()
	anthropicURL = anthropicServer.URL

	t.Setenv("ANTHROPIC_API_KEY", "test-key")

	policies := []Policy{
		{Name: "cloud-check", Prompt: "check quality", Backend: "anthropic"},
		{Name: "local-check", Prompt: "check security", Backend: "ollama", Endpoint: ollamaServer.URL},
	}

	results, err := Evaluate(context.Background(), policies, []byte(`{}`))
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("Expected 2 results, got %d", len(results))
	}
	if !results[0].Passed || results[0].Backend != "anthropic" {
		t.Errorf("Anthropic result: passed=%v backend=%s", results[0].Passed, results[0].Backend)
	}
	if results[1].Passed || results[1].Backend != "ollama" {
		t.Errorf("Ollama result: passed=%v backend=%s", results[1].Passed, results[1].Backend)
	}
}

// ---- URL validation tests ----

// TestValidateURL_StrictByDefault checks the post-M9 behavior: localhost,
// loopback, and RFC 1918 are blocked unless AFLOCK_AIEVAL_ALLOW_INTERNAL=1.
// Public IPs and bad schemes behave as before.
func TestValidateURL_StrictByDefault(t *testing.T) {
	tests := []struct {
		url     string
		wantErr bool
	}{
		{"http://localhost:11434", true},         // blocked: loopback
		{"http://127.0.0.1:11434", true},         // blocked: loopback
		{"http://192.168.1.100:11434", true},     // blocked: RFC 1918
		{"http://169.254.169.254/", true},        // blocked: cloud metadata
		{"https://api.anthropic.com/v1/", false}, // public API allowed
		{"ftp://evil.com", true},                 // wrong scheme
		{"not-a-url", true},                      // unparseable
	}
	for _, tt := range tests {
		err := validateURL(tt.url)
		if (err != nil) != tt.wantErr {
			t.Errorf("validateURL(%q) err=%v, wantErr=%v", tt.url, err, tt.wantErr)
		}
	}
}

// TestValidateURL_AllowInternalOptIn covers the local-development escape
// hatch added for self-hosted Ollama at 127.0.0.1.
func TestValidateURL_AllowInternalOptIn(t *testing.T) {
	t.Setenv("AFLOCK_AIEVAL_ALLOW_INTERNAL", "1")
	for _, raw := range []string{
		"http://localhost:11434",
		"http://127.0.0.1:11434",
		"http://192.168.1.100:11434",
	} {
		if err := validateURL(raw); err != nil {
			t.Errorf("validateURL(%q) err=%v, want nil with ALLOW_INTERNAL=1", raw, err)
		}
	}
}
