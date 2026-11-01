package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHelpMentionsServe(t *testing.T) {
	var stdout bytes.Buffer
	if code := Run([]string{"--help"}, &stdout, &bytes.Buffer{}); code != 0 {
		t.Fatalf("código = %d", code)
	}
	if !strings.Contains(stdout.String(), "serve") {
		t.Fatalf("ajuda sem o comando serve:\n%s", stdout.String())
	}
}

func TestCommandSpecsIncludeServe(t *testing.T) {
	spec, ok := lookupCommand("serve")
	if !ok || spec.takesSubcommand {
		t.Fatalf("spec = %+v, ok = %v", spec, ok)
	}
}

func TestCommandWritesStructuredLogFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".pwn"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)

	var stdout, stderr bytes.Buffer
	if code := Run([]string{"work", "status", "--json"}, &stdout, &stderr); code != 0 {
		t.Fatalf("código = %d: %s", code, stderr.String())
	}

	data, err := os.ReadFile(filepath.Join(dir, ".pwn", "logs", "pwn.log"))
	if err != nil {
		t.Fatalf("log estruturado ausente: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("linhas = %d, esperava start e end: %s", len(lines), data)
	}
	messages := make([]string, 0, 2)
	for _, line := range lines {
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("linha não é JSON: %q", line)
		}
		message, _ := record["msg"].(string)
		messages = append(messages, message)
	}
	if messages[0] != "command.start" || messages[1] != "command.end" {
		t.Fatalf("mensagens = %v", messages)
	}
}
