package logx

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenWritesJSONLinesAndRedactsSecrets(t *testing.T) {
	file := filepath.Join(t.TempDir(), "logs", "pwn.log")
	logger, err := Open(Options{Level: "info", File: file})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	logger.Info("command.start", "command", "work", "api_key", "minha-chave-secreta")
	logger.Info("http", "url", "https://exemplo.test?token=abc123def456", "header", "Bearer abcdefghijklmnop")
	logger.Debug("debug.ignorado")
	if err := logger.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("ler log: %v", err)
	}
	if strings.Contains(string(data), "minha-chave-secreta") {
		t.Fatalf("segredo em chave não foi redigido: %s", data)
	}
	if strings.Contains(string(data), "abc123def456") || strings.Contains(string(data), "abcdefghijklmnop") {
		t.Fatalf("segredo em valor não foi redigido: %s", data)
	}
	if !strings.Contains(string(data), "[REDACTED]") {
		t.Fatalf("marcador de redação ausente: %s", data)
	}
	if strings.Contains(string(data), "debug.ignorado") {
		t.Fatalf("nível debug vazou com nível info: %s", data)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("linhas = %d, esperava 2", len(lines))
	}
	for _, line := range lines {
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("linha não é JSON: %v (%q)", err, line)
		}
		if record["level"] == nil || record["msg"] == nil || record["time"] == nil {
			t.Fatalf("campos base ausentes: %v", record)
		}
	}
}

func TestOpenTruncatesLongValues(t *testing.T) {
	file := filepath.Join(t.TempDir(), "pwn.log")
	logger, err := Open(Options{File: file})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	logger.Info("big", "payload", strings.Repeat("a", MaxValueLength+100))
	if err := logger.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), strings.Repeat("a", MaxValueLength+1)) {
		t.Fatal("valor longo não foi truncado")
	}
	if !strings.Contains(string(data), "…") {
		t.Fatal("marcador de truncamento ausente")
	}
}

func TestOpenWithoutDestinationsIsSilent(t *testing.T) {
	logger, err := Open(Options{})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	logger.Info("nada")
	if err := logger.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestOpenFailsOnUnwritablePath(t *testing.T) {
	root := t.TempDir()
	blocker := filepath.Join(root, "arquivo")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(Options{File: filepath.Join(blocker, "sub", "pwn.log")}); err == nil {
		t.Fatal("Open deveria falhar com diretório inválido")
	}
}

func TestParseLevel(t *testing.T) {
	tests := map[string]string{
		"debug":   "DEBUG",
		"INFO":    "INFO",
		" warn ":  "WARN",
		"warning": "WARN",
		"error":   "ERROR",
		"lixo":    "INFO",
		"":        "INFO",
	}
	for input, want := range tests {
		if got := ParseLevel(input).String(); got != want {
			t.Fatalf("ParseLevel(%q) = %s, quer %s", input, got, want)
		}
	}
}

func TestIsLoopback(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "::1", "localhost"} {
		if !IsLoopback(host) {
			t.Fatalf("%s deveria ser local", host)
		}
	}
	for _, host := range []string{"0.0.0.0", "10.0.0.1", "exemplo.test", ""} {
		if IsLoopback(host) {
			t.Fatalf("%s não deveria ser local", host)
		}
	}
}
