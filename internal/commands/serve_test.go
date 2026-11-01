package commands

import (
	"bytes"
	"strings"
	"testing"
)

func TestParseServeOptions(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		token   string
		want    ServeOptions
		wantErr string
	}{
		{name: "padrões", args: nil, want: ServeOptions{Host: "127.0.0.1", Port: 7932}},
		{name: "host e porta", args: []string{"--host", "0.0.0.0", "--port", "9000"}, want: ServeOptions{Host: "0.0.0.0", Port: 9000}},
		{name: "forma inline", args: []string{"--port=8080", "--token=abc"}, want: ServeOptions{Host: "127.0.0.1", Port: 8080, Token: "abc"}},
		{name: "token do ambiente", args: []string{"--host", "0.0.0.0"}, token: "env", want: ServeOptions{Host: "0.0.0.0", Port: 7932, Token: "env"}},
		{name: "porta inválida", args: []string{"--port", "0"}, wantErr: "porta inválida"},
		{name: "porta não numérica", args: []string{"--port", "abc"}, wantErr: "porta inválida"},
		{name: "porta ausente", args: []string{"--port"}, wantErr: "exige um valor"},
		{name: "token vazio", args: []string{"--token="}, wantErr: "--token não pode ser vazio"},
		{name: "host vazio", args: []string{"--host="}, wantErr: "--host não pode ser vazio"},
		{name: "argumento desconhecido", args: []string{"--wat"}, wantErr: "argumento desconhecido"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := parseServeOptions(test.args, test.token)
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("erro = %v, esperava %q", err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("erro inesperado: %v", err)
			}
			if got != test.want {
				t.Fatalf("opções = %+v, esperava %+v", got, test.want)
			}
		})
	}
}

func TestServeRejectsNonLoopbackWithoutToken(t *testing.T) {
	var stderr bytes.Buffer
	runner := &Runner{Stdout: &bytes.Buffer{}, Stderr: &stderr, RootDir: t.TempDir()}
	if code := runner.Serve([]string{"--host", "0.0.0.0", "--port", "7999"}); code != 1 {
		t.Fatalf("código = %d, esperava 1", code)
	}
	if !strings.Contains(stderr.String(), "--token") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestServeRejectsInvalidArguments(t *testing.T) {
	var stdout, stderr bytes.Buffer
	runner := &Runner{Stdout: &stdout, Stderr: &stderr, RootDir: t.TempDir()}
	if code := runner.Serve([]string{"--port", "99999"}); code != 2 {
		t.Fatalf("código = %d, esperava 2", code)
	}
	if !strings.Contains(stdout.String(), "pwn serve") {
		t.Fatalf("uso ausente: %q", stdout.String())
	}
}
