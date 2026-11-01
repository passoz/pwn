package cli

import (
	"bytes"
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
