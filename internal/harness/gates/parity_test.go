package gates_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"testing"

	"github.com/passoz/pwn/internal/assets"
	"github.com/passoz/pwn/internal/harness/gates"
)

// repoRoot sobe a partir do diretório do teste até encontrar go.mod.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod não encontrado")
		}
		dir = parent
	}
}

type parityGate struct {
	Output    json.RawMessage `json:"output"`
	CacheKey  string          `json:"cache_key"`
	Signature string          `json:"signature"`
}

type parityDocument struct {
	GateCacheVersion string       `json:"gate_cache_version"`
	HarnessVersion   string       `json:"harness_version"`
	LawsSHA256       string       `json:"laws_sha256"`
	VerifierKey      string       `json:"verifier_key"`
	Gates            []parityGate `json:"gates"`
}

func loadParityDocument(t *testing.T) parityDocument {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "work0002.json"))
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	var document parityDocument
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatalf("unmarshal golden: %v", err)
	}
	return document
}

// TestWork0002Parity compara os vereditos, os hashes de entrada, as chaves de
// cache e as assinaturas do Work 0002 real com a referência TypeScript.
func TestWork0002Parity(t *testing.T) {
	document := loadParityDocument(t)
	root := repoRoot(t)
	workDir := filepath.Join(root, ".pwn", "work", "0002")
	t.Setenv("PWN_VERIFIER_KEY", document.VerifierKey)

	if got := gates.GateCacheVersion; got != document.GateCacheVersion {
		t.Fatalf("gate cache version = %q, want %q", got, document.GateCacheVersion)
	}
	if got := gates.HarnessVersion(); got != document.HarnessVersion {
		t.Fatalf("harness version = %q, want %q", got, document.HarnessVersion)
	}
	if got := assets.LawsDigest(); got != document.LawsSHA256 {
		t.Fatalf("laws digest = %q, want %q", got, document.LawsSHA256)
	}

	outputs := gates.EvaluateAllGates("0002", workDir)
	if len(outputs) != len(document.Gates) {
		t.Fatalf("outputs = %d, want %d", len(outputs), len(document.Gates))
	}

	for index, expected := range document.Gates {
		output := outputs[index]

		var wantOutput gates.GateOutput
		if err := json.Unmarshal(expected.Output, &wantOutput); err != nil {
			t.Fatalf("unmarshal output %d: %v", index, err)
		}
		if !reflect.DeepEqual(output, wantOutput) {
			t.Fatalf("%s: output = %+v\nwant %+v", output.Gate, output, wantOutput)
		}

		// A serialização precisa ser byte a byte a do TypeScript.
		serialized, err := gates.MarshalOutput(output)
		if err != nil {
			t.Fatalf("marshal %s: %v", output.Gate, err)
		}
		var compacted bytes.Buffer
		if err := json.Compact(&compacted, expected.Output); err != nil {
			t.Fatalf("compact %s: %v", output.Gate, err)
		}
		if !bytes.Equal(serialized, compacted.Bytes()) {
			t.Fatalf("%s: JSON = %s\nwant %s", output.Gate, serialized, compacted.Bytes())
		}

		if key := gates.GateCacheKey(output.Gate, output.InputVersions); key != expected.CacheKey {
			t.Fatalf("%s: cache key = %q, want %q", output.Gate, key, expected.CacheKey)
		}
		signature, err := gates.SignVerdict(output, workDir, document.LawsSHA256)
		if err != nil {
			t.Fatalf("%s: sign: %v", output.Gate, err)
		}
		if signature != expected.Signature {
			t.Fatalf("%s: signature = %q, want %q", output.Gate, signature, expected.Signature)
		}
		if !gates.VerifyVerdict(output, workDir, document.LawsSHA256, signature, document.GateCacheVersion, document.HarnessVersion) {
			t.Fatalf("%s: assinatura não verificou", output.Gate)
		}
		// Qualquer alteração do veredito invalida a assinatura.
		tampered := output
		tampered.Result = gates.ResultBlocked
		if gates.VerifyVerdict(tampered, workDir, document.LawsSHA256, signature, document.GateCacheVersion, document.HarnessVersion) {
			t.Fatalf("%s: assinatura aceitou veredito alterado", output.Gate)
		}
	}
}

// TestWork0002CacheRoundTrip grava e relê o cache dos cinco gates numa cópia do
// Work real, sem tocar no repositório.
func TestWork0002CacheRoundTrip(t *testing.T) {
	document := loadParityDocument(t)
	root := repoRoot(t)
	source := filepath.Join(root, ".pwn", "work", "0002")
	t.Setenv("PWN_VERIFIER_KEY", document.VerifierKey)

	tempWorkDir := t.TempDir()
	if err := copyDirectoryForTest(source, tempWorkDir); err != nil {
		t.Fatalf("copy: %v", err)
	}

	outputs := gates.EvaluateAllGates("0002", tempWorkDir)
	for _, output := range outputs {
		if err := gates.WriteGateCache(output, tempWorkDir); err != nil {
			t.Fatalf("%s: write cache: %v", output.Gate, err)
		}
		cached := gates.ReadGateCache(output.Gate, tempWorkDir, output.InputVersions)
		if cached == nil {
			t.Fatalf("%s: cache não encontrado", output.Gate)
		}
		if !reflect.DeepEqual(*cached, output) {
			t.Fatalf("%s: cache = %+v\nwant %+v", output.Gate, *cached, output)
		}
	}
	if removed := gates.ClearGateCache(tempWorkDir); removed != len(outputs) {
		t.Fatalf("removed = %d", removed)
	}
}

func copyDirectoryForTest(src, dst string) error {
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return err
	}
	for _, entry := range entries {
		source := filepath.Join(src, entry.Name())
		target := filepath.Join(dst, entry.Name())
		if entry.IsDir() {
			if err := copyDirectoryForTest(source, target); err != nil {
				return err
			}
			continue
		}
		data, err := os.ReadFile(source)
		if err != nil {
			return err
		}
		if err := os.WriteFile(target, data, 0o644); err != nil {
			return err
		}
	}
	return nil
}

// TestSemanticGapFixtureParity compara os achados, a ordem deles e as
// assinaturas de uma fixture com múltiplas violações semânticas.
func TestSemanticGapFixtureParity(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "semantic-gap-expected.json"))
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	var document struct {
		VerifierKey string       `json:"verifier_key"`
		LawsSHA256  string       `json:"laws_sha256"`
		Gates       []parityGate `json:"gates"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatalf("unmarshal golden: %v", err)
	}
	t.Setenv("PWN_VERIFIER_KEY", document.VerifierKey)

	workDir, err := filepath.Abs(filepath.Join("testdata", "fixtures", "semantic-gap"))
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	outputs := gates.EvaluateAllGates("0099", workDir)
	if len(outputs) != len(document.Gates) {
		t.Fatalf("outputs = %d, want %d", len(outputs), len(document.Gates))
	}

	for index, expected := range document.Gates {
		output := outputs[index]
		var wantOutput gates.GateOutput
		if err := json.Unmarshal(expected.Output, &wantOutput); err != nil {
			t.Fatalf("unmarshal output %d: %v", index, err)
		}
		if !reflect.DeepEqual(output, wantOutput) {
			t.Fatalf("%s: output = %+v\nwant %+v", output.Gate, output, wantOutput)
		}
		serialized, err := gates.MarshalOutput(output)
		if err != nil {
			t.Fatalf("marshal %s: %v", output.Gate, err)
		}
		var compacted bytes.Buffer
		if err := json.Compact(&compacted, expected.Output); err != nil {
			t.Fatalf("compact %s: %v", output.Gate, err)
		}
		if !bytes.Equal(serialized, compacted.Bytes()) {
			t.Fatalf("%s: JSON = %s\nwant %s", output.Gate, serialized, compacted.Bytes())
		}
		if key := gates.GateCacheKey(output.Gate, output.InputVersions); key != expected.CacheKey {
			t.Fatalf("%s: cache key = %q, want %q", output.Gate, key, expected.CacheKey)
		}
		signature, err := gates.SignVerdict(output, workDir, document.LawsSHA256)
		if err != nil {
			t.Fatalf("%s: sign: %v", output.Gate, err)
		}
		if signature != expected.Signature {
			t.Fatalf("%s: signature = %q, want %q", output.Gate, signature, expected.Signature)
		}
	}
}

// TestEnvelopeFormatParity confere que o arquivo de cache tem os mesmos bytes
// do TypeScript, sem escapar HTML e com a mesma indentação.
func TestEnvelopeFormatParity(t *testing.T) {
	document := loadParityDocument(t)
	t.Setenv("PWN_VERIFIER_KEY", document.VerifierKey)

	workDir, err := filepath.Abs(filepath.Join("testdata", "fixtures", "semantic-gap"))
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	output := gates.EvaluateAllGates("0099", workDir)[3]
	cacheRoot := t.TempDir()
	if err := gates.WriteGateCache(output, cacheRoot); err != nil {
		t.Fatalf("write cache: %v", err)
	}

	entries, err := os.ReadDir(filepath.Join(cacheRoot, ".pwn", "gate-cache"))
	if err != nil || len(entries) != 1 {
		t.Fatalf("cache dir: %v (%d entries)", err, len(entries))
	}
	written, err := os.ReadFile(filepath.Join(cacheRoot, ".pwn", "gate-cache", entries[0].Name()))
	if err != nil {
		t.Fatalf("read cache: %v", err)
	}
	expected, err := os.ReadFile(filepath.Join("testdata", "semantic-gap-envelope.json"))
	if err != nil {
		t.Fatalf("read envelope golden: %v", err)
	}

	normalized := regexp.MustCompile(`"computed_at": "[^"]*"`).
		ReplaceAllString(string(written), `"computed_at": "2026-10-29T00:00:00.000Z"`)
	if normalized != string(expected) {
		t.Fatalf("envelope = %s\nwant %s", normalized, expected)
	}
}
