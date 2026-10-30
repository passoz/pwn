package gates_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/passoz/pwn/internal/assets"
	"github.com/passoz/pwn/internal/harness/contract"
	"github.com/passoz/pwn/internal/harness/gates"
)

// cacheEnvelope monta um envelope válido e permite alterar campos antes de
// gravá-lo no caminho de cache de gate + versões.
func cacheEnvelope(t *testing.T, workDir string, output gates.GateOutput, mutate func(map[string]any)) {
	t.Helper()
	laws := assets.LawsDigest()
	signature, err := gates.SignVerdict(output, workDir, laws)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	envelope := map[string]any{
		"gate_version":    gates.GateCacheVersion,
		"harness_version": gates.HarnessVersion(),
		"laws_sha256":     laws,
		"computed_at":     "2026-10-29T00:00:00.000Z",
		"output":          output,
		"signature":       signature,
	}
	if mutate != nil {
		mutate(envelope)
	}
	file := cacheFilePath(workDir, output.Gate, output.InputVersions)
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	writeEnvelope(t, file, envelope)
}

func TestGateCacheRejectsInconsistentEnvelopes(t *testing.T) {
	versions := gates.InputVersions{{Key: "spec", Value: "aaa"}, {Key: "plan", Value: "bbb"}}
	output := sampleOutput("GATE-SPEC-PLAN", versions)

	cases := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"output nulo", func(e map[string]any) { e["output"] = nil }},
		{"gate do output diverge do pedido", func(e map[string]any) {
			other := sampleOutput("GATE-OUTRO", versions)
			e["output"] = other
		}},
		{"quantidade de inputs diverge", func(e map[string]any) {
			e["output"] = sampleOutput("GATE-SPEC-PLAN", gates.InputVersions{{Key: "spec", Value: "aaa"}})
		}},
		{"valor de input diverge", func(e map[string]any) {
			e["output"] = sampleOutput("GATE-SPEC-PLAN", gates.InputVersions{{Key: "spec", Value: "aaa"}, {Key: "plan", Value: "XXX"}})
		}},
		{"chave de input diverge", func(e map[string]any) {
			e["output"] = sampleOutput("GATE-SPEC-PLAN", gates.InputVersions{{Key: "spec", Value: "aaa"}, {Key: "outra", Value: "bbb"}})
		}},
		{"sem assinatura", func(e map[string]any) { delete(e, "signature") }},
		{"assinatura vazia", func(e map[string]any) { e["signature"] = "" }},
		{"assinatura de tamanho errado", func(e map[string]any) { e["signature"] = "abc" }},
		{"assinatura do tamanho certo mas incorreta", func(e map[string]any) { e["signature"] = strings.Repeat("0", 64) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			workDir := cacheFixture(t)
			cacheEnvelope(t, workDir, output, tc.mutate)
			if cached := gates.ReadGateCache("GATE-SPEC-PLAN", workDir, versions); cached != nil {
				t.Fatalf("envelope inconsistente foi servido: %+v", cached)
			}
		})
	}

	// Controle: o envelope sem alteração é servido.
	workDir := cacheFixture(t)
	cacheEnvelope(t, workDir, output, nil)
	if gates.ReadGateCache("GATE-SPEC-PLAN", workDir, versions) == nil {
		t.Fatal("envelope íntegro deveria ser servido")
	}
}

func TestGateCacheServesEnvelopeWithoutLawsDigestWhenSignatureMatches(t *testing.T) {
	workDir := cacheFixture(t)
	versions := gates.InputVersions{{Key: "spec", Value: "aaa"}}
	output := sampleOutput("GATE-SPEC-PLAN", versions)
	// O envelope legado omite laws_sha256: a assinatura vale para o digest atual.
	cacheEnvelope(t, workDir, output, func(e map[string]any) { delete(e, "laws_sha256") })
	if cached := gates.ReadGateCache("GATE-SPEC-PLAN", workDir, versions); cached == nil || cached.Gate != "GATE-SPEC-PLAN" {
		t.Fatalf("cached = %+v", cached)
	}

	// Com laws_sha256 omitido, uma assinatura calculada para outro digest falha.
	signature, err := gates.SignVerdict(output, workDir, "0000")
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	cacheEnvelope(t, workDir, output, func(e map[string]any) {
		delete(e, "laws_sha256")
		e["signature"] = signature
	})
	if gates.ReadGateCache("GATE-SPEC-PLAN", workDir, versions) != nil {
		t.Fatal("assinatura de outro digest deveria ser rejeitada")
	}
}

func TestVerifyVerdictChecksSignatureAndContext(t *testing.T) {
	workDir := cacheFixture(t)
	output := sampleOutput("GATE-DISC-REQ", gates.InputVersions{{Key: "discovery", Value: "aaa"}})
	laws := assets.LawsDigest()
	signature, err := gates.SignVerdict(output, workDir, laws)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	version, harness := gates.GateCacheVersion, gates.HarnessVersion()

	if !gates.VerifyVerdict(output, workDir, laws, signature, version, harness) {
		t.Fatal("assinatura legítima deveria conferir")
	}
	if gates.VerifyVerdict(output, workDir, laws, signature[:len(signature)-1], version, harness) {
		t.Fatal("assinatura truncada não deveria conferir")
	}
	if gates.VerifyVerdict(output, workDir, laws, "", version, harness) {
		t.Fatal("assinatura vazia não deveria conferir")
	}
	if gates.VerifyVerdict(output, workDir, "outro-digest", signature, version, harness) {
		t.Fatal("digest de leis diferente não deveria conferir")
	}
	if gates.VerifyVerdict(output, workDir, laws, signature, "999", harness) {
		t.Fatal("versão de gate diferente não deveria conferir")
	}
	if gates.VerifyVerdict(output, workDir, laws, signature, version, "0.0.0") {
		t.Fatal("versão de harness diferente não deveria conferir")
	}
	tampered := output
	tampered.Result = gates.ResultBlocked
	if gates.VerifyVerdict(tampered, workDir, laws, signature, version, harness) {
		t.Fatal("veredito alterado não deveria conferir")
	}
	t.Setenv("PWN_VERIFIER_KEY", "outra-chave")
	if gates.VerifyVerdict(output, workDir, laws, signature, version, harness) {
		t.Fatal("chave diferente não deveria conferir")
	}
}

func TestSignVerdictTreatsNilFindingsAsEmpty(t *testing.T) {
	workDir := cacheFixture(t)
	versions := gates.InputVersions{{Key: "discovery", Value: "aaa"}}
	withNil := gates.GateOutput{Gate: "GATE-DISC-REQ", WorkID: "0001", InputVersions: versions, Result: gates.ResultPass}
	withEmpty := withNil
	withEmpty.Findings = []contract.Finding{}

	nilSignature, err := gates.SignVerdict(withNil, workDir, "laws")
	if err != nil {
		t.Fatalf("sign nil: %v", err)
	}
	emptySignature, err := gates.SignVerdict(withEmpty, workDir, "laws")
	if err != nil {
		t.Fatalf("sign empty: %v", err)
	}
	if nilSignature != emptySignature {
		t.Fatalf("findings nil e vazio assinam diferente: %s != %s", nilSignature, emptySignature)
	}
	if !gates.VerifyVerdict(withNil, workDir, "laws", emptySignature, gates.GateCacheVersion, gates.HarnessVersion()) {
		t.Fatal("assinatura de findings vazio deveria valer para findings nil")
	}
}

func TestWriteGateCacheFailsWhenCacheDirIsBlocked(t *testing.T) {
	workDir := cacheFixture(t)
	// `.pwn` como arquivo regular impede criar `.pwn/gate-cache`.
	if err := os.WriteFile(filepath.Join(workDir, ".pwn"), []byte("x"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	output := sampleOutput("GATE-DISC-REQ", gates.InputVersions{{Key: "discovery", Value: "aaa"}})
	if err := gates.WriteGateCache(output, workDir); err == nil {
		t.Fatal("esperava erro ao criar o diretório de cache")
	}
}

func TestClearGateCacheWithoutWorkDirClearsCurrentDirectoryAndWorks(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	t.Setenv("PWN_VERIFIER_KEY", testVerifierKey)

	write := func(workDir, gate string) {
		t.Helper()
		versions := gates.InputVersions{{Key: "discovery", Value: gate}}
		if err := gates.WriteGateCache(sampleOutput(gate, versions), workDir); err != nil {
			t.Fatalf("write %s: %v", workDir, err)
		}
	}
	workA := filepath.Join(root, ".pwn", "work", "0001")
	workB := filepath.Join(root, ".pwn", "work", "0002")
	for _, dir := range []string{workA, workB} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
	}
	// Arquivo solto em `.pwn/work` não é Work e deve ser ignorado.
	if err := os.WriteFile(filepath.Join(root, ".pwn", "work", "LEIA-ME.txt"), []byte("x"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	write(root, "GATE-DISC-REQ")
	write(workA, "GATE-REQ-PRD")
	write(workA, "GATE-PRD-SPEC")
	write(workB, "GATE-SPEC-PLAN")

	// Arquivos que não são cache ficam; o diretório com resto não é removido.
	keep := filepath.Join(workA, ".pwn", "gate-cache", "notas.txt")
	if err := os.WriteFile(keep, []byte("x"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.Mkdir(filepath.Join(workB, ".pwn", "gate-cache", "sub.json"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	if removed := gates.ClearGateCache(""); removed != 4 {
		t.Fatalf("removidos = %d, want 4", removed)
	}
	if _, err := os.Stat(keep); err != nil {
		t.Fatalf("arquivo que não é cache foi removido: %v", err)
	}
	if _, err := os.Stat(filepath.Join(workB, ".pwn", "gate-cache", "sub.json")); err != nil {
		t.Fatalf("diretório *.json foi removido: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, ".pwn", "gate-cache")); err == nil {
		t.Fatal("diretório de cache vazio da raiz deveria ser removido")
	}
	if removed := gates.ClearGateCache(""); removed != 0 {
		t.Fatalf("segunda limpeza removeu %d", removed)
	}
}

func TestClearGateCacheWithoutWorkDirAndWithoutWorksReturnsRootCount(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	t.Setenv("PWN_VERIFIER_KEY", testVerifierKey)
	output := sampleOutput("GATE-DISC-REQ", gates.InputVersions{{Key: "discovery", Value: "aaa"}})
	if err := gates.WriteGateCache(output, root); err != nil {
		t.Fatalf("write: %v", err)
	}
	if removed := gates.ClearGateCache(""); removed != 1 {
		t.Fatalf("removidos = %d, want 1", removed)
	}
}

func TestVerifierKeyRepairsPermissionsAndEmptyFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("modos POSIX não se aplicam ao Windows")
	}
	t.Setenv("PWN_VERIFIER_KEY", "")

	loose := t.TempDir()
	keyPath := filepath.Join(loose, ".pwn", ".verifier_key")
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte("  chave-existente\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if key := gates.GetVerifierKey(loose); key != "chave-existente" {
		t.Fatalf("key = %q", key)
	}
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("permissão = %o, quer 0600", info.Mode().Perm())
	}
	if stored := gates.ReadVerifierKey(loose); stored != "chave-existente" {
		t.Fatalf("ReadVerifierKey = %q", stored)
	}

	empty := t.TempDir()
	emptyPath := filepath.Join(empty, ".pwn", ".verifier_key")
	if err := os.MkdirAll(filepath.Dir(emptyPath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(emptyPath, []byte("   \n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	generated := gates.GetVerifierKey(empty)
	if generated == "" {
		t.Fatal("chave vazia no arquivo deveria gerar uma nova")
	}
	data, err := os.ReadFile(emptyPath)
	if err != nil || strings.TrimSpace(string(data)) != generated {
		t.Fatalf("arquivo = %q, %v; quer %q", data, err, generated)
	}
}

func TestReadVerifierKeyEnvironmentWins(t *testing.T) {
	workDir := t.TempDir()
	keyPath := filepath.Join(workDir, ".pwn", ".verifier_key")
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte("do-arquivo"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	t.Setenv("PWN_VERIFIER_KEY", "  do-ambiente ")
	if key := gates.ReadVerifierKey(workDir); key != "do-ambiente" {
		t.Fatalf("key = %q", key)
	}
	t.Setenv("PWN_VERIFIER_KEY", "")
	if key := gates.ReadVerifierKey(workDir); key != "do-arquivo" {
		t.Fatalf("key = %q", key)
	}
}
