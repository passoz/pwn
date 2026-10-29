package gates_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/passoz/pwn/internal/assets"
	"github.com/passoz/pwn/internal/harness/contract"
	"github.com/passoz/pwn/internal/harness/gates"
)

const testVerifierKey = "test-verifier-key"

// cacheFixture cria um diretório isolado com uma chave fixa.
func cacheFixture(t *testing.T) string {
	t.Helper()
	t.Setenv("PWN_VERIFIER_KEY", testVerifierKey)
	return t.TempDir()
}

func sampleOutput(gate string, versions gates.InputVersions) gates.GateOutput {
	return gates.GateOutput{
		Gate:          gate,
		WorkID:        "0001",
		InputVersions: versions,
		Result:        gates.ResultPassWithNotes,
		Summary:       gates.Summary{Covered: 2, Gaps: 1},
		Findings: []contract.Finding{
			{
				ID:                 "FIND-01",
				Severity:           contract.SeverityMedium,
				Type:               contract.FindingCoverageGap,
				SourceRefs:         []string{"discovery.json"},
				TargetRefs:         []string{"requirements.json"},
				Description:        "Lacuna de exemplo",
				RequiredResolution: "Cobrir o requisito",
				ResolutionOwner:    "product-owner",
				Status:             contract.FindingStatusOpen,
			},
		},
	}
}

func cacheFilePath(workDir, gate string, versions gates.InputVersions) string {
	return filepath.Join(workDir, ".pwn", "gate-cache", gate+"-"+gates.GateCacheKey(gate, versions)+".json")
}

func TestGateCacheRoundTrip(t *testing.T) {
	workDir := cacheFixture(t)
	output := sampleOutput("GATE-DISC-REQ", gates.InputVersions{
		{Key: "discovery", Value: "aaa"},
		{Key: "requirements", Value: "bbb"},
	})
	if err := gates.WriteGateCache(output, workDir); err != nil {
		t.Fatalf("write: %v", err)
	}

	cached := gates.ReadGateCache("GATE-DISC-REQ", workDir, output.InputVersions)
	if cached == nil {
		t.Fatal("cache não encontrado")
	}
	if !reflect.DeepEqual(*cached, output) {
		t.Fatalf("cached = %+v, want %+v", *cached, output)
	}
	if cached.Findings[0].RequiredResolution != "Cobrir o requisito" || cached.Summary.Gaps != 1 {
		t.Fatalf("round-trip perdeu campos: %+v", cached)
	}
}

func TestGateCacheInvalidatedByInputVersions(t *testing.T) {
	workDir := cacheFixture(t)
	output := sampleOutput("GATE-REQ-PRD", gates.InputVersions{
		{Key: "requirements", Value: "aaa"},
		{Key: "prd", Value: "bbb"},
	})
	if err := gates.WriteGateCache(output, workDir); err != nil {
		t.Fatalf("write: %v", err)
	}

	if gates.ReadGateCache("GATE-REQ-PRD", workDir, output.InputVersions) == nil {
		t.Fatal("mesmas versões devem servir o cache")
	}
	cases := []gates.InputVersions{
		{{Key: "requirements", Value: "aaa"}, {Key: "prd", Value: "CCC"}},
		{{Key: "requirements", Value: "aaa"}},
		{{Key: "requirements", Value: "aaa"}, {Key: "prd", Value: "bbb"}, {Key: "extra", Value: "x"}},
	}
	for index, versions := range cases {
		if gates.ReadGateCache("GATE-REQ-PRD", workDir, versions) != nil {
			t.Fatalf("caso %d deveria devolver nil", index)
		}
	}
}

func TestGateCacheRejectsDivergentVersions(t *testing.T) {
	workDir := cacheFixture(t)
	versions := gates.InputVersions{{Key: "spec", Value: "aaa"}, {Key: "plan", Value: "bbb"}}
	file := cacheFilePath(workDir, "GATE-SPEC-PLAN", versions)
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	output := sampleOutput("GATE-SPEC-PLAN", versions)
	writeEnvelope(t, file, map[string]any{
		"gate_version":    "999",
		"harness_version": gates.HarnessVersion(),
		"computed_at":     "2026-10-29T00:00:00.000Z",
		"output":          output,
	})
	if gates.ReadGateCache("GATE-SPEC-PLAN", workDir, versions) != nil {
		t.Fatal("gate_version divergente deveria invalidar")
	}

	writeEnvelope(t, file, map[string]any{
		"gate_version":    gates.GateCacheVersion,
		"harness_version": "0.0.0",
		"computed_at":     "2026-10-29T00:00:00.000Z",
		"output":          output,
	})
	if gates.ReadGateCache("GATE-SPEC-PLAN", workDir, versions) != nil {
		t.Fatal("harness_version divergente deveria invalidar")
	}

	laws := assets.LawsDigest()
	signature, err := gates.SignVerdict(output, workDir, laws)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	writeEnvelope(t, file, map[string]any{
		"gate_version":    gates.GateCacheVersion,
		"harness_version": gates.HarnessVersion(),
		"laws_sha256":     laws,
		"computed_at":     "2026-10-29T00:00:00.000Z",
		"output":          output,
		"signature":       signature,
	})
	if gates.ReadGateCache("GATE-SPEC-PLAN", workDir, versions) == nil {
		t.Fatal("envelope válido deveria ser servido")
	}
}

func TestGateCacheRejectsMissingOrCorruptFile(t *testing.T) {
	workDir := cacheFixture(t)
	versions := gates.InputVersions{{Key: "discovery", Value: "aaa"}}
	if gates.ReadGateCache("GATE-DISC-REQ", workDir, versions) != nil {
		t.Fatal("arquivo ausente deveria devolver nil")
	}

	file := cacheFilePath(workDir, "GATE-DISC-REQ", versions)
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(file, []byte("{ isto não é json"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if gates.ReadGateCache("GATE-DISC-REQ", workDir, versions) != nil {
		t.Fatal("arquivo corrompido deveria devolver nil")
	}
}

func TestClearGateCacheCountsRemovedFiles(t *testing.T) {
	workDir := cacheFixture(t)
	first := sampleOutput("GATE-DISC-REQ", gates.InputVersions{
		{Key: "discovery", Value: "aaa"},
		{Key: "requirements", Value: "bbb"},
	})
	second := sampleOutput("GATE-REQ-PRD", gates.InputVersions{
		{Key: "requirements", Value: "bbb"},
		{Key: "prd", Value: "ccc"},
	})
	if err := gates.WriteGateCache(first, workDir); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := gates.WriteGateCache(second, workDir); err != nil {
		t.Fatalf("write: %v", err)
	}

	if removed := gates.ClearGateCache(workDir); removed != 2 {
		t.Fatalf("removed = %d", removed)
	}
	if gates.ReadGateCache("GATE-DISC-REQ", workDir, first.InputVersions) != nil {
		t.Fatal("cache deveria ter sido removido")
	}
	if removed := gates.ClearGateCache(workDir); removed != 0 {
		t.Fatalf("segunda limpeza removed = %d", removed)
	}
}

func TestGateCacheKeyIsOrderIndependent(t *testing.T) {
	first := gates.GateCacheKey("GATE-DISC-REQ", gates.InputVersions{
		{Key: "discovery", Value: "aaa"},
		{Key: "requirements", Value: "bbb"},
	})
	second := gates.GateCacheKey("GATE-DISC-REQ", gates.InputVersions{
		{Key: "requirements", Value: "bbb"},
		{Key: "discovery", Value: "aaa"},
	})
	if first != second {
		t.Fatalf("chave depende da ordem: %q != %q", first, second)
	}
	if len(first) != 12 {
		t.Fatalf("chave = %q", first)
	}
	if gates.GateCacheKey("GATE-REQ-PRD", gates.InputVersions{
		{Key: "discovery", Value: "aaa"},
		{Key: "requirements", Value: "bbb"},
	}) == first {
		t.Fatal("gate diferente deve gerar chave diferente")
	}
	if gates.GateCacheKey("GATE-DISC-REQ", gates.InputVersions{
		{Key: "discovery", Value: "aaa"},
		{Key: "requirements", Value: "CCC"},
	}) == first {
		t.Fatal("hash diferente deve gerar chave diferente")
	}
}

func TestGateCacheRejectsTamperedEnvelope(t *testing.T) {
	workDir := cacheFixture(t)
	versions := gates.InputVersions{{Key: "prd", Value: "111"}, {Key: "spec", Value: "222"}}
	output := sampleOutput("GATE-PRD-SPEC", versions)
	output.Result = gates.ResultBlocked
	if err := gates.WriteGateCache(output, workDir); err != nil {
		t.Fatalf("write: %v", err)
	}

	cached := gates.ReadGateCache("GATE-PRD-SPEC", workDir, versions)
	if cached == nil || cached.Result != gates.ResultBlocked {
		t.Fatalf("cached = %+v", cached)
	}

	file := cacheFilePath(workDir, "GATE-PRD-SPEC", versions)
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var envelope map[string]any
	if err := json.Unmarshal(data, &envelope); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	envelopeOutput := envelope["output"].(map[string]any)
	envelopeOutput["result"] = "pass"
	envelopeOutput["findings"] = []any{}
	tampered, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(file, tampered, 0o644); err != nil {
		t.Fatalf("write tampered: %v", err)
	}

	if gates.ReadGateCache("GATE-PRD-SPEC", workDir, versions) != nil {
		t.Fatal("envelope adulterado deveria ser rejeitado")
	}
}

func TestGateCacheRejectsDivergentLawsDigest(t *testing.T) {
	workDir := cacheFixture(t)
	versions := gates.InputVersions{{Key: "prd", Value: "111"}, {Key: "spec", Value: "222"}}
	output := sampleOutput("GATE-PRD-SPEC", versions)
	if err := gates.WriteGateCache(output, workDir); err != nil {
		t.Fatalf("write: %v", err)
	}

	file := cacheFilePath(workDir, "GATE-PRD-SPEC", versions)
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var envelope map[string]any
	if err := json.Unmarshal(data, &envelope); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	envelope["laws_sha256"] = "0000000000000000"
	tampered, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(file, tampered, 0o644); err != nil {
		t.Fatalf("write tampered: %v", err)
	}

	if gates.ReadGateCache("GATE-PRD-SPEC", workDir, versions) != nil {
		t.Fatal("laws_sha256 divergente deveria invalidar")
	}
}

func TestVerifierKeyGeneratedWithRestrictedPermissions(t *testing.T) {
	workDir := t.TempDir()
	t.Setenv("PWN_VERIFIER_KEY", "")

	key := gates.GetVerifierKey(workDir)
	if key == "" {
		t.Fatal("chave vazia")
	}
	if again := gates.GetVerifierKey(workDir); again != key {
		t.Fatalf("chave mudou: %q != %q", again, key)
	}
	if stored := gates.ReadVerifierKey(workDir); stored != key {
		t.Fatalf("ReadVerifierKey = %q, want %q", stored, key)
	}
	info, err := os.Stat(filepath.Join(workDir, ".pwn", ".verifier_key"))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("permissão = %o, quer 0600", info.Mode().Perm())
	}
}

func TestVerifierKeyFromEnvironmentWins(t *testing.T) {
	workDir := t.TempDir()
	t.Setenv("PWN_VERIFIER_KEY", "  env-key  ")
	if key := gates.GetVerifierKey(workDir); key != "env-key" {
		t.Fatalf("key = %q", key)
	}
	if _, err := os.Stat(filepath.Join(workDir, ".pwn", ".verifier_key")); err == nil {
		t.Fatal("não deve gravar chave quando o ambiente a fornece")
	}
}

func TestReadVerifierKeyDoesNotCreate(t *testing.T) {
	workDir := t.TempDir()
	t.Setenv("PWN_VERIFIER_KEY", "")
	if key := gates.ReadVerifierKey(workDir); key != "" {
		t.Fatalf("key = %q", key)
	}
	if _, err := os.Stat(filepath.Join(workDir, ".pwn", ".verifier_key")); err == nil {
		t.Fatal("ReadVerifierKey não deve criar a chave")
	}
}

func writeEnvelope(t *testing.T, file string, envelope map[string]any) {
	t.Helper()
	data, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	if err := os.WriteFile(file, data, 0o644); err != nil {
		t.Fatalf("write envelope: %v", err)
	}
}

func TestEnvelopeKeepsVersionMetadata(t *testing.T) {
	workDir := cacheFixture(t)
	output := sampleOutput("GATE-DISC-REQ", gates.InputVersions{{Key: "discovery", Value: "aaa"}})
	if err := gates.WriteGateCache(output, workDir); err != nil {
		t.Fatalf("write: %v", err)
	}
	data, err := os.ReadFile(cacheFilePath(workDir, "GATE-DISC-REQ", output.InputVersions))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var envelope gates.GateCacheEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if envelope.GateVersion != gates.GateCacheVersion {
		t.Fatalf("gate_version = %q", envelope.GateVersion)
	}
	if envelope.HarnessVersion != assets.Version() {
		t.Fatalf("harness_version = %q", envelope.HarnessVersion)
	}
	if envelope.LawsSHA256 != assets.LawsDigest() {
		t.Fatalf("laws_sha256 = %q", envelope.LawsSHA256)
	}
	if !strings.HasSuffix(envelope.ComputedAt, "Z") {
		t.Fatalf("computed_at = %q", envelope.ComputedAt)
	}
	if envelope.Signature == "" {
		t.Fatal("assinatura ausente")
	}
}
