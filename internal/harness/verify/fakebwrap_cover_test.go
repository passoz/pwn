package verify_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/passoz/pwn/internal/harness/verify"
)

// fakeBwrapScript imita o contrato do bwrap que o verificador usa: ignora as
// opções de montagem, entra em --chdir e executa o comando depois de `--`.
// Assim os caminhos de execução são testados sem depender de bwrap no host.
const fakeBwrapScript = `#!/bin/sh
chdir=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --chdir) chdir=$2; shift 2 ;;
    --) shift; break ;;
    *) shift ;;
  esac
done
cd "$chdir" || exit 97
exec "$@"
`

func writeScript(t *testing.T, directory, name, body string) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatalf("gravar %s: %v", path, err)
	}
	return path
}

// useFakeBwrap aponta o verificador para o bwrap de mentira e para /bin/sh como
// runtime aprovado.
func useFakeBwrap(t *testing.T, verifierRoot string) string {
	t.Helper()
	bwrap := writeScript(t, t.TempDir(), "bwrap", fakeBwrapScript)
	configureVerifier(t, verifierRoot, "/bin/sh", bwrap)
	return bwrap
}

func fakeRepo(t *testing.T, options repoOptions) repoFixture {
	t.Helper()
	fixture := buildRepo(t, options)
	useFakeBwrap(t, fixture.verifierRoot)
	return fixture
}

// causalRepo cria um repositório cujo candidato é NEW e cujo baseline é OLD, e
// devolve a aprovação com o AC-1 trocado por um comando que depende do conteúdo
// da implementação.
func causalRepo(t *testing.T, command string) (repoFixture, verify.Approval) {
	t.Helper()
	fixture := fakeRepo(t, repoOptions{candidate: newImplementation, baseline: oldImplementation})
	approval := approve(t, fixture)
	approval.Checks[0].Command = []string{"/bin/sh", "-c", command}
	return fixture, approval
}

func runWithTimeout(t *testing.T, fixture repoFixture, approval verify.Approval, seconds int) verify.VerificationRunResult {
	t.Helper()
	result, err := verify.RunVerification(verify.RunVerificationOptions{
		RootDir:         fixture.rootDir,
		Approval:        approval,
		TimeoutSeconds:  seconds,
		VerifierRootDir: fixture.verifierRoot,
	})
	if err != nil {
		t.Fatalf("executar a verificação: %v", err)
	}
	return result
}

func setProject(t *testing.T, verifierRoot, repoDir string, entry any) {
	t.Helper()
	config := verify.ReadConfig(verifierRoot)
	if config == nil {
		t.Fatalf("config.json ausente em %s", verifierRoot)
	}
	key, err := filepath.EvalSymlinks(repoDir)
	if err != nil {
		t.Fatalf("resolver %s: %v", repoDir, err)
	}
	raw, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("serializar o projeto: %v", err)
	}
	config.Projects = map[string]json.RawMessage{key: raw}
	if err := verify.WriteJSONAtomic(verify.ConfigFile(verifierRoot), config); err != nil {
		t.Fatalf("gravar a configuração: %v", err)
	}
}

func TestRunVerificationCausalPassWithFakeSandbox(t *testing.T) {
	fixture, approval := causalRepo(t, "test -L link.ts && grep -q NEW src/lib.ts && grep -q NEW tests/acceptance.test.ts")
	if err := os.Symlink("src/lib.ts", filepath.Join(fixture.rootDir, "link.ts")); err != nil {
		t.Fatalf("criar o vínculo: %v", err)
	}
	writeFile(t, fixture.rootDir, "node_modules/marker.txt", "ok\n") // dependência: fora do snapshot, montada à parte
	// O arquivo do repositório foi enfraquecido; o aprovado vive na raiz protegida.
	writeFile(t, fixture.rootDir, acPath, "// enfraquecido\n")

	result := runWithTimeout(t, fixture, approval, 0)
	ac := findCheck(t, result, "AC-1")
	if ac.Outcome != "pass" || ac.ExitCode != 0 {
		t.Fatalf("AC-1 = %+v", ac)
	}
	if ac.Baseline == nil || ac.Baseline.ExitCode == 0 || ac.Baseline.SuspectEnvironmental {
		t.Errorf("baseline = %+v, quer falha causal sem suspeita de ambiente", ac.Baseline)
	}
	regression := findCheck(t, result, "REGRESSION")
	if regression.Outcome != "pass" || regression.Baseline != nil {
		t.Errorf("REGRESSION = %+v", regression)
	}
	if result.SandboxPolicy.Engine != "bwrap" || result.SandboxPolicy.Network {
		t.Errorf("política = %+v", result.SandboxPolicy)
	}
	if len(result.SnapshotDigest) != 64 || len(result.DependencyDigest) != 64 || len(result.SandboxDigest) != 64 {
		t.Errorf("digests = %q %q %q", result.SnapshotDigest, result.DependencyDigest, result.SandboxDigest)
	}
	if outcome := verify.ReceiptOutcome(result); outcome != "pass" {
		t.Errorf("outcome = %q", outcome)
	}
}

func TestRunVerificationOutcomes(t *testing.T) {
	t.Run("candidato falha", func(t *testing.T) {
		fixture, approval := causalRepo(t, "grep -q WRONG src/lib.ts")
		ac := findCheck(t, runWithTimeout(t, fixture, approval, 30), "AC-1")
		if ac.Outcome != "fail" || ac.ExitCode != 1 || !strings.Contains(ac.Reason, "exit 1") {
			t.Fatalf("AC-1 = %+v", ac)
		}
		if ac.Baseline != nil {
			t.Errorf("o baseline não roda quando o candidato falha: %+v", ac.Baseline)
		}
	})

	t.Run("prova vácua", func(t *testing.T) {
		fixture, approval := causalRepo(t, "true")
		ac := findCheck(t, runWithTimeout(t, fixture, approval, 30), "AC-1")
		if ac.Outcome != "fail" || !strings.Contains(ac.Reason, "sem a implementação") {
			t.Fatalf("AC-1 = %+v", ac)
		}
		if ac.Baseline == nil || ac.Baseline.ExitCode != 0 {
			t.Errorf("baseline = %+v", ac.Baseline)
		}
	})

	t.Run("falha de baseline parece ambiente", func(t *testing.T) {
		fixture, approval := causalRepo(t, "echo 'command not found' >&2; grep -q NEW src/lib.ts")
		ac := findCheck(t, runWithTimeout(t, fixture, approval, 30), "AC-1")
		if ac.Outcome != "fail" || !strings.Contains(ac.Reason, "erro de ambiente") {
			t.Fatalf("AC-1 = %+v", ac)
		}
		if ac.Baseline == nil || !ac.Baseline.SuspectEnvironmental || ac.Baseline.ExitCode == 0 {
			t.Errorf("baseline = %+v", ac.Baseline)
		}
	})

	t.Run("expect_output presente", func(t *testing.T) {
		fixture, approval := causalRepo(t, "echo marcador; grep -q NEW src/lib.ts")
		approval.Checks[0].ExpectOutput = new("marcador")
		ac := findCheck(t, runWithTimeout(t, fixture, approval, 30), "AC-1")
		if ac.Outcome != "pass" {
			t.Fatalf("AC-1 = %+v", ac)
		}
		if !strings.Contains(ac.OutputTail, "marcador") {
			t.Errorf("cauda = %q", ac.OutputTail)
		}
	})

	t.Run("expect_output ausente", func(t *testing.T) {
		fixture, approval := causalRepo(t, "grep -q NEW src/lib.ts")
		approval.Checks[0].ExpectOutput = new("texto \"aprovado\"")
		ac := findCheck(t, runWithTimeout(t, fixture, approval, 30), "AC-1")
		if ac.Outcome != "fail" || !strings.Contains(ac.Reason, `"texto \"aprovado\""`) {
			t.Fatalf("AC-1 = %+v", ac)
		}
	})

	t.Run("candidato excede o tempo", func(t *testing.T) {
		fixture, approval := causalRepo(t, "exec sleep 5")
		started := time.Now()
		ac := findCheck(t, runWithTimeout(t, fixture, approval, 1), "AC-1")
		if ac.Outcome != "blocked" || !strings.Contains(ac.Reason, "excedeu 1s") {
			t.Fatalf("AC-1 = %+v", ac)
		}
		if elapsed := time.Since(started); elapsed > 4*time.Second {
			t.Errorf("o sandbox não foi interrompido no prazo: %v", elapsed)
		}
	})

	t.Run("baseline excede o tempo", func(t *testing.T) {
		fixture, approval := causalRepo(t, "grep -q NEW src/lib.ts && exit 0; exec sleep 5")
		ac := findCheck(t, runWithTimeout(t, fixture, approval, 1), "AC-1")
		if ac.Outcome != "blocked" || !strings.Contains(ac.Reason, "baseline de AC-1") {
			t.Fatalf("AC-1 = %+v", ac)
		}
		if ac.Baseline == nil {
			t.Error("o baseline observado deve constar no resultado")
		}
	})

	t.Run("arquivo novo some no baseline", func(t *testing.T) {
		fixture, approval := causalRepo(t, "test -f src/extra.ts")
		writeFile(t, fixture.rootDir, "src/extra.ts", "export const extra = 1;\n")
		approval.ImplementationFiles = []string{implPath, "src/extra.ts", "src/inexistente.ts"}
		ac := findCheck(t, runWithTimeout(t, fixture, approval, 30), "AC-1")
		if ac.Outcome != "pass" || ac.Baseline == nil || ac.Baseline.ExitCode == 0 {
			t.Fatalf("AC-1 = %+v", ac)
		}
	})

	t.Run("arquivo do baseline não pode ser restaurado", func(t *testing.T) {
		fixture, approval := causalRepo(t, "grep -q NEW src/lib.ts")
		writeFile(t, fixture.rootDir, "velho/x.ts", "export {};\n")
		runGit(t, fixture.rootDir, "add", "-A")
		runGit(t, fixture.rootDir, "commit", "-q", "-m", "arquivo velho")
		if err := os.RemoveAll(filepath.Join(fixture.rootDir, "velho")); err != nil {
			t.Fatalf("remover o diretório: %v", err)
		}
		approval.BaselineCommit = strings.TrimSpace(runGit(t, fixture.rootDir, "rev-parse", "HEAD"))
		approval.ImplementationFiles = []string{implPath, "velho/x.ts"}
		_, err := verify.RunVerification(verify.RunVerificationOptions{
			RootDir:         fixture.rootDir,
			Approval:        approval,
			TimeoutSeconds:  30,
			VerifierRootDir: fixture.verifierRoot,
		})
		if err == nil || !strings.Contains(err.Error(), "gravar") {
			t.Fatalf("erro = %v, quer falha ao gravar o arquivo do baseline", err)
		}
	})
}

func TestRunVerificationPreconditions(t *testing.T) {
	t.Run("verificador sem configuração", func(t *testing.T) {
		fixture := buildRepo(t, repoOptions{})
		approval := approve(t, fixture)
		if err := os.Remove(verify.ConfigFile(fixture.verifierRoot)); err != nil {
			t.Fatalf("remover a configuração: %v", err)
		}
		_, err := verify.RunVerification(verify.RunVerificationOptions{RootDir: fixture.rootDir, Approval: approval, VerifierRootDir: fixture.verifierRoot})
		if !verify.IsUnavailable(err) || !strings.Contains(err.Error(), "não configurado") {
			t.Fatalf("erro = %v", err)
		}
	})

	t.Run("raiz do verificador dentro do repositório", func(t *testing.T) {
		fixture := buildRepo(t, repoOptions{})
		approval := approve(t, fixture)
		inside := filepath.Join(fixture.rootDir, "verificador")
		if _, err := verify.InitializeVerifierHome(inside); err != nil {
			t.Fatalf("inicializar: %v", err)
		}
		useFakeBwrap(t, inside)
		_, err := verify.RunVerification(verify.RunVerificationOptions{RootDir: fixture.rootDir, Approval: approval, VerifierRootDir: inside})
		if !verify.IsUnavailable(err) || !strings.Contains(err.Error(), "dentro do repositório") {
			t.Fatalf("erro = %v", err)
		}
	})

	t.Run("configuração de projeto malformada", func(t *testing.T) {
		fixture := fakeRepo(t, repoOptions{})
		approval := approve(t, fixture)
		setProject(t, fixture.verifierRoot, fixture.rootDir, map[string]any{"home": "relativo"})
		_, err := verify.RunVerification(verify.RunVerificationOptions{RootDir: fixture.rootDir, Approval: approval, VerifierRootDir: fixture.verifierRoot})
		if !verify.IsUnavailable(err) || !strings.Contains(err.Error(), ".home inválido") {
			t.Fatalf("erro = %v", err)
		}
	})

	t.Run("arquivo aprovado ausente na raiz protegida", func(t *testing.T) {
		fixture := fakeRepo(t, repoOptions{})
		approval := approve(t, fixture)
		if err := os.RemoveAll(filepath.Join(verify.ApprovalsDir(fixture.verifierRoot), approval.ApprovalID, "files")); err != nil {
			t.Fatalf("remover os arquivos aprovados: %v", err)
		}
		_, err := verify.RunVerification(verify.RunVerificationOptions{RootDir: fixture.rootDir, Approval: approval, VerifierRootDir: fixture.verifierRoot})
		if err == nil || !strings.Contains(err.Error(), "ausente na raiz protegida") {
			t.Fatalf("erro = %v", err)
		}
	})

	t.Run("arquivo aprovado corrompido na raiz protegida", func(t *testing.T) {
		fixture := fakeRepo(t, repoOptions{})
		approval := approve(t, fixture)
		stored := filepath.Join(verify.ApprovalFilesDir(approval.ApprovalID, fixture.verifierRoot), acPath)
		if err := os.WriteFile(stored, []byte("adulterado\n"), 0o600); err != nil {
			t.Fatalf("adulterar o arquivo aprovado: %v", err)
		}
		_, err := verify.RunVerification(verify.RunVerificationOptions{RootDir: fixture.rootDir, Approval: approval, VerifierRootDir: fixture.verifierRoot})
		if err == nil || !strings.Contains(err.Error(), "corrompido na raiz protegida") {
			t.Fatalf("erro = %v", err)
		}
	})

	t.Run("bwrap não executável", func(t *testing.T) {
		fixture := buildRepo(t, repoOptions{})
		approval := approve(t, fixture)
		notExecutable := filepath.Join(t.TempDir(), "bwrap")
		if err := os.WriteFile(notExecutable, []byte("texto\n"), 0o644); err != nil {
			t.Fatalf("gravar: %v", err)
		}
		configureVerifier(t, fixture.verifierRoot, "/bin/sh", notExecutable)
		_, err := verify.RunVerification(verify.RunVerificationOptions{RootDir: fixture.rootDir, Approval: approval, VerifierRootDir: fixture.verifierRoot})
		if !verify.IsUnavailable(err) || !strings.Contains(err.Error(), "não foi possível executar") {
			t.Fatalf("erro = %v", err)
		}
	})

	t.Run("execução cancelada durante o check", func(t *testing.T) {
		fixture, approval := causalRepo(t, "exec sleep 5")
		ctx, cancel := context.WithCancel(context.Background())
		time.AfterFunc(300*time.Millisecond, cancel)
		defer cancel()
		_, err := verify.RunVerification(verify.RunVerificationOptions{
			Ctx:             ctx,
			RootDir:         fixture.rootDir,
			Approval:        approval,
			TimeoutSeconds:  30,
			VerifierRootDir: fixture.verifierRoot,
		})
		if err == nil || !strings.Contains(err.Error(), "cancelada") {
			t.Fatalf("erro = %v, quer execução cancelada", err)
		}
	})

	t.Run("arquivo ilegível no snapshot", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root lê qualquer arquivo")
		}
		fixture := fakeRepo(t, repoOptions{})
		approval := approve(t, fixture)
		locked := filepath.Join(fixture.rootDir, "segredo.txt")
		writeFile(t, fixture.rootDir, "segredo.txt", "x")
		if err := os.Chmod(locked, 0); err != nil {
			t.Fatalf("chmod: %v", err)
		}
		t.Cleanup(func() { _ = os.Chmod(locked, 0o600) })
		_, err := verify.RunVerification(verify.RunVerificationOptions{RootDir: fixture.rootDir, Approval: approval, VerifierRootDir: fixture.verifierRoot})
		if err == nil || !strings.Contains(err.Error(), "segredo.txt") {
			t.Fatalf("erro = %v", err)
		}
	})
}

func TestAfterRunFullFlowWithFakeSandbox(t *testing.T) {
	fixture := fakeRepo(t, repoOptions{
		candidate:  newImplementation,
		baseline:   oldImplementation,
		acCommand:  "/usr/bin/grep -q NEW src/lib.ts",
		regression: "/usr/bin/grep -q NEW src/lib.ts",
	})
	approval := approve(t, fixture)
	options := verify.AfterRunOptions{
		RootDir:         fixture.rootDir,
		WorkID:          workID,
		TaskID:          taskID,
		TimeoutSeconds:  30,
		VerifierRootDir: fixture.verifierRoot,
	}

	verification, err := verify.AfterRun(options)
	if err != nil {
		t.Fatalf("verificação automática: %v", err)
	}
	if !verification.Attempted || verification.Outcome != "pass" || len(verification.ReceiptID) != 64 {
		t.Fatalf("verificação = %+v", verification)
	}
	latest := verify.LatestReceipt(workID, taskID, fixture.verifierRoot)
	if latest == nil || latest.ReceiptID != verification.ReceiptID || latest.ApprovalID != approval.ApprovalID {
		t.Fatalf("recibo corrente = %+v", latest)
	}
	if _, err := os.Stat(verify.ReceiptRepoCopy(fixture.rootDir, workID, taskID)); err != nil {
		t.Errorf("a cópia do recibo no repositório não foi gravada: %v", err)
	}
	evaluation := verify.EvaluateAcceptance(verify.EvaluateAcceptanceOptions{RootDir: fixture.rootDir, WorkID: workID, TaskID: taskID, VerifierRootDir: fixture.verifierRoot})
	if !evaluation.Accepted {
		t.Fatalf("avaliação = %+v", evaluation)
	}

	// Sem o recibo corrente, a cópia do repositório ainda é lida (e continua
	// valendo só se a assinatura confere).
	if err := os.Remove(filepath.Join(verify.ReceiptDir(fixture.verifierRoot), workID+"-"+taskID+".json")); err != nil {
		t.Fatalf("remover o recibo corrente: %v", err)
	}
	fromCopy := verify.EvaluateAcceptance(verify.EvaluateAcceptanceOptions{RootDir: fixture.rootDir, WorkID: workID, TaskID: taskID, VerifierRootDir: fixture.verifierRoot})
	if !fromCopy.Accepted || fromCopy.Receipt == nil || fromCopy.Receipt.ReceiptID != verification.ReceiptID {
		t.Fatalf("avaliação pela cópia = %+v", fromCopy)
	}

	// Trocar a implementação depois da avaliação invalida a autorização.
	writeFile(t, fixture.rootDir, implPath, wrongImplementation)
	changed := verify.EvaluateAcceptance(verify.EvaluateAcceptanceOptions{RootDir: fixture.rootDir, WorkID: workID, TaskID: taskID, VerifierRootDir: fixture.verifierRoot})
	if changed.Accepted || !strings.Contains(changed.Reason, "árvore mudou") {
		t.Errorf("avaliação após mudança = %+v", changed)
	}
}

func TestAfterRunFailureAndErrors(t *testing.T) {
	t.Run("resultado fail gera recibo fail", func(t *testing.T) {
		fixture := fakeRepo(t, repoOptions{candidate: newImplementation, baseline: oldImplementation, acCommand: "/usr/bin/grep -q WRONG src/lib.ts"})
		approve(t, fixture)
		verification, err := verify.AfterRun(verify.AfterRunOptions{RootDir: fixture.rootDir, WorkID: workID, TaskID: taskID, VerifierRootDir: fixture.verifierRoot})
		if err != nil {
			t.Fatalf("verificação automática: %v", err)
		}
		if verification.Outcome != "fail" || verification.ReceiptID == "" {
			t.Fatalf("verificação = %+v", verification)
		}
		evaluation := verify.EvaluateAcceptance(verify.EvaluateAcceptanceOptions{RootDir: fixture.rootDir, WorkID: workID, TaskID: taskID, VerifierRootDir: fixture.verifierRoot})
		if evaluation.Accepted || !strings.Contains(evaluation.Reason, "fail") {
			t.Errorf("avaliação = %+v", evaluation)
		}
	})

	t.Run("erro que não é indisponibilidade propaga", func(t *testing.T) {
		fixture := fakeRepo(t, repoOptions{})
		approval := approve(t, fixture)
		if err := os.RemoveAll(filepath.Join(verify.ApprovalsDir(fixture.verifierRoot), approval.ApprovalID, "files")); err != nil {
			t.Fatalf("remover os arquivos aprovados: %v", err)
		}
		verification, err := verify.AfterRun(verify.AfterRunOptions{RootDir: fixture.rootDir, WorkID: workID, TaskID: taskID, VerifierRootDir: fixture.verifierRoot})
		if err == nil || !strings.Contains(err.Error(), "ausente na raiz protegida") {
			t.Fatalf("erro = %v, verificação = %+v", err, verification)
		}
		if verification.Attempted {
			t.Errorf("verificação = %+v", verification)
		}
	})

	t.Run("sem chave privada o recibo não é assinado", func(t *testing.T) {
		fixture := fakeRepo(t, repoOptions{candidate: newImplementation, baseline: oldImplementation, acCommand: "/usr/bin/grep -q NEW src/lib.ts"})
		approve(t, fixture)
		if err := os.Remove(verify.PrivateKeyFile(fixture.verifierRoot)); err != nil {
			t.Fatalf("remover a chave privada: %v", err)
		}
		_, err := verify.AfterRun(verify.AfterRunOptions{RootDir: fixture.rootDir, WorkID: workID, TaskID: taskID, VerifierRootDir: fixture.verifierRoot})
		if err == nil || !strings.Contains(err.Error(), "não há chave privada") {
			t.Fatalf("erro = %v", err)
		}
	})

	t.Run("falha ao gravar o recibo propaga", func(t *testing.T) {
		fixture := fakeRepo(t, repoOptions{candidate: newImplementation, baseline: oldImplementation, acCommand: "/usr/bin/grep -q NEW src/lib.ts"})
		approve(t, fixture)
		receipts := verify.ReceiptDir(fixture.verifierRoot)
		if err := os.RemoveAll(receipts); err != nil {
			t.Fatalf("remover os recibos: %v", err)
		}
		if err := os.WriteFile(receipts, []byte("arquivo no lugar do diretório"), 0o600); err != nil {
			t.Fatalf("bloquear os recibos: %v", err)
		}
		_, err := verify.AfterRun(verify.AfterRunOptions{RootDir: fixture.rootDir, WorkID: workID, TaskID: taskID, VerifierRootDir: fixture.verifierRoot})
		if err == nil || !strings.Contains(err.Error(), "verifier:") {
			t.Fatalf("erro = %v", err)
		}
	})
}

func TestWarmOverlays(t *testing.T) {
	prepare := func(t *testing.T) (repoFixture, string) {
		t.Helper()
		fixture := fakeRepo(t, repoOptions{})
		cache := filepath.Join(t.TempDir(), "cache", "go")
		setProject(t, fixture.verifierRoot, fixture.rootDir, map[string]any{
			"overlays": []map[string]string{{"source": cache, "dest": "/cache/go"}},
		})
		return fixture, cache
	}

	t.Run("executa o comando e cria a origem do overlay", func(t *testing.T) {
		fixture, cache := prepare(t)
		result, err := verify.WarmOverlays(verify.WarmOptions{
			RootDir:         fixture.rootDir,
			Command:         []string{"/bin/sh", "-c", "echo aquecido; exit 3"},
			VerifierRootDir: fixture.verifierRoot,
		})
		if err != nil {
			t.Fatalf("aquecer: %v", err)
		}
		if result.Status != 3 || result.TimedOut || result.Output != "aquecido\n" {
			t.Errorf("resultado = %+v", result)
		}
		if len(result.Overlays) != 1 || result.Overlays[0].Source != cache || result.Overlays[0].Dest != "/cache/go" {
			t.Errorf("overlays = %+v", result.Overlays)
		}
		if len(result.Command) != 3 || result.Duration <= 0 {
			t.Errorf("comando/duração = %v %v", result.Command, result.Duration)
		}
		if !verify.IsDirectory(cache) {
			t.Errorf("a origem do overlay %s não foi criada", cache)
		}
	})

	t.Run("comando padrão de projeto Go", func(t *testing.T) {
		fixture, _ := prepare(t)
		writeFile(t, fixture.rootDir, "go.mod", "module exemplo\n")
		if command := verify.DefaultWarmCommand(fixture.rootDir); strings.Join(command, " ") != "go build std" {
			t.Fatalf("comando padrão = %v", command)
		}
		binDir := t.TempDir()
		writeScript(t, binDir, "go", "#!/bin/sh\necho \"go $*\"\n")
		t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
		result, err := verify.WarmOverlays(verify.WarmOptions{RootDir: fixture.rootDir, VerifierRootDir: fixture.verifierRoot})
		if err != nil {
			t.Fatalf("aquecer: %v", err)
		}
		if result.Status != 0 || !strings.HasPrefix(result.Output, "go build std\n") {
			t.Errorf("resultado = %+v", result)
		}
	})

	t.Run("tempo excedido", func(t *testing.T) {
		fixture, _ := prepare(t)
		result, err := verify.WarmOverlays(verify.WarmOptions{
			RootDir:         fixture.rootDir,
			Command:         []string{"sleep", "5"},
			TimeoutSeconds:  1,
			VerifierRootDir: fixture.verifierRoot,
		})
		if err != nil {
			t.Fatalf("aquecer: %v", err)
		}
		if !result.TimedOut {
			t.Errorf("resultado = %+v, quer TimedOut", result)
		}
	})

	t.Run("tipo de projeto desconhecido", func(t *testing.T) {
		fixture, _ := prepare(t)
		if command := verify.DefaultWarmCommand(fixture.rootDir); command != nil {
			t.Fatalf("comando padrão = %v, quer nil", command)
		}
		_, err := verify.WarmOverlays(verify.WarmOptions{RootDir: fixture.rootDir, VerifierRootDir: fixture.verifierRoot})
		if err == nil || !strings.Contains(err.Error(), "tipo de projeto desconhecido") {
			t.Fatalf("erro = %v", err)
		}
	})

	t.Run("projeto sem overlays", func(t *testing.T) {
		fixture := fakeRepo(t, repoOptions{})
		_, err := verify.WarmOverlays(verify.WarmOptions{RootDir: fixture.rootDir, Command: []string{"true"}, VerifierRootDir: fixture.verifierRoot})
		if !verify.IsUnavailable(err) || !strings.Contains(err.Error(), "não declara overlays") {
			t.Fatalf("erro = %v", err)
		}
		var unavailable *verify.VerificationUnavailable
		if !errors.As(err, &unavailable) || !strings.Contains(unavailable.Detail, "overlays") {
			t.Errorf("detalhe = %+v", unavailable)
		}
	})

	t.Run("verificador não pronto", func(t *testing.T) {
		fixture := buildRepo(t, repoOptions{})
		configureVerifier(t, fixture.verifierRoot, "/bin/sh", filepath.Join(t.TempDir(), "sem-bwrap"))
		_, err := verify.WarmOverlays(verify.WarmOptions{RootDir: fixture.rootDir, Command: []string{"true"}, VerifierRootDir: fixture.verifierRoot})
		if !verify.IsUnavailable(err) || !strings.Contains(err.Error(), "isolamento indisponível") {
			t.Fatalf("erro = %v", err)
		}
	})

	t.Run("raiz do verificador dentro do repositório", func(t *testing.T) {
		fixture := buildRepo(t, repoOptions{})
		inside := filepath.Join(fixture.rootDir, "verificador")
		if _, err := verify.InitializeVerifierHome(inside); err != nil {
			t.Fatalf("inicializar: %v", err)
		}
		useFakeBwrap(t, inside)
		_, err := verify.WarmOverlays(verify.WarmOptions{RootDir: fixture.rootDir, Command: []string{"true"}, VerifierRootDir: inside})
		if !verify.IsUnavailable(err) || !strings.Contains(err.Error(), "dentro do repositório") {
			t.Fatalf("erro = %v", err)
		}
	})

	t.Run("configuração de projeto malformada", func(t *testing.T) {
		fixture := fakeRepo(t, repoOptions{})
		setProject(t, fixture.verifierRoot, fixture.rootDir, []string{"não é objeto"})
		_, err := verify.WarmOverlays(verify.WarmOptions{RootDir: fixture.rootDir, Command: []string{"true"}, VerifierRootDir: fixture.verifierRoot})
		if !verify.IsUnavailable(err) || !strings.Contains(err.Error(), "inválido") {
			t.Fatalf("erro = %v", err)
		}
	})

	t.Run("origem do overlay não pode ser criada", func(t *testing.T) {
		fixture := fakeRepo(t, repoOptions{})
		blocker := filepath.Join(t.TempDir(), "arquivo")
		if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
			t.Fatalf("gravar: %v", err)
		}
		setProject(t, fixture.verifierRoot, fixture.rootDir, map[string]any{
			"overlays": []map[string]string{{"source": filepath.Join(blocker, "cache"), "dest": "/cache"}},
		})
		_, err := verify.WarmOverlays(verify.WarmOptions{RootDir: fixture.rootDir, Command: []string{"true"}, VerifierRootDir: fixture.verifierRoot})
		if err == nil || !strings.Contains(err.Error(), "criar") {
			t.Fatalf("erro = %v", err)
		}
	})

	t.Run("bwrap não executável", func(t *testing.T) {
		fixture, _ := prepare(t)
		notExecutable := filepath.Join(t.TempDir(), "bwrap")
		if err := os.WriteFile(notExecutable, []byte("texto\n"), 0o644); err != nil {
			t.Fatalf("gravar: %v", err)
		}
		configureVerifier(t, fixture.verifierRoot, "/bin/sh", notExecutable)
		_, err := verify.WarmOverlays(verify.WarmOptions{RootDir: fixture.rootDir, Command: []string{"true"}, VerifierRootDir: fixture.verifierRoot})
		if !verify.IsUnavailable(err) || !strings.Contains(err.Error(), "não foi possível executar") {
			t.Fatalf("erro = %v", err)
		}
	})
}
