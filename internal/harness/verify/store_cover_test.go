package verify_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/passoz/pwn/internal/harness/plan"
	"github.com/passoz/pwn/internal/harness/verify"
)

func createOptions(fixture repoFixture) verify.CreateApprovalOptions {
	return verify.CreateApprovalOptions{
		RootDir:         fixture.rootDir,
		WorkID:          workID,
		TaskID:          taskID,
		ApprovedBy:      "operator",
		VerifierRootDir: fixture.verifierRoot,
	}
}

func rewriteFile(t *testing.T, rootDir, relative, from, to string) {
	t.Helper()
	text, err := readText(rootDir, relative)
	if err != nil {
		t.Fatalf("ler %s: %v", relative, err)
	}
	if !strings.Contains(text, from) {
		t.Fatalf("%s não contém %q", relative, from)
	}
	writeFile(t, rootDir, relative, strings.Replace(text, from, to, 1))
}

func TestApprovalStoreIgnoresInvalidRecords(t *testing.T) {
	root := newVerifier(t)
	approvals := verify.ApprovalsDir(root)

	if got := verify.ReadApproval("ausente", root); got != nil {
		t.Errorf("aprovação ausente = %+v", got)
	}
	writeFile(t, approvals, "quebrada.json", "{")
	if got := verify.ReadApproval("quebrada", root); got != nil {
		t.Errorf("JSON inválido = %+v", got)
	}
	writeFile(t, approvals, "outra-versao.json", `{"version":2,"approval_id":"outra-versao"}`)
	if got := verify.ReadApproval("outra-versao", root); got != nil {
		t.Errorf("versão 2 = %+v", got)
	}
	writeFile(t, approvals, "valida.json", `{"version":1,"approval_id":"valida","work_id":"0001","task_id":"1.1"}`)
	if got := verify.ReadApproval("valida", root); got == nil || got.TaskID != "1.1" {
		t.Errorf("aprovação válida = %+v", got)
	}

	if _, ok := verify.ApprovedFileContent(verify.Approval{ApprovalID: "valida"}, "tests/x.ts", root); ok {
		t.Error("arquivo aprovado inexistente não pode ser devolvido")
	}

	// Índice ilegível, de outra versão ou sem mapa equivale a nenhuma aprovação.
	for label, content := range map[string]string{
		"json inválido":  "{",
		"outra versão":   `{"version":2,"current":{"0001:1.1":"valida"}}`,
		"sem mapa":       `{"version":1}`,
		"id vazio":       `{"version":1,"current":{"0001:1.1":""}}`,
		"id inexistente": `{"version":1,"current":{"0001:1.1":"fantasma"}}`,
	} {
		writeFile(t, approvals, "index.json", content)
		if got := verify.CurrentApproval("0001", "1.1", root); got != nil {
			t.Errorf("%s: aprovação vigente = %+v", label, got)
		}
		if got := verify.ListApprovals(root); len(got) != 0 {
			t.Errorf("%s: lista = %+v", label, got)
		}
	}

	writeFile(t, approvals, "index.json", `{"version":1,"current":{"0001:2.1":"fantasma","0001:1.1":"valida"}}`)
	listed := verify.ListApprovals(root)
	if len(listed) != 1 || listed[0].ApprovalID != "valida" {
		t.Errorf("a lista deve pular ids sem pacote: %+v", listed)
	}
}

func TestCreateApprovalPlanErrors(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(t *testing.T, fixture repoFixture)
		want   string
	}{
		{"plano ausente", func(t *testing.T, f repoFixture) {
			if err := os.Remove(filepath.Join(f.rootDir, ".todo", workID+"-tasks.md")); err != nil {
				t.Fatal(err)
			}
		}, "plano não encontrado"},
		{"repositório sem git", func(t *testing.T, f repoFixture) {
			if err := os.RemoveAll(filepath.Join(f.rootDir, ".git")); err != nil {
				t.Fatal(err)
			}
		}, "git rev-parse HEAD falhou"},
		{"task inexistente", func(t *testing.T, f repoFixture) {
			rewriteFile(t, f.rootDir, ".todo/"+workID+"-tasks.md", "### [ ] [1.1]", "### [ ] [7.7]")
		}, "task 1.1 não encontrada"},
		{"AC sem comando", func(t *testing.T, f repoFixture) {
			rewriteFile(t, f.rootDir, ".todo/"+workID+"-tasks.md", "- [ ] `/usr/bin/true` — value() satisfaz o AC", "- [ ] `\"\"` — value() satisfaz o AC")
		}, "AC-1: comando vazio no plano"},
		{"plano sem comando de regressão", func(t *testing.T, f repoFixture) {
			rewriteFile(t, f.rootDir, ".todo/"+workID+"-tasks.md", "| core | `N/A` | `/usr/bin/true` |", "| core | `N/A` | `N/A` |")
		}, "REGRESSION"},
		{"sem arquivos de implementação", func(t *testing.T, f repoFixture) {
			rewriteFile(t, f.rootDir, ".todo/"+workID+"-tasks.md", "**Implementation files:** `src/lib.ts`", "**Implementation files:** N/A")
		}, "não declara arquivos de implementação"},
		{"plan.json sem contract_id", func(t *testing.T, f repoFixture) {
			rewritePlanJSON(t, f.rootDir, func(p *plan.Plan) { p.Tasks[0].ContractID = "" })
		}, "não vincula contract_id"},
		{"plan.json ausente", func(t *testing.T, f repoFixture) {
			if err := os.Remove(filepath.Join(f.rootDir, ".pwn", "work", workID, "plan.json")); err != nil {
				t.Fatal(err)
			}
		}, "não vincula contract_id"},
		{"contrato ausente", func(t *testing.T, f repoFixture) {
			if err := os.Remove(filepath.Join(f.rootDir, ".pwn", "work", workID, "CTR-001.json")); err != nil {
				t.Fatal(err)
			}
		}, "CTR-001 não encontrado"},
		{"contrato de outra versão", func(t *testing.T, f repoFixture) {
			rewriteFile(t, f.rootDir, ".pwn/work/"+workID+"/CTR-001.json", `"contract_version": "4.0"`, `"contract_version": "3.0"`)
		}, "não é V4"},
		{"teste de aceitação ausente no repositório", func(t *testing.T, f repoFixture) {
			if err := os.Remove(filepath.Join(f.rootDir, acPath)); err != nil {
				t.Fatal(err)
			}
		}, "ausente no repositório"},
		{"teste de aceitação é um diretório", func(t *testing.T, f repoFixture) {
			if err := os.Remove(filepath.Join(f.rootDir, acPath)); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(filepath.Join(f.rootDir, acPath), 0o755); err != nil {
				t.Fatal(err)
			}
		}, "ausente no repositório"},
		{"commit de referência inexistente", func(t *testing.T, f repoFixture) {}, "git rev-parse --verify"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fixture := buildRepo(t, repoOptions{})
			tc.mutate(t, fixture)
			options := createOptions(fixture)
			if tc.name == "commit de referência inexistente" {
				options.BaselineCommit = "nao-existe-no-repositorio"
			}
			_, err := verify.CreateApproval(options)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("erro = %v, quer conter %q", err, tc.want)
			}
			if verify.CurrentApproval(workID, taskID, fixture.verifierRoot) != nil {
				t.Error("uma aprovação recusada não pode virar vigente")
			}
		})
	}
}

func rewritePlanJSON(t *testing.T, rootDir string, mutate func(*plan.Plan)) {
	t.Helper()
	path := filepath.Join(rootDir, ".pwn", "work", workID, "plan.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ler o plano: %v", err)
	}
	var workPlan plan.Plan
	if err := json.Unmarshal(data, &workPlan); err != nil {
		t.Fatalf("decodificar o plano: %v", err)
	}
	mutate(&workPlan)
	rendered, err := json.Marshal(workPlan)
	if err != nil {
		t.Fatalf("serializar o plano: %v", err)
	}
	if err := os.WriteFile(path, rendered, 0o644); err != nil {
		t.Fatalf("gravar o plano: %v", err)
	}
}

func TestCreateApprovalGlobalGateErrors(t *testing.T) {
	t.Run("gate sem comando executável", func(t *testing.T) {
		fixture := buildRepo(t, repoOptions{globalGates: []string{"G-1 revisar manualmente"}})
		options := createOptions(fixture)
		options.TaskID, options.Global = "", "G-1"
		_, err := verify.CreateApproval(options)
		if err == nil || !strings.Contains(err.Error(), "não declara comando executável") {
			t.Fatalf("erro = %v", err)
		}
	})

	for _, name := range []string{"G-0", "gate", "G-x"} {
		t.Run("nome inválido "+name, func(t *testing.T) {
			fixture := buildRepo(t, repoOptions{globalGates: []string{"G-1 `true`"}})
			options := createOptions(fixture)
			options.TaskID, options.Global = "", name
			_, err := verify.CreateApproval(options)
			if err == nil || !strings.Contains(err.Error(), "não existe no plano") {
				t.Fatalf("erro = %v", err)
			}
		})
	}

	t.Run("comando só com aspas vazias", func(t *testing.T) {
		fixture := buildRepo(t, repoOptions{globalGates: []string{"G-1 `\"\"`"}})
		options := createOptions(fixture)
		options.TaskID, options.Global = "", "G-1"
		_, err := verify.CreateApproval(options)
		if err == nil || !strings.Contains(err.Error(), "G-1: comando vazio no plano") {
			t.Fatalf("erro = %v", err)
		}
	})

	t.Run("segundo gate vira aprovação própria", func(t *testing.T) {
		fixture := buildRepo(t, repoOptions{globalGates: []string{"G-1 `/usr/bin/true`", "G-2 `/usr/bin/env FOO=\"a b\" true`"}})
		options := createOptions(fixture)
		options.TaskID, options.Global = "", "G-2"
		approval, err := verify.CreateApproval(options)
		if err != nil {
			t.Fatalf("aprovar G-2: %v", err)
		}
		want := []string{"/usr/bin/env", "FOO=a b", "true"}
		if len(approval.Checks) != 1 || strings.Join(approval.Checks[0].Command, "|") != strings.Join(want, "|") {
			t.Errorf("comando = %v, quer %v", approval.Checks, want)
		}
		if verify.CurrentApproval(workID, "G-2", fixture.verifierRoot) == nil || verify.CurrentApproval(workID, "G-1", fixture.verifierRoot) != nil {
			t.Error("só G-2 deveria estar vigente")
		}
	})
}

func TestCreateApprovalBaselineCommit(t *testing.T) {
	t.Run("ancestral vira o commit de referência", func(t *testing.T) {
		fixture := buildRepo(t, repoOptions{candidate: newImplementation, baseline: oldImplementation})
		first := strings.TrimSpace(runGit(t, fixture.rootDir, "rev-parse", "HEAD"))
		runGit(t, fixture.rootDir, "add", "-A")
		runGit(t, fixture.rootDir, "commit", "-q", "-m", "implementação")
		head := strings.TrimSpace(runGit(t, fixture.rootDir, "rev-parse", "HEAD"))

		options := createOptions(fixture)
		options.BaselineCommit = first
		approval, err := verify.CreateApproval(options)
		if err != nil {
			t.Fatalf("aprovar: %v", err)
		}
		if approval.BaselineCommit != first || first == head {
			t.Errorf("baseline = %s, quer %s (HEAD %s)", approval.BaselineCommit, first, head)
		}
	})

	t.Run("commit fora do histórico do HEAD", func(t *testing.T) {
		fixture := buildRepo(t, repoOptions{})
		original := strings.TrimSpace(runGit(t, fixture.rootDir, "rev-parse", "HEAD"))
		runGit(t, fixture.rootDir, "checkout", "-q", "--orphan", "paralelo")
		runGit(t, fixture.rootDir, "commit", "-q", "-m", "histórico paralelo")

		options := createOptions(fixture)
		options.BaselineCommit = original
		_, err := verify.CreateApproval(options)
		if err == nil || !strings.Contains(err.Error(), "não é ancestral do HEAD") {
			t.Fatalf("erro = %v", err)
		}
	})
}

func TestCreateApprovalStorageErrors(t *testing.T) {
	t.Run("raiz do verificador sob um arquivo", func(t *testing.T) {
		fixture := buildRepo(t, repoOptions{})
		blocker := filepath.Join(t.TempDir(), "arquivo")
		if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		options := createOptions(fixture)
		options.VerifierRootDir = filepath.Join(blocker, "verificador")
		if _, err := verify.CreateApproval(options); err == nil || !strings.Contains(err.Error(), "criar") {
			t.Fatalf("erro = %v", err)
		}
	})

	t.Run("raiz do verificador dentro do repositório", func(t *testing.T) {
		fixture := buildRepo(t, repoOptions{})
		options := createOptions(fixture)
		options.VerifierRootDir = filepath.Join(fixture.rootDir, "verificador")
		_, err := verify.CreateApproval(options)
		if !verify.IsUnavailable(err) {
			t.Fatalf("erro = %v, quer VerificationUnavailable", err)
		}
	})

	t.Run("índice não pode ser publicado", func(t *testing.T) {
		fixture := buildRepo(t, repoOptions{})
		indexPath := filepath.Join(verify.ApprovalsDir(fixture.verifierRoot), "index.json")
		if err := os.MkdirAll(filepath.Join(indexPath, "ocupado"), 0o755); err != nil {
			t.Fatal(err)
		}
		_, err := verify.CreateApproval(createOptions(fixture))
		if err == nil || !strings.Contains(err.Error(), "publicar") {
			t.Fatalf("erro = %v", err)
		}
	})
}

func TestSnapshotErrorsAndSpecialFiles(t *testing.T) {
	t.Run("fifo não entra no snapshot", func(t *testing.T) {
		rootDir := t.TempDir()
		writeFile(t, rootDir, "a.txt", "a")
		before, err := verify.CaptureSnapshot(rootDir)
		if err != nil {
			t.Fatal(err)
		}
		if err := syscall.Mkfifo(filepath.Join(rootDir, "canal"), 0o600); err != nil {
			t.Skipf("mkfifo indisponível: %v", err)
		}
		after, err := verify.CaptureSnapshot(rootDir)
		if err != nil {
			t.Fatal(err)
		}
		if after.Digest != before.Digest || len(after.Files) != 1 {
			t.Errorf("snapshot com fifo = %+v, antes = %+v", after.Files, before.Files)
		}
	})

	t.Run("vínculo simbólico é registrado sem seguir", func(t *testing.T) {
		rootDir := t.TempDir()
		writeFile(t, rootDir, "alvo.txt", "a")
		if err := os.Symlink("alvo.txt", filepath.Join(rootDir, "link")); err != nil {
			t.Fatal(err)
		}
		snapshot, err := verify.CaptureSnapshot(rootDir)
		if err != nil {
			t.Fatal(err)
		}
		var link *verify.SnapshotEntry
		for i := range snapshot.Files {
			if snapshot.Files[i].Path == "link" {
				link = &snapshot.Files[i]
			}
		}
		if link == nil || link.Kind != "symlink" || link.Target == nil || *link.Target != "alvo.txt" || link.SHA256 != nil {
			t.Fatalf("entrada do vínculo = %+v", link)
		}
	})

	t.Run("diretório e arquivo ilegíveis", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root lê qualquer caminho")
		}
		rootDir := t.TempDir()
		writeFile(t, rootDir, "fechado/x.txt", "x")
		closed := filepath.Join(rootDir, "fechado")
		if err := os.Chmod(closed, 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(closed, 0o755) })
		if _, err := verify.CaptureSnapshot(rootDir); err == nil || !strings.Contains(err.Error(), "fechado") {
			t.Errorf("erro = %v", err)
		}
	})

	t.Run("raiz inexistente", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "nada")
		if _, err := verify.CaptureSnapshot(missing); err == nil {
			t.Error("snapshot de raiz inexistente deveria falhar")
		}
		if _, err := verify.CurrentTreeDigest(missing); err == nil {
			t.Error("digest de raiz inexistente deveria falhar")
		}
	})

	t.Run("dependências", func(t *testing.T) {
		rootDir := t.TempDir()
		if got := verify.PresentDependencyPaths(rootDir); len(got) != 0 {
			t.Errorf("sem node_modules: %v", got)
		}
		writeFile(t, rootDir, "node_modules/x.js", "x")
		got := verify.PresentDependencyPaths(rootDir)
		if len(got) != 1 || got[0] != filepath.Join(rootDir, "node_modules") {
			t.Errorf("com node_modules: %v", got)
		}
		// Manifesto que é diretório não conta como presente.
		if err := os.Mkdir(filepath.Join(rootDir, "package.json"), 0o755); err != nil {
			t.Fatal(err)
		}
		digest, err := verify.CaptureDependencyDigest(rootDir)
		if err != nil {
			t.Fatal(err)
		}
		for _, file := range digest.Files {
			if file.Path == "package.json" && file.SHA256 != nil {
				t.Errorf("package.json diretório = %+v", file)
			}
		}
	})

	t.Run("manifesto ilegível", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root lê qualquer arquivo")
		}
		rootDir := t.TempDir()
		writeFile(t, rootDir, "package.json", "{}")
		if err := os.Chmod(filepath.Join(rootDir, "package.json"), 0); err != nil {
			t.Fatal(err)
		}
		if _, err := verify.CaptureDependencyDigest(rootDir); err == nil || !strings.Contains(err.Error(), "package.json") {
			t.Errorf("erro = %v", err)
		}
	})
}

func TestMaterializeSnapshotErrors(t *testing.T) {
	source := t.TempDir()
	writeFile(t, source, "a.txt", "a")
	if err := os.Symlink("a.txt", filepath.Join(source, "link")); err != nil {
		t.Fatal(err)
	}
	snapshot, err := verify.CaptureSnapshot(source)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("origem sem o arquivo registrado", func(t *testing.T) {
		if err := verify.MaterializeSnapshot(snapshot, t.TempDir(), t.TempDir()); err == nil || !strings.Contains(err.Error(), "ler") {
			t.Errorf("erro = %v", err)
		}
	})

	t.Run("destino já tem o vínculo", func(t *testing.T) {
		destination := t.TempDir()
		if err := verify.MaterializeSnapshot(snapshot, destination, source); err != nil {
			t.Fatalf("primeira materialização: %v", err)
		}
		if target, err := os.Readlink(filepath.Join(destination, "link")); err != nil || target != "a.txt" {
			t.Errorf("vínculo = %q, %v", target, err)
		}
		if err := verify.MaterializeSnapshot(snapshot, destination, source); err == nil || !strings.Contains(err.Error(), "vínculo") {
			t.Errorf("erro = %v, quer falha ao recriar o vínculo", err)
		}
	})

	t.Run("destino sob um arquivo", func(t *testing.T) {
		blocker := filepath.Join(t.TempDir(), "arquivo")
		if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := verify.MaterializeSnapshot(snapshot, filepath.Join(blocker, "d"), source); err == nil || !strings.Contains(err.Error(), "criar") {
			t.Errorf("erro = %v", err)
		}
	})
}

func TestReceiptEvaluationEdgeCases(t *testing.T) {
	evaluate := func(fixture repoFixture) verify.AcceptanceEvaluation {
		return verify.EvaluateAcceptance(verify.EvaluateAcceptanceOptions{RootDir: fixture.rootDir, WorkID: workID, TaskID: taskID, VerifierRootDir: fixture.verifierRoot})
	}
	issue := func(t *testing.T, fixture repoFixture, approval verify.Approval, result verify.VerificationRunResult) verify.VerificationReceipt {
		t.Helper()
		receipt, err := verify.BuildReceipt(verify.BuildReceiptOptions{Approval: approval, Result: result, VerifierRootDir: fixture.verifierRoot})
		if err != nil {
			t.Fatalf("montar o recibo: %v", err)
		}
		if _, err := verify.StoreReceipt(receipt, fixture.rootDir, fixture.verifierRoot); err != nil {
			t.Fatalf("gravar o recibo: %v", err)
		}
		return receipt
	}

	t.Run("recibo de outra aprovação", func(t *testing.T) {
		fixture := buildRepo(t, repoOptions{})
		approval := approve(t, fixture)
		stale := approval
		stale.ApprovalID = verify.DigestOfText("aprovação anterior")
		issue(t, fixture, stale, passingResult(t, fixture.rootDir))
		if got := evaluate(fixture); got.Accepted || !strings.Contains(got.Reason, "aprovação anterior") {
			t.Errorf("avaliação = %+v", got)
		}
	})

	t.Run("recibo que não é de aceitação independente", func(t *testing.T) {
		fixture := buildRepo(t, repoOptions{})
		approve(t, fixture)
		writeFile(t, verify.ReceiptDir(fixture.verifierRoot), workID+"-"+taskID+".json", `{"version":1,"kind":"outro"}`)
		if verify.LatestReceipt(workID, taskID, fixture.verifierRoot) != nil {
			t.Error("recibo de outro tipo não pode ser lido")
		}
		writeFile(t, verify.ReceiptDir(fixture.verifierRoot), workID+"-"+taskID+".json", `{`)
		if verify.LatestReceipt(workID, taskID, fixture.verifierRoot) != nil {
			t.Error("recibo ilegível não pode ser lido")
		}
		if got := evaluate(fixture); got.Accepted || !strings.Contains(got.Reason, "sem recibo") {
			t.Errorf("avaliação = %+v", got)
		}
	})

	t.Run("cópia ilegível no repositório", func(t *testing.T) {
		fixture := buildRepo(t, repoOptions{})
		approve(t, fixture)
		writeFile(t, fixture.rootDir, ".todo/verification/"+workID+"-"+taskID+"-receipt.json", `{"version":9}`)
		if got := evaluate(fixture); got.Accepted || !strings.Contains(got.Reason, "sem recibo") {
			t.Errorf("avaliação = %+v", got)
		}
	})

	t.Run("recibo de outro verificador", func(t *testing.T) {
		fixture := buildRepo(t, repoOptions{})
		approval := approve(t, fixture)
		receipt := issue(t, fixture, approval, passingResult(t, fixture.rootDir))
		receipt.Verifier.PublicKeyFingerprint = verify.DigestOfText("outro verificador")
		if err := verify.WriteJSONAtomic(filepath.Join(verify.ReceiptDir(fixture.verifierRoot), workID+"-"+taskID+".json"), receipt); err != nil {
			t.Fatal(err)
		}
		if got := evaluate(fixture); got.Accepted || !strings.Contains(got.Reason, "verificador desconhecido") {
			t.Errorf("avaliação = %+v", got)
		}
	})

	t.Run("dependências mudaram", func(t *testing.T) {
		fixture := buildRepo(t, repoOptions{})
		approval := approve(t, fixture)
		issue(t, fixture, approval, passingResult(t, fixture.rootDir))
		writeFile(t, fixture.rootDir, "package.json", `{"dependencies":{"x":"1"}}`)
		// package.json entra no snapshot e nos manifestos; a árvore muda primeiro.
		if got := evaluate(fixture); got.Accepted || !strings.Contains(got.Reason, "mudou") {
			t.Errorf("avaliação = %+v", got)
		}
	})

	t.Run("somente as dependências mudaram", func(t *testing.T) {
		fixture := buildRepo(t, repoOptions{})
		approval := approve(t, fixture)
		result := passingResult(t, fixture.rootDir)
		result.DependencyDigest = verify.DigestOfText("outras dependências")
		issue(t, fixture, approval, result)
		if got := evaluate(fixture); got.Accepted || !strings.Contains(got.Reason, "as dependências mudaram") {
			t.Errorf("avaliação = %+v", got)
		}
	})

	t.Run("snapshot ilegível na avaliação", func(t *testing.T) {
		fixture := buildRepo(t, repoOptions{})
		approval := approve(t, fixture)
		issue(t, fixture, approval, passingResult(t, fixture.rootDir))
		if err := os.RemoveAll(filepath.Join(fixture.rootDir, "src")); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(fixture.rootDir, "src"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		// A árvore existe mas é diferente: a recusa cita a mudança.
		if got := evaluate(fixture); got.Accepted || !strings.Contains(got.Reason, "mudou") {
			t.Errorf("avaliação = %+v", got)
		}
	})
}

func TestReceiptOutcomeAggregation(t *testing.T) {
	check := func(outcome string) verify.CheckObservation {
		return verify.CheckObservation{ID: "AC-1", Outcome: outcome}
	}
	cases := []struct {
		name   string
		checks []verify.CheckObservation
		want   string
	}{
		{"sem checks bloqueia", nil, "blocked"},
		{"tudo passa", []verify.CheckObservation{check("pass"), check("pass")}, "pass"},
		{"uma falha", []verify.CheckObservation{check("pass"), check("fail")}, "fail"},
		{"bloqueio vence a falha", []verify.CheckObservation{check("fail"), check("blocked")}, "blocked"},
	}
	for _, tc := range cases {
		if got := verify.ReceiptOutcome(verify.VerificationRunResult{Checks: tc.checks}); got != tc.want {
			t.Errorf("%s: outcome = %q, quer %q", tc.name, got, tc.want)
		}
	}
}

func TestBuildReceiptSummarizesBaseline(t *testing.T) {
	fixture := buildRepo(t, repoOptions{})
	approval := approve(t, fixture)
	result := passingResult(t, fixture.rootDir)
	result.Checks[0].Baseline = &verify.BaselineObservation{ExitCode: 7, SuspectEnvironmental: true}
	receipt, err := verify.BuildReceipt(verify.BuildReceiptOptions{Approval: approval, Result: result, VerifierRootDir: fixture.verifierRoot})
	if err != nil {
		t.Fatal(err)
	}
	summary := receipt.Checks[0]
	if summary.BaselineExitCode == nil || *summary.BaselineExitCode != 7 || !summary.BaselineSuspectEnvironmental {
		t.Errorf("resumo = %+v", summary)
	}
	if receipt.Verifier.ID == "" {
		t.Error("o recibo deve identificar o verificador")
	}

	t.Run("sem configuração não assina", func(t *testing.T) {
		if err := os.Remove(verify.ConfigFile(fixture.verifierRoot)); err != nil {
			t.Fatal(err)
		}
		_, err := verify.BuildReceipt(verify.BuildReceiptOptions{Approval: approval, Result: result, VerifierRootDir: fixture.verifierRoot})
		if err == nil || !strings.Contains(err.Error(), "não há chave privada") {
			t.Errorf("erro = %v", err)
		}
	})
}

func TestStoreReceiptErrors(t *testing.T) {
	build := func(t *testing.T) (repoFixture, verify.VerificationReceipt) {
		t.Helper()
		fixture := buildRepo(t, repoOptions{})
		approval := approve(t, fixture)
		receipt, err := verify.BuildReceipt(verify.BuildReceiptOptions{Approval: approval, Result: passingResult(t, fixture.rootDir), VerifierRootDir: fixture.verifierRoot})
		if err != nil {
			t.Fatal(err)
		}
		return fixture, receipt
	}

	t.Run("histórico bloqueado", func(t *testing.T) {
		fixture, receipt := build(t)
		if err := os.WriteFile(filepath.Join(verify.ReceiptDir(fixture.verifierRoot), "history"), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := verify.StoreReceipt(receipt, fixture.rootDir, fixture.verifierRoot); err == nil || !strings.Contains(err.Error(), "verifier:") {
			t.Errorf("erro = %v", err)
		}
	})

	t.Run("rota corrente bloqueada", func(t *testing.T) {
		fixture, receipt := build(t)
		current := filepath.Join(verify.ReceiptDir(fixture.verifierRoot), workID+"-"+taskID+".json")
		if err := os.MkdirAll(filepath.Join(current, "ocupado"), 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := verify.StoreReceipt(receipt, fixture.rootDir, fixture.verifierRoot); err == nil || !strings.Contains(err.Error(), "publicar") {
			t.Errorf("erro = %v", err)
		}
	})

	t.Run("cópia no repositório bloqueada", func(t *testing.T) {
		fixture, receipt := build(t)
		if err := os.WriteFile(filepath.Join(fixture.rootDir, ".todo", "verification"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := verify.StoreReceipt(receipt, fixture.rootDir, fixture.verifierRoot); err == nil || !strings.Contains(err.Error(), "criar") {
			t.Errorf("erro = %v", err)
		}
	})

	t.Run("cópia no repositório é um diretório", func(t *testing.T) {
		fixture, receipt := build(t)
		copyPath := verify.ReceiptRepoCopy(fixture.rootDir, workID, taskID)
		if err := os.MkdirAll(filepath.Join(copyPath, "ocupado"), 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := verify.StoreReceipt(receipt, fixture.rootDir, fixture.verifierRoot); err == nil || !strings.Contains(err.Error(), "publicar") {
			t.Errorf("erro = %v", err)
		}
	})
}

func TestVerifierRootResolution(t *testing.T) {
	t.Run("sem HOME nem override", func(t *testing.T) {
		t.Setenv(verify.HomeEnv, "")
		t.Setenv("HOME", "")
		if _, err := verify.Root(); err == nil || !strings.Contains(err.Error(), "diretório pessoal") {
			t.Errorf("erro = %v", err)
		}
		if _, err := verify.InitializeVerifierHome(""); err == nil {
			t.Error("a inicialização sem raiz resolvível deveria falhar")
		}
		if _, err := verify.RequireVerifierReady(""); err == nil {
			t.Error("a prontidão sem raiz resolvível deveria falhar")
		}
		if _, err := verify.AfterRun(verify.AfterRunOptions{RootDir: t.TempDir(), WorkID: workID, TaskID: taskID}); err == nil {
			t.Error("AfterRun sem raiz resolvível deveria falhar")
		}
	})

	t.Run("HOME define a raiz padrão", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv(verify.HomeEnv, "")
		t.Setenv("HOME", home)
		root, err := verify.Root()
		if err != nil || root != filepath.Join(home, ".config", "pwn", "verifier") {
			t.Errorf("raiz = %q, %v", root, err)
		}
	})

	t.Run("override relativo vira absoluto", func(t *testing.T) {
		t.Chdir(t.TempDir())
		t.Setenv(verify.HomeEnv, "relativa")
		root, err := verify.Root()
		if err != nil || !filepath.IsAbs(root) || filepath.Base(root) != "relativa" {
			t.Errorf("raiz = %q, %v", root, err)
		}
	})
}

func TestDefaultRuntimeFallsBackToOwnExecutable(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	if _, ok := verify.FindExecutable("bun"); ok {
		t.Fatal("bun não deveria existir num PATH vazio")
	}
	runtime := verify.DefaultRuntime()
	own, err := os.Executable()
	if err != nil {
		t.Skipf("os.Executable indisponível: %v", err)
	}
	if runtime != own {
		t.Errorf("runtime = %q, quer o executável do processo %q", runtime, own)
	}
}

func TestAtomicWriters(t *testing.T) {
	directory := t.TempDir()

	t.Run("JSON indentado sem escapar HTML", func(t *testing.T) {
		target := filepath.Join(directory, "novo", "a.json")
		if err := verify.WriteJSONAtomic(target, map[string]string{"k": "<v>&"}); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(target)
		if err != nil || string(data) != "{\n  \"k\": \"<v>&\"\n}\n" {
			t.Errorf("conteúdo = %q, %v", data, err)
		}
	})

	t.Run("valor não serializável", func(t *testing.T) {
		err := verify.WriteJSONAtomic(filepath.Join(directory, "b.json"), make(chan int))
		if err == nil || !strings.Contains(err.Error(), "serializar") {
			t.Errorf("erro = %v", err)
		}
		if _, statErr := os.Stat(filepath.Join(directory, "b.json")); statErr == nil {
			t.Error("nada deveria ser publicado")
		}
	})

	t.Run("destino é um diretório", func(t *testing.T) {
		target := filepath.Join(directory, "dir.json")
		if err := os.MkdirAll(filepath.Join(target, "x"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := verify.WriteJSONAtomic(target, 1); err == nil || !strings.Contains(err.Error(), "publicar") {
			t.Errorf("JSON: erro = %v", err)
		}
		if err := verify.WriteFileAtomic(target, "x", 0o600); err == nil || !strings.Contains(err.Error(), "publicar") {
			t.Errorf("arquivo: erro = %v", err)
		}
	})

	t.Run("pai é um arquivo", func(t *testing.T) {
		blocker := filepath.Join(directory, "arquivo")
		if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := verify.WriteJSONAtomic(filepath.Join(blocker, "a.json"), 1); err == nil || !strings.Contains(err.Error(), "criar") {
			t.Errorf("JSON: erro = %v", err)
		}
		if err := verify.WriteFileAtomic(filepath.Join(blocker, "a"), "x", 0o600); err == nil || !strings.Contains(err.Error(), "criar") {
			t.Errorf("arquivo: erro = %v", err)
		}
	})

	t.Run("arquivo com modo restrito", func(t *testing.T) {
		target := filepath.Join(directory, "segredo")
		if err := verify.WriteFileAtomic(target, "conteúdo", 0o600); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(target)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Errorf("modo = %v, %v", info, err)
		}
	})
}

func TestKeyFilesRejectInvalidMaterial(t *testing.T) {
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(ecdsaKey)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&ecdsaKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	encode := func(kind string, der []byte) string {
		return string(pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der}))
	}

	cases := map[string]string{
		"vazio":              "",
		"sem bloco PEM":      "isto não é PEM",
		"DER inválido":       encode("PRIVATE KEY", []byte("lixo")),
		"chave não Ed25519":  encode("PRIVATE KEY", privateDER),
		"pública não Ed2551": encode("PUBLIC KEY", publicDER),
	}
	for label, content := range cases {
		t.Run(label, func(t *testing.T) {
			root := newVerifier(t)
			if err := os.WriteFile(verify.PrivateKeyFile(root), []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(verify.PublicKeyFile(root), []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			if key, ok := verify.LoadPrivateKey(root); ok || key != nil {
				t.Errorf("chave privada aceita: %v", key)
			}
			if key, ok := verify.LoadPublicKey(root); ok || key != nil {
				t.Errorf("chave pública aceita: %v", key)
			}
			if _, ok := verify.PublicKeyFingerprint(root); ok {
				t.Error("fingerprint de chave inválida")
			}
		})
	}

	t.Run("raiz sem chaves", func(t *testing.T) {
		root := t.TempDir()
		if _, ok := verify.LoadPrivateKey(root); ok {
			t.Error("chave privada inexistente aceita")
		}
		if _, ok := verify.LoadPublicKey(root); ok {
			t.Error("chave pública inexistente aceita")
		}
	})
}

func TestInitializeVerifierHomeIsIdempotent(t *testing.T) {
	root := t.TempDir()
	first, err := verify.InitializeVerifierHome(root)
	if err != nil || !first.Created {
		t.Fatalf("primeira inicialização = %+v, %v", first, err)
	}
	privateBefore, err := os.ReadFile(verify.PrivateKeyFile(root))
	if err != nil {
		t.Fatal(err)
	}
	again, err := verify.InitializeVerifierHome(root)
	if err != nil || again.Created || again.Config.VerifierID != first.Config.VerifierID {
		t.Fatalf("segunda inicialização = %+v, %v", again, err)
	}
	privateAfter, _ := os.ReadFile(verify.PrivateKeyFile(root))
	if string(privateBefore) != string(privateAfter) {
		t.Error("a chave existente não pode ser regenerada")
	}

	// Com um par de chaves incompleto, o par é recriado e a configuração fica.
	if err := os.Remove(verify.PublicKeyFile(root)); err != nil {
		t.Fatal(err)
	}
	repaired, err := verify.InitializeVerifierHome(root)
	if err != nil || repaired.Created {
		t.Fatalf("reparo = %+v, %v", repaired, err)
	}
	if _, ok := verify.LoadPublicKey(root); !ok {
		t.Error("a chave pública deveria ter sido recriada")
	}
	if _, ok := verify.LoadPrivateKey(root); !ok {
		t.Error("a chave privada deveria continuar válida")
	}
}

func TestInitializeVerifierHomeErrors(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "arquivo")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := verify.InitializeVerifierHome(filepath.Join(blocker, "raiz")); err == nil || !strings.Contains(err.Error(), "criar") {
		t.Errorf("erro = %v", err)
	}
}

func TestListJSONFilesAndDigestErrors(t *testing.T) {
	file := filepath.Join(t.TempDir(), "arquivo.txt")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := verify.ListJSONFiles(file); err == nil || !strings.Contains(err.Error(), "listar") {
		t.Errorf("listar um arquivo: erro = %v", err)
	}
	if _, err := verify.DigestOfFile(filepath.Join(t.TempDir(), "ausente")); err == nil || !strings.Contains(err.Error(), "ler") {
		t.Errorf("digest de arquivo ausente: erro = %v", err)
	}
	digest, err := verify.DigestOfFile(file)
	if err != nil || digest != verify.DigestOfText("x") {
		t.Errorf("digest = %q, %v", digest, err)
	}
}

func TestAssertProtectedOutsideRepositoryEdges(t *testing.T) {
	repository := t.TempDir()
	if err := verify.AssertProtectedOutsideRepository(repository, repository); !verify.IsUnavailable(err) {
		t.Errorf("raiz igual ao repositório: erro = %v", err)
	}
	// Prefixo textual não é contenção: "repo-2" não está dentro de "repo".
	sibling := repository + "-2"
	if err := verify.AssertProtectedOutsideRepository(sibling, repository); err != nil {
		t.Errorf("diretório irmão: erro = %v", err)
	}
}

func TestProjectSandboxMalformedEntries(t *testing.T) {
	projectDir := t.TempDir()
	cases := map[string]string{
		"mounts não é array":       `{"mounts":{}}`,
		"mount não é objeto":       `{"mounts":["/x"]}`,
		"overlays não é array":     `{"overlays":"x"}`,
		"overlay não é objeto":     `{"overlays":[1]}`,
		"overlay dentro do repo":   `{"overlays":[{"source":` + quote(filepath.Join(projectDir, "cache")) + `,"dest":"/c"}]}`,
		"overlay dest reservado":   `{"overlays":[{"source":"/opt/c","dest":"/proc"}]}`,
		"overlay dest repetido":    `{"overlays":[{"source":"/opt/a","dest":"/c"},{"source":"/opt/b","dest":"/c"}]}`,
		"env não é objeto":         `{"env":[]}`,
		"env nome inválido":        `{"env":{"minusculo":"x"}}`,
		"env valor não é texto":    `{"env":{"GOFLAGS":1}}`,
		"path_prepend não é array": `{"path_prepend":"/bin"}`,
		"mounts_ro não é array":    `{"mounts_ro":{}}`,
		"mounts_ro com relativo":   `{"mounts_ro":["/ok","relativo"]}`,
	}
	for name, entry := range cases {
		t.Run(name, func(t *testing.T) {
			root := verifierWithProject(t, projectDir, entry)
			sandbox, err := verify.ProjectSandbox(projectDir, root)
			if !verify.IsUnavailable(err) {
				t.Fatalf("sandbox = %+v, erro = %v; quer VerificationUnavailable", sandbox, err)
			}
		})
	}

	t.Run("projeto inexistente", func(t *testing.T) {
		root := verifierWithProject(t, projectDir, `{}`)
		if _, err := verify.ProjectSandbox(filepath.Join(projectDir, "ausente"), root); err == nil || !strings.Contains(err.Error(), "resolver o projeto") {
			t.Errorf("erro = %v", err)
		}
	})

	t.Run("entrada de outro projeto é ignorada", func(t *testing.T) {
		root := verifierWithProject(t, filepath.Join(projectDir, "outro-inexistente"), `{"home":"relativo"}`)
		sandbox, err := verify.ProjectSandbox(projectDir, root)
		if err != nil || sandbox != nil {
			t.Errorf("sandbox = %+v, erro = %v; quer a política padrão", sandbox, err)
		}
	})

	t.Run("raiz do verificador irresolvível", func(t *testing.T) {
		t.Setenv(verify.HomeEnv, "")
		t.Setenv("HOME", "")
		if _, err := verify.ProjectSandbox(projectDir, ""); err == nil {
			t.Error("erro esperado")
		}
	})

	t.Run("entradas válidas normalizam os caminhos", func(t *testing.T) {
		root := verifierWithProject(t, projectDir, `{"path_prepend":["/opt/bin/"],"mounts_ro":["/opt//ro"],"env":null,"mounts":null,"overlays":null}`)
		sandbox, err := verify.ProjectSandbox(projectDir, root)
		if err != nil || sandbox == nil {
			t.Fatalf("sandbox = %+v, erro = %v", sandbox, err)
		}
		if len(sandbox.PathPrepend) != 1 || sandbox.PathPrepend[0] != "/opt/bin" || len(sandbox.MountsRO) != 1 || sandbox.MountsRO[0] != "/opt/ro" {
			t.Errorf("caminhos = %+v", sandbox)
		}
		if len(sandbox.Mounts) != 0 || len(sandbox.Overlays) != 0 || len(sandbox.Env) != 0 || sandbox.Home != "" {
			t.Errorf("campos vazios = %+v", sandbox)
		}
	})
}
