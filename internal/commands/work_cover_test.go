package commands

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/passoz/pwn/internal/harness/work"
)

// breakRequirements zera requirements.json: o PRD passa a citar um requisito
// que não existe mais, e GATE-REQ-PRD bloqueia.
func breakRequirements(e *env, workID string) {
	e.t.Helper()
	e.write(".pwn/work/"+workID+"/requirements.json", "{}\n")
}

func TestWorkGateHandler(t *testing.T) {
	t.Run("gate aprovado grava cache e o reaproveita", func(t *testing.T) {
		e := newEnv(t)
		e.scaffold("0001")

		first := e.work("gate", "GATE-DISC-REQ", "--work", "0001")
		first.expect(t, 0, []string{
			"=== [pwn work gate] Executando Gate GATE-DISC-REQ para Work 0001 ===\n",
			"  \"gate\": \"GATE-DISC-REQ\",\n",
			"  \"result\": \"pass\",\n",
			"\n[GATE RESULT]: PASS — Gate aprovado.\n",
		}, nil)
		if strings.Contains(first.stdout, "(cache)") {
			t.Fatalf("a primeira execução não pode vir do cache:\n%s", first.stdout)
		}
		cached, err := os.ReadDir(filepath.Join(e.dir, ".pwn", "gate-cache"))
		if err != nil || len(cached) == 0 {
			t.Fatalf("cache de gates não foi gravado: %v", err)
		}

		second := e.work("gate", "GATE-DISC-REQ", "--work", "0001")
		second.expect(t, 0, []string{"Executando Gate GATE-DISC-REQ para Work 0001 (cache) ===\n"}, nil)

		noCache := e.work("gate", "GATE-DISC-REQ", "--work", "0001", "--no-cache")
		noCache.expect(t, 0, []string{"Executando Gate GATE-DISC-REQ para Work 0001 ===\n"}, nil)
		if strings.Contains(noCache.stdout, "(cache)") {
			t.Fatalf("--no-cache não pode usar o cache:\n%s", noCache.stdout)
		}

		e.work("gate", "--clear-cache").expect(t, 0, []string{"✓ 1 arquivo(s) de cache removido(s) de .pwn/gate-cache/.\n"}, nil)
	})

	t.Run("sem nome usa GATE-DISC-REQ e o último Work", func(t *testing.T) {
		e := newEnv(t)
		e.scaffold("0003")
		e.work("gate", "--no-cache").expect(t, 0, []string{
			"=== [pwn work gate] Executando Gate GATE-DISC-REQ para Work 0003 ===\n",
		}, nil)
	})

	t.Run("gate bloqueado devolve 1", func(t *testing.T) {
		e := newEnv(t)
		e.scaffold("0001")
		breakRequirements(e, "0001")
		result := e.work("gate", "GATE-REQ-PRD", "--work", "0001", "--no-cache")
		result.expect(t, 1,
			[]string{"  \"result\": \"blocked\",\n", "FIND-PRD-XREF-FR-001"},
			[]string{"\n[GATE RESULT]: BLOCKED — Existem lacunas ou conflitos materiais no Work 0001.\n"})
	})

	t.Run("todos os gates aprovados", func(t *testing.T) {
		e := newEnv(t)
		e.scaffold("0001")
		e.work("gate", "--all", "--work", "0001").expect(t, 0, []string{
			"\n── GATE-DISC-REQ ──\n  (nenhum finding)\n",
			"\n── Resumo por gate ──\n",
			"GATE-DISC-REQ: pass (0 findings)\n",
			"GATE-PLAN-CONTRACT: pass (0 findings)\n",
			"\n[GATE RESULT]: PASS — todos os gates aprovados.\n",
		}, nil)
	})

	t.Run("todos os gates com um bloqueado listam os findings", func(t *testing.T) {
		e := newEnv(t)
		e.scaffold("0001")
		breakRequirements(e, "0001")
		result := e.work("gate", "--all", "--work", "0001")
		result.expect(t, 1, []string{
			"\n── GATE-REQ-PRD ──\n",
			"  [high] FIND-PRD-XREF-FR-001 · traceability_gap · open\n",
			"      Requisito FR-001 aceito no PRD mas não encontrado em requirements.json\n",
			"      resolução: Verificar se o requisito FR-001 existe ou remover do PRD (owner: product-owner)\n",
			"GATE-REQ-PRD: blocked (1 findings)\n",
			"GATE-DISC-REQ: pass (0 findings)\n",
		}, []string{"\n[GATE RESULT]: BLOCKED — 1 gate(s) bloqueado(s): GATE-REQ-PRD.\n"})
	})
}

func TestWorkContractHandler(t *testing.T) {
	t.Run("valida os contratos congelados", func(t *testing.T) {
		e := newEnv(t)
		e.scaffold("0001")
		e.work("contract", "--work", "0001").expect(t, 0, []string{
			"Work 0001 — 1 task(s) no plano\n\n",
			"✓ 1.1 — CTR-001 | risco L2 | tdd-strict\n",
			"    write_allow: src/**, tests/**\n",
			"    aceitação:   sh tests/add-widget.test.ts ; sh tests/reg.sh ; sh tests/check.sh\n",
			"\n[CONTRACT RESULT]: PASS — todos os contratos V4 estão congelados e utilizáveis.\n",
		}, nil)
	})

	t.Run("congelar testes e listar os congelados", func(t *testing.T) {
		e := newEnv(t)
		e.scaffold("0001")
		frozen := e.work("contract", "--work", "0001", "--task", "1.1", "--freeze-tests", "tests/add-widget.test.ts")
		frozen.expect(t, 0, []string{
			"=== [pwn work contract --freeze-tests] Congelando testes de aceitação no contrato ===\n",
			"✓ 1 teste(s) congelado(s) em CTR-001:\n",
			"  tests/add-widget.test.ts\n",
			"\nAo menos um AC da task precisa exercitar cada arquivo; o audit recusa a atestação se algum deles mudar.\n",
		}, nil)
		if !regexp.MustCompile(`  [0-9a-f]{12}  tests/add-widget.test.ts\n`).MatchString(frozen.stdout) {
			t.Fatalf("stdout sem o hash de 12 caracteres:\n%s", frozen.stdout)
		}

		e.work("contract", "--work", "0001").expect(t, 0, []string{
			"    congelados:  tests/add-widget.test.ts\n",
		}, nil)
	})

	t.Run("congelar arquivo que não existe", func(t *testing.T) {
		e := newEnv(t)
		e.scaffold("0001")
		e.work("contract", "--work", "0001", "--task", "1.1", "--freeze-tests", "tests/nao-existe.test.ts").
			expect(t, 1, nil, []string{"✗ "})
	})

	t.Run("contratos inválidos", func(t *testing.T) {
		tests := []struct {
			name   string
			mutate func(document map[string]any)
			want   string
		}{
			{
				name: "sem comandos de aceitação",
				mutate: func(document map[string]any) {
					document["acceptance_contract"].(map[string]any)["commands"] = []any{}
				},
				want: "✗ 1.1 — acceptance_contract.commands vazio (fail-closed: nenhuma execução seria autorizada)\n",
			},
			{
				name: "sem escopo de escrita",
				mutate: func(document map[string]any) {
					document["scope_contract"].(map[string]any)["write_allow"] = []any{}
				},
				want: "✗ 1.1 — scope_contract.write_allow vazio\n",
			},
			{
				name: "sem nível de risco",
				mutate: func(document map[string]any) {
					document["risk"].(map[string]any)["level"] = ""
				},
				want: "✗ 1.1 — ",
			},
		}
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				e := newEnv(t)
				e.scaffold("0001")
				e.mutateJSON(".pwn/work/0001/CTR-001.json", test.mutate)
				e.work("contract", "--work", "0001").expect(t, 1,
					[]string{"Work 0001 — 1 task(s) no plano\n\n"},
					[]string{test.want, "\n[CONTRACT RESULT]: FAIL — 1 contrato(s) inválido(s) ou ausente(s). A execução ficaria bloqueada.\n"})
			})
		}
	})

	t.Run("contrato ausente", func(t *testing.T) {
		e := newEnv(t)
		e.scaffold("0001")
		if err := os.Remove(filepath.Join(e.dir, ".pwn", "work", "0001", "CTR-001.json")); err != nil {
			t.Fatalf("remover contrato: %v", err)
		}
		e.work("contract", "--work", "0001").expect(t, 1, nil, []string{"✗ 1.1 — ", "[CONTRACT RESULT]: FAIL"})
	})
}

func TestWorkPlanHandler(t *testing.T) {
	t.Run("valida o plano existente sem avisar de drift", func(t *testing.T) {
		e := newEnv(t)
		e.scaffold("0001")
		result := e.work("plan", "--work", "0001")
		result.expect(t, 0, []string{"PASS: " + filepath.Join(e.dir, ".todo", "0001-tasks.md")}, nil)
		if result.stderr != "" {
			t.Fatalf("stderr = %q, quer vazio", result.stderr)
		}
	})

	t.Run("gera o markdown ausente a partir do plan.json", func(t *testing.T) {
		e := newEnv(t)
		e.scaffold("0001")
		target := filepath.Join(e.dir, ".todo", "0001-tasks.md")
		original := e.read(".todo/0001-tasks.md")
		if err := os.Remove(target); err != nil {
			t.Fatalf("remover markdown: %v", err)
		}
		e.work("plan", "--work", "0001").expect(t, 0,
			[]string{"✓ Plano gerado a partir de plan.json em: " + target + "\n", "PASS: " + target}, nil)
		if got := e.read(".todo/0001-tasks.md"); got != original {
			t.Fatalf("markdown regenerado difere do original:\n%s", got)
		}
	})

	t.Run("drift avisa e --force regenera", func(t *testing.T) {
		e := newEnv(t)
		e.scaffold("0001")
		original := e.read(".todo/0001-tasks.md")
		e.write(".todo/0001-tasks.md", strings.Replace(original, "### [ ] [1.1] Add widget", "### [ ] [1.1] Widget editado à mão", 1))

		drift := e.work("plan", "--work", "0001")
		if !strings.Contains(drift.stderr, "⚠  DRIFT: o markdown diverge de plan.json (edição manual ou fora de sincronia).\n") ||
			!strings.Contains(drift.stderr, "   Regenere com: pwn work plan --work 0001 --force\n") {
			t.Fatalf("stderr sem o aviso de drift: %q", drift.stderr)
		}

		target := filepath.Join(e.dir, ".todo", "0001-tasks.md")
		e.work("plan", "--work", "0001", "--force").expect(t, 0,
			[]string{"✓ Plano regenerado (--force) em: " + target + "\n"}, nil)
		if got := e.read(".todo/0001-tasks.md"); got != original {
			t.Fatalf("--force não restaurou o markdown:\n%s", got)
		}
	})

	t.Run("caminho fora do padrão canônico é recusado", func(t *testing.T) {
		e := newEnv(t)
		e.scaffold("0001")
		e.write("plano-solto.md", e.read(".todo/0001-tasks.md"))
		e.work("plan", "plano-solto.md", "--work", "0009").expect(t, 1, []string{
			"FAIL: plano-solto.md\n",
			"- current task contract requires canonical path .todo/NNNN-tasks.md: plano-solto.md\n",
		}, nil)
	})

	t.Run("work derivado do nome numerado do plano", func(t *testing.T) {
		e := newEnv(t)
		e.scaffold("0001")
		e.work("plan", ".todo/0001-tasks.md").expect(t, 0, []string{"PASS: .todo/0001-tasks.md"}, nil)
	})

	t.Run("plan.json inexistente e sem caminho", func(t *testing.T) {
		e := newEnv(t)
		e.work("plan", "--work", "0007").expect(t, 1, nil, []string{
			"Nenhum plan.json encontrado para o Work 0007. Rode 'pwn work init' e crie .pwn/work/0007/plan.json, ou informe um caminho de plano markdown.\n",
		})
	})
}

func TestWorkScaffoldHandler(t *testing.T) {
	t.Run("cria a cadeia completa e numera o próximo Work", func(t *testing.T) {
		e := newEnv(t)
		first := e.work("scaffold", "--title", "Primeiro recurso")
		first.expect(t, 0, []string{
			"✓ Work 0001 criado em ",
			"Artefatos gerados (8):\n",
			"  + .pwn/work/0001/plan.json\n",
			"  + .todo/0001-tasks.md\n",
			"\nRevisão obrigatória antes de implementar:\n",
			"  ! O risco congelado é L2; ajuste com --risk se a mudança for mais sensível.\n",
			"  pwn work contract --work 0001\n  pwn work gate GATE-PLAN-CONTRACT --work 0001\n  pwn validate --work 0001\n  pwn task capsule 1.1 0001\n",
		}, nil)
		for _, rel := range []string{"discovery.json", "requirements.json", "prd.json", "spec.json", "plan.json", "CTR-001.json", "traceability-matrix.json"} {
			if !e.exists(".pwn/work/0001/" + rel) {
				t.Errorf("artefato %s ausente", rel)
			}
		}

		second := e.work("scaffold", "--title", "Segundo recurso", "--risk", "L3")
		second.expect(t, 0, []string{"✓ Work 0002 criado em "}, nil)
		if !strings.Contains(e.read(".pwn/work/0002/CTR-001.json"), `"level": "L3"`) {
			t.Fatalf("contrato do Work 0002 sem o risco L3:\n%s", e.read(".pwn/work/0002/CTR-001.json"))
		}
	})

	t.Run("Work existente é preservado sem --force", func(t *testing.T) {
		e := newEnv(t)
		e.work("scaffold", "--title", "Recurso", "--work", "0005").mustOK(t, "scaffold")
		e.write(".pwn/work/0005/plan.json", "{\"editado\": true}\n")

		kept := e.work("scaffold", "--title", "Recurso", "--work", "0005")
		kept.expect(t, 0, []string{
			"Artefatos gerados (0):\n",
			"  · ignorado .pwn/work/0005/plan.json: já existe (use --force para sobrescrever)\n",
			"  · ignorado .todo/0005-tasks.md: já existe (use --force para sobrescrever)\n",
		}, nil)
		if got := e.read(".pwn/work/0005/plan.json"); got != "{\"editado\": true}\n" {
			t.Fatalf("plan.json foi sobrescrito sem --force: %s", got)
		}

		e.work("scaffold", "--title", "Recurso", "--work", "0005", "--force").expect(t, 0,
			[]string{"Artefatos gerados (8):\n", "  + .pwn/work/0005/plan.json\n"}, nil)
		if strings.Contains(e.read(".pwn/work/0005/plan.json"), "editado") {
			t.Fatal("--force não regravou plan.json")
		}
	})

	t.Run("--dir cria o Work em outro diretório", func(t *testing.T) {
		e := newEnv(t)
		other := filepath.Join(t.TempDir(), "outro")
		if err := os.MkdirAll(other, 0o755); err != nil {
			t.Fatalf("criar diretório: %v", err)
		}
		e.work("scaffold", "--title", "Recurso", "--work", "0001", "--dir", other).expect(t, 0,
			[]string{"✓ Work 0001 criado em .pwn/work/0001\n"}, nil)
		if e.exists(".pwn/work/0001") {
			t.Fatal("o Work foi criado no repositório em vez de --dir")
		}
		if _, err := os.Stat(filepath.Join(other, ".pwn", "work", "0001", "plan.json")); err != nil {
			t.Fatalf("plan.json ausente em --dir: %v", err)
		}
	})

	t.Run("--source inexistente falha", func(t *testing.T) {
		e := newEnv(t)
		e.work("scaffold", "--title", "Recurso", "--source", "nao-existe.md").expect(t, 1, nil, []string{"✗ "})
	})
}

// v3Layout apaga os artefatos canônicos do Work, deixando só o plano v3 em
// .todo/, que é o que `work import` consome.
func v3Layout(e *env, workID string) {
	e.t.Helper()
	if err := os.RemoveAll(filepath.Join(e.dir, ".pwn", "work", workID)); err != nil {
		e.t.Fatalf("remover artefatos canônicos: %v", err)
	}
}

func TestWorkImportHandler(t *testing.T) {
	t.Run("importa o plano v3 com risco congelado", func(t *testing.T) {
		e := newEnv(t)
		e.scaffold("0001")
		v3Layout(e, "0001")
		before := e.read(".todo/0001-tasks.md")

		result := e.work("import")
		result.expect(t, 0, []string{
			"Raiz: " + e.dir + "\n",
			"Works: 0001 | risco: L2 | gate-chain: não | force: não\n\n",
			"── Work 0001 ──\n",
			"✓ 2 artefato(s) em .pwn/work/0001/: plan.json, CTR-001.json\n",
			"  risco congelado: L2\n",
			"ℹ  Os artefatos v3 (.work/, .todo/, .prompts/, .sources/, .specs/) não foram alterados.\n",
		}, []string{"  ! Task 1.1: nenhuma capability casou por palavra-chave; usando CAP-001"})
		if !e.exists(".pwn/work/0001/plan.json") || !e.exists(".pwn/work/0001/CTR-001.json") {
			t.Fatal("o import não gerou plan.json e CTR-001.json")
		}
		if got := e.read(".todo/0001-tasks.md"); got != before {
			t.Fatal("o import alterou o plano v3")
		}
	})

	t.Run("--risk auto lista o risco por task", func(t *testing.T) {
		e := newEnv(t)
		e.scaffold("0001")
		v3Layout(e, "0001")
		e.work("import", "--risk", "auto").expect(t, 0, []string{
			"Works: 0001 | risco: auto | gate-chain: não | force: não\n",
			"  risco por task: 1.1=L2\n",
		}, nil)
	})

	t.Run("--force e --gate-chain regeneram a cadeia documental", func(t *testing.T) {
		e := newEnv(t)
		e.scaffold("0001")
		v3Layout(e, "0001")
		e.work("import", "--work", "0001", "--force", "--gate-chain", "--risk", "L1").expect(t, 0, []string{
			"Works: 0001 | risco: L1 | gate-chain: sim | force: sim\n",
			"✓ 7 artefato(s) em .pwn/work/0001/: plan.json, CTR-001.json, discovery.json, requirements.json, prd.json, spec.json, traceability-matrix.json\n",
			"  risco congelado: L1\n",
		}, []string{"  ! Nenhum .sources/NNNN-*.md encontrado: discovery.json derivado apenas do prompt/plano.\n"})
		if !strings.Contains(e.read(".pwn/work/0001/CTR-001.json"), `"level": "L1"`) {
			t.Fatal("o contrato importado não congelou L1")
		}
	})

	t.Run("Work fora de .todo avisa e falha", func(t *testing.T) {
		e := newEnv(t)
		e.scaffold("0001")
		v3Layout(e, "0001")
		e.work("import", "--work", "0009").expect(t, 1,
			[]string{"── Work 0009 ──\n"},
			[]string{
				"⚠  Work 0009 não está em .todo/ (0001); tentando mesmo assim.\n",
				"✗ Work 0009: Work v3 0009 não encontrado: falta .todo/0009-tasks.md em " + e.dir,
			})
	})

	t.Run("--all suprime o aviso de Work ausente", func(t *testing.T) {
		e := newEnv(t)
		e.scaffold("0001")
		v3Layout(e, "0001")
		result := e.work("import", "--work", "0009", "--all")
		result.expect(t, 1, nil, []string{"✗ Work 0009: "})
		if strings.Contains(result.stderr, "tentando mesmo assim") {
			t.Fatalf("--all não deveria avisar:\n%s", result.stderr)
		}
	})

	t.Run("Work já importado só é regravado com --force", func(t *testing.T) {
		e := newEnv(t)
		e.scaffold("0001")
		e.write(".pwn/work/0001/plan.json", "{\"editado\": true}\n")
		e.work("import").expect(t, 0, []string{
			"✓ 0 artefato(s) em .pwn/work/0001/: \n",
			"  · ignorado plan.json: já existe (use --force para sobrescrever)\n",
			"  · ignorado CTR-001.json: já existe (use --force para sobrescrever)\n",
		}, nil)
		if got := e.read(".pwn/work/0001/plan.json"); got != "{\"editado\": true}\n" {
			t.Fatalf("plan.json foi sobrescrito sem --force: %s", got)
		}
		e.work("import", "--force").expect(t, 0, []string{"✓ 2 artefato(s) em .pwn/work/0001/: plan.json, CTR-001.json\n"}, nil)
	})
}

// commitFeature cria um commit-base e um commit de mudança fora do pwn.
func commitFeature(e *env, files map[string]string) (base string) {
	e.t.Helper()
	e.write("README.md", "base\n")
	e.commit("base")
	base = e.git("rev-parse", "HEAD")
	for rel, content := range files {
		e.write(rel, content)
	}
	e.commit("mudança fora do pwn")
	return base
}

func TestWorkReconcileHandler(t *testing.T) {
	t.Run("dry-run lista as mudanças sem criar o Work", func(t *testing.T) {
		e := newEnv(t)
		base := commitFeature(e, map[string]string{"src/foo.go": "package x\n", "src/foo_test.go": "package x\n"})
		result := e.work("reconcile", "--since", base, "--title", "Feature Foo", "--dry-run")
		result.expect(t, 0, []string{
			"=== [pwn work reconcile] Conciliando mudanças feitas fora do pwn ===\n",
			"Referência: " + base[:12] + " | HEAD: ",
			"Mudanças a conciliar (2):\n",
			"  A código src/foo.go\n",
			"  A teste  src/foo_test.go\n",
			"Tasks (1): 1.1 [1 arquivo(s)]\n",
			"\n(--dry-run) nada foi criado. Rode sem --dry-run para criar o Work.\n",
		}, nil)
		if e.exists(".pwn/work") {
			t.Fatal("dry-run não pode criar o Work")
		}
	})

	t.Run("cria o Work e congela os testes existentes", func(t *testing.T) {
		e := newEnv(t)
		base := commitFeature(e, map[string]string{"src/foo.go": "package x\n", "src/foo_test.go": "package x\n"})
		result := e.work("reconcile", "--since", base, "--title", "Feature Foo", "--work", "0001")
		result.expect(t, 0, []string{
			"\n✓ Work 0001 criado em .pwn/work/0001/ (9 artefato(s))\n",
			"✓ Testes congelados no contrato: task(s) 1.1\n",
			"\nA conciliação não conclui nada: sem RED/GREEN observado, a prova é o recibo do verificador.\n",
			"  pwn work gate --all --work 0001\n",
			"  pwn verify approve --work 0001 --task 1.1 --by <nome> && pwn verify run --work 0001 --task 1.1\n",
		}, nil)
		if result.stderr != "" {
			t.Fatalf("stderr = %q, quer vazio", result.stderr)
		}
		recorded := work.ReadReconciliation(e.dir, "0001")
		if recorded == nil || recorded.BaseCommit != base {
			t.Fatalf("registro de conciliação = %+v, quer base %s", recorded, base)
		}

		// Reconciliar de novo a mesma mudança não duplica: o arquivo já pertence ao Work 0001.
		e.work("reconcile", "--since", base, "--title", "Feature Foo", "--work", "0001").
			expect(t, 1, nil, []string{"✗ "})
	})

	t.Run("mudança sem teste orienta a escrever o teste", func(t *testing.T) {
		e := newEnv(t)
		base := commitFeature(e, map[string]string{"src/only.go": "package x\n"})
		result := e.work("reconcile", "--since", base, "--title", "Somente codigo", "--work", "0002")
		result.expect(t, 0,
			[]string{"\n✓ Work 0002 criado em .pwn/work/0002/ (9 artefato(s))\n"},
			[]string{
				"! task 1.1: a mudança não tem teste — escrever depois: tests/only.test.ts\n",
				"  O contrato já autoriza esse arquivo. O teste deve FALHAR com src/only.go no commit-base " + base[:7] + ".\n",
				"  Escreva e commite o teste; depois: pwn work contract --work 0002 --task 1.1 --freeze-tests tests/only.test.ts\n",
			})
		if strings.Contains(result.stdout, "Testes congelados") {
			t.Fatalf("nenhum teste foi congelado:\n%s", result.stdout)
		}
	})

	t.Run("--paths e --tests delimitam a mudança", func(t *testing.T) {
		e := newEnv(t)
		base := commitFeature(e, map[string]string{
			"src/a.go": "package x\n", "src/b.go": "package x\n", "src/a_test.go": "package x\n",
		})
		result := e.work("reconcile", "--since", base, "--title", "Somente A", "--paths", "src/a.go, ,", "--tests", "src/a_test.go", "--dry-run")
		result.expect(t, 0, []string{
			"Mudanças a conciliar (1):\n",
			"  A código src/a.go\n",
			"Tasks (1): 1.1 [1 arquivo(s)]\n",
		}, nil)
		if strings.Contains(result.stdout, "src/b.go") {
			t.Fatalf("src/b.go está fora de --paths:\n%s", result.stdout)
		}
	})

	t.Run("risco inválido e título curto", func(t *testing.T) {
		e := newEnv(t)
		e.work("reconcile", "--risk", "L9").expect(t, 1, nil, []string{"--risk inválido: L9. Opções: L0, L1, L2, L3, L4\n"})
		base := commitFeature(e, map[string]string{"src/a.go": "package x\n"})
		e.work("reconcile", "--since", base, "--title", "abc").expect(t, 1, nil, []string{"✗ --title deve ter ao menos 5 caracteres\n"})
	})

	t.Run("referência desconhecida", func(t *testing.T) {
		e := newEnv(t)
		e.work("reconcile", "--since", "refs/nao-existe", "--title", "Titulo longo").expect(t, 1, nil, []string{"✗ "})
	})
}

func TestWorkStatusHandler(t *testing.T) {
	t.Run("índice de Works em texto e em JSON", func(t *testing.T) {
		e := newEnv(t)
		e.scaffold("0001")
		e.work("status").expect(t, 0, []string{
			"=== [pwn work status] Relatório de Status do Work ===\n",
			"| Work | State | Plan | Progress | Panorama |\n",
			"| `0001` | planned | `.todo/0001-tasks.md` | 0/1 | NOT STARTED |\n",
		}, nil)

		asJSON := e.work("status", "--json")
		asJSON.expect(t, 0, []string{"=== [pwn work status] Relatório de Status do Work ===\n", "  \"work_id\": \"0001\""}, nil)
	})

	t.Run("status de um plano em texto e em JSON", func(t *testing.T) {
		e := newEnv(t)
		e.scaffold("0001")
		e.work("status", "0001").expect(t, 0, []string{
			"# Project status\n",
			"- **Project state:** NOT STARTED\n",
			"- **Progress:** 0/1 checked (0%)\n",
			"| `1.1` | [ ] pending | `FR-001` | none | not started — sem aprovação de aceitação independente | Add widget |\n",
		}, nil)

		result := e.work("status", "0001", "--json")
		result.expect(t, 0, []string{
			"  \"panorama\": {\n    \"state\": \"NOT STARTED\",\n",
			"  \"workId\": \"0001\",\n",
			"      \"id\": \"1.1\",\n",
		}, nil)
	})

	t.Run("plano inexistente", func(t *testing.T) {
		e := newEnv(t)
		e.work("status", "0009").expect(t, 1, []string{"=== [pwn work status] Relatório de Status do Work ===\n"}, []string{"✗ "})
	})

	t.Run("cobertura com --work e sem Work informado", func(t *testing.T) {
		e := newEnv(t)
		e.scaffold("0001")
		e.work("status", "--coverage", "--work", "0001").expect(t, 0, []string{
			"=== [pwn work status --coverage] Cobertura do Work 0001 ===\n",
			"  ✓ requisitos aceitos                 1/1\n",
			"  ✓ tasks com contrato congelado       1/1\n",
			"\n[COVERAGE RESULT]: COMPLETO\n",
		}, nil)
		// Sem --work nem id posicional, vale o último Work.
		e.work("status", "--coverage").expect(t, 0, []string{"Cobertura do Work 0001 ===\n"}, nil)
	})

	t.Run("cobertura aponta requisito não aceito", func(t *testing.T) {
		e := newEnv(t)
		e.scaffold("0001")
		e.write(".pwn/work/0001/prd.json", "{\"accepted_requirements\":[]}\n")
		e.work("status", "--coverage", "0001").expect(t, 1, []string{
			"  ⚠ requisitos aceitos                 0/1\n",
			"[COVERAGE RESULT]: 1 lacuna(s)\n",
		}, nil)
	})
}

func TestWorkSyncHandler(t *testing.T) {
	t.Run("projeta o estado do plano no manifest", func(t *testing.T) {
		e := newEnv(t)
		e.scaffold("0001")
		if _, err := work.ReserveWork(e.dir, work.ReserveWorkOptions{WorkID: "0001", OriginType: "manual"}); err != nil {
			t.Fatalf("reservar Work: %v", err)
		}
		e.work("sync", "--work", "0001").expect(t, 0, []string{
			"=== [pwn work sync] Sincronizando estado do manifest .work/NNNN.json ===\n",
			"✓ Manifest .work/0001.json → state: planned\n",
		}, nil)
		manifest, err := work.LoadManifest(e.dir, "0001")
		if err != nil || manifest.State != work.StatePlanned {
			t.Fatalf("manifest = %+v (erro %v), quer state planned", manifest, err)
		}

		// Sem --work vale o último Work.
		e.work("sync").expect(t, 0, []string{"✓ Manifest .work/0001.json → state: planned\n"}, nil)
	})

	t.Run("manifest ilegível", func(t *testing.T) {
		e := newEnv(t)
		e.write(".work/0001.json", "{não é json")
		e.work("sync", "--work", "0001").expect(t, 1, nil, []string{"✗ "})
	})
}

func TestWorkSpecifyAndAuditDispatch(t *testing.T) {
	t.Run("specify escreve o cabeçalho e valida o prompt", func(t *testing.T) {
		e := newEnv(t)
		result := e.work("specify", "prompt-inexistente.md")
		if !strings.HasPrefix(result.stdout, "=== [pwn work specify] Especificando mudança / baseline ===\n") {
			t.Fatalf("stdout = %q", result.stdout)
		}
		if result.code == 0 {
			t.Fatalf("um prompt inexistente não pode ser validado (stderr: %q)", result.stderr)
		}
	})

	t.Run("audit sem ação roda verify e exige --task", func(t *testing.T) {
		e := newEnv(t)
		result := e.work("audit")
		if !strings.HasPrefix(result.stdout, "=== [pwn work audit] Auditando Evidências e Aceitação ===\n") {
			t.Fatalf("stdout = %q", result.stdout)
		}
		if result.code == 0 {
			t.Fatalf("audit sem parâmetros não pode passar (stdout: %q, stderr: %q)", result.stdout, result.stderr)
		}
	})

	t.Run("workAuditArgs preserva a ação conhecida", func(t *testing.T) {
		if got := strings.Join(workAuditArgs([]string{"red", "--work", "0001"}), " "); got != "red --work 0001" {
			t.Fatalf("ação explícita = %q", got)
		}
		if got := strings.Join(workAuditArgs([]string{"--work", "0001"}), " "); got != "verify --work 0001" {
			t.Fatalf("sem ação = %q, quer verify na frente", got)
		}
	})
}
