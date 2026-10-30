package queue_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/passoz/pwn/internal/harness/queue"
)

func reviewDir(t *testing.T, root string) string {
	t.Helper()
	dir := filepath.Join(root, "queue", "review")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestDirFailsWhenQueueIsRegularFile(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "queue"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := queue.Dir(root); err == nil {
		t.Error("Dir: esperava erro")
	}
	if _, err := queue.Enqueue(baseItem("r1"), root, ""); err == nil {
		t.Error("Enqueue: esperava erro")
	}
	if _, err := queue.List(root); err == nil {
		t.Error("List: esperava erro")
	}
	if _, err := queue.UpdateStatus("r1", queue.StatusApproved, root); err == nil {
		t.Error("UpdateStatus: esperava erro")
	}
	binding := queue.ReviewBinding{ContractSHA256: "abc123", Command: []string{"echo", "hi"}}
	if _, err := queue.FindApproved("0001", "1.1", binding, root); err == nil {
		t.Error("FindApproved: esperava erro")
	}
}

func TestEmptyRootUsesWorkingDirectory(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	if _, err := queue.Enqueue(baseItem("r1"), "", queue.StatusPendingReview); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "queue", "review", "r1.json")); err != nil {
		t.Fatalf("item não gravado no diretório atual: %v", err)
	}
	items, err := queue.List("")
	if err != nil || len(items) != 1 || items[0].RunID != "r1" {
		t.Fatalf("List = %v, %v", items, err)
	}
}

func TestRelativeRootIsResolved(t *testing.T) {
	base := t.TempDir()
	t.Chdir(base)
	dir, err := queue.Dir("rel")
	if err != nil {
		t.Fatalf("Dir: %v", err)
	}
	if !filepath.IsAbs(dir) {
		t.Errorf("caminho deveria ser absoluto: %q", dir)
	}
	if _, err := os.Stat(filepath.Join(base, "rel", "queue", "review")); err != nil {
		t.Errorf("diretório não criado: %v", err)
	}
}

func TestEnqueueFailsWhenTargetIsDirectory(t *testing.T) {
	root := t.TempDir()
	dir := reviewDir(t, root)
	target := filepath.Join(dir, "r1.json")
	if err := os.MkdirAll(filepath.Join(target, "x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := queue.Enqueue(baseItem("r1"), root, ""); err == nil {
		t.Error("esperava erro ao gravar sobre diretório")
	}
}

func TestListSkipsDirectoriesNonJSONAndCorrupt(t *testing.T) {
	root := t.TempDir()
	dir := reviewDir(t, root)
	if err := os.Mkdir(filepath.Join(dir, "pasta.json"), 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"notas.txt":     "ignorado",
		"corrupto.json": "{",
		"b.json":        `{"runId":"b","status":"approved"}`,
		"a.json":        `{"runId":"a","status":"pending_review"}`,
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	items, err := queue.List(root)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(items) != 2 || items[0].RunID != "a" || items[1].RunID != "b" {
		t.Fatalf("itens = %+v, queria a,b em ordem de nome", items)
	}
}

func TestUpdateStatusErrors(t *testing.T) {
	root := t.TempDir()
	dir := reviewDir(t, root)

	if _, err := queue.UpdateStatus("r1", queue.StatusPendingReview, root); err == nil {
		t.Error("status pending_review não é válido para atualização")
	}
	if _, err := queue.UpdateStatus("r1", "", root); err == nil {
		t.Error("status vazio não é válido para atualização")
	}
	got, err := queue.UpdateStatus("ausente", queue.StatusApproved, root)
	if err != nil || got != nil {
		t.Errorf("run ausente: got %v, err %v; queria nil, nil", got, err)
	}

	if err := os.WriteFile(filepath.Join(dir, "ruim.json"), []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := queue.UpdateStatus("ruim", queue.StatusApproved, root); err == nil {
		t.Error("JSON inválido: esperava erro")
	}
	if data, _ := os.ReadFile(filepath.Join(dir, "ruim.json")); string(data) != "{" {
		t.Errorf("arquivo corrompido não deve ser reescrito: %q", data)
	}

	if err := os.Mkdir(filepath.Join(dir, "dir.json"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := queue.UpdateStatus("dir", queue.StatusApproved, root); err == nil {
		t.Error("arquivo que é diretório: esperava erro de leitura")
	}
}

func TestFindApprovedPayloadShapes(t *testing.T) {
	binding := queue.ReviewBinding{ContractSHA256: "abc123", Command: []string{"echo", "hi"}}
	tests := []struct {
		name    string
		payload string
		want    bool
	}{
		{"vigente", `{"contract_sha256":"abc123","command":["echo","hi"]}`, true},
		{"sem payload", ``, false},
		{"sem command", `{"contract_sha256":"abc123"}`, false},
		{"command não é lista", `{"contract_sha256":"abc123","command":"echo hi"}`, false},
		{"elemento não string", `{"contract_sha256":"abc123","command":["echo",1]}`, false},
		{"comprimento diferente", `{"contract_sha256":"abc123","command":["echo"]}`, false},
		{"contrato não string", `{"contract_sha256":5,"command":["echo","hi"]}`, false},
		{"sem contrato", `{"command":["echo","hi"]}`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			dir := reviewDir(t, root)
			body := `{"runId":"r","workId":"0001","taskId":"1.1","status":"approved"`
			if tt.payload != "" {
				body += `,"payload":` + tt.payload
			}
			body += `}`
			if err := os.WriteFile(filepath.Join(dir, "r.json"), []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
			got, err := queue.FindApproved("0001", "1.1", binding, root)
			if err != nil {
				t.Fatalf("FindApproved: %v", err)
			}
			if (got != nil) != tt.want {
				t.Errorf("got %v, queria achado=%v", got, tt.want)
			}
		})
	}
}
