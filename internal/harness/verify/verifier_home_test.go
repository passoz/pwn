package verify_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/passoz/pwn/internal/harness/verify"
)

func TestInitializeVerifierHomeLayout(t *testing.T) {
	root := t.TempDir()
	initialization, err := verify.InitializeVerifierHome(root)
	if err != nil {
		t.Fatalf("inicializar: %v", err)
	}
	if !initialization.Created {
		t.Error("a primeira inicialização deve criar a configuração")
	}
	for _, directory := range []string{
		root,
		verify.KeysDir(root),
		verify.ApprovalsDir(root),
		verify.ReceiptDir(root),
	} {
		info, err := os.Stat(directory)
		if err != nil {
			t.Fatalf("diretório %s ausente: %v", directory, err)
		}
		if mode := info.Mode().Perm(); mode != 0o700 {
			t.Errorf("modo de %s = %o, quer 700", directory, mode)
		}
	}
	for _, file := range []string{verify.PrivateKeyFile(root), verify.PublicKeyFile(root)} {
		info, err := os.Stat(file)
		if err != nil {
			t.Fatalf("arquivo %s ausente: %v", file, err)
		}
		if mode := info.Mode().Perm(); mode != 0o600 {
			t.Errorf("modo de %s = %o, quer 600", file, mode)
		}
	}

	config := verify.ReadConfig(root)
	if config == nil {
		t.Fatal("config.json não foi criado")
	}
	if config.Version != 1 || config.Runtime.Bun != verify.DefaultRuntime() {
		t.Errorf("configuração inesperada: %+v", config)
	}
	if config.Isolation.Mode != "bwrap" || config.Isolation.Network {
		t.Errorf("isolamento inesperado: %+v", config.Isolation)
	}
	if config.VerifierID == "" || !strings.Contains(config.VerifierID, "-") {
		t.Errorf("verifier_id inesperado: %q", config.VerifierID)
	}

	firstFingerprint, ok := verify.PublicKeyFingerprint(root)
	if !ok {
		t.Fatal("a chave pública não carregou")
	}
	second, err := verify.InitializeVerifierHome(root)
	if err != nil {
		t.Fatalf("reinicializar: %v", err)
	}
	if second.Created {
		t.Error("a segunda inicialização não pode recriar a configuração")
	}
	secondFingerprint, ok := verify.PublicKeyFingerprint(root)
	if !ok || secondFingerprint != firstFingerprint {
		t.Errorf("a chave mudou entre inicializações: %s != %s", secondFingerprint, firstFingerprint)
	}
}

func TestVerifierRootEnvOverride(t *testing.T) {
	target := filepath.Join(t.TempDir(), "isolado")
	t.Setenv(verify.HomeEnv, "  "+target+"  ")
	root, err := verify.Root()
	if err != nil {
		t.Fatalf("resolver a raiz: %v", err)
	}
	if root != target {
		t.Errorf("raiz = %q, quer %q", root, target)
	}
	if _, err := verify.InitializeVerifierHome(""); err != nil {
		t.Fatalf("inicializar com a variável de ambiente: %v", err)
	}
	if _, err := os.Stat(verify.ConfigFile(target)); err != nil {
		t.Errorf("config.json não foi criado em %s: %v", target, err)
	}
}

func TestRequireVerifierReady(t *testing.T) {
	t.Run("configuração ausente", func(t *testing.T) {
		root := t.TempDir()
		_, err := verify.RequireVerifierReady(root)
		if !verify.IsUnavailable(err) {
			t.Fatalf("erro = %v, quer VerificationUnavailable", err)
		}
		if !strings.Contains(err.Error(), "não configurado") {
			t.Errorf("mensagem inesperada: %v", err)
		}
	})

	t.Run("runtime ausente", func(t *testing.T) {
		root := newVerifier(t)
		configureVerifier(t, root, filepath.Join(root, "sem-runtime"), "/bin/true")
		_, err := verify.RequireVerifierReady(root)
		if !verify.IsUnavailable(err) || !strings.Contains(err.Error(), "runtime aprovado") {
			t.Fatalf("erro = %v, quer runtime ausente", err)
		}
	})

	t.Run("bwrap ausente", func(t *testing.T) {
		root := newVerifier(t)
		configureVerifier(t, root, verify.DefaultRuntime(), filepath.Join(root, "sem-bwrap"))
		_, err := verify.RequireVerifierReady(root)
		if !verify.IsUnavailable(err) {
			t.Fatalf("erro = %v, quer VerificationUnavailable", err)
		}
		unavailable := err.(*verify.VerificationUnavailable)
		if !strings.Contains(unavailable.Message, "isolamento indisponível") {
			t.Errorf("mensagem inesperada: %q", unavailable.Message)
		}
		if unavailable.Detail == "" {
			t.Error("o detalhe deve indicar a ação corretiva")
		}
	})

	t.Run("chave pública ausente", func(t *testing.T) {
		root := newVerifier(t)
		configureVerifier(t, root, verify.DefaultRuntime(), "/bin/true")
		if err := os.Remove(verify.PublicKeyFile(root)); err != nil {
			t.Fatalf("remover a chave pública: %v", err)
		}
		_, err := verify.RequireVerifierReady(root)
		if !verify.IsUnavailable(err) || !strings.Contains(err.Error(), "chave pública") {
			t.Fatalf("erro = %v, quer chave pública ausente", err)
		}
	})

	t.Run("pronto", func(t *testing.T) {
		root := newVerifier(t)
		configureVerifier(t, root, verify.DefaultRuntime(), "/bin/true")
		readiness, err := verify.RequireVerifierReady(root)
		if err != nil {
			t.Fatalf("prontidão: %v", err)
		}
		if readiness.Root != root || readiness.Bwrap != "/bin/true" || readiness.Runtime == "" {
			t.Errorf("prontidão inesperada: %+v", readiness)
		}
		if len(readiness.PublicKeyFingerprint) != 64 {
			t.Errorf("fingerprint inesperado: %q", readiness.PublicKeyFingerprint)
		}
	})
}

func TestAssertProtectedOutsideRepository(t *testing.T) {
	repository := t.TempDir()
	for _, candidate := range []string{
		filepath.Join(repository, ".pwn-verifier"),
		repository,
	} {
		if err := verify.AssertProtectedOutsideRepository(candidate, repository); !verify.IsUnavailable(err) {
			t.Errorf("%s dentro do repositório deveria falhar: %v", candidate, err)
		}
	}
	outside := filepath.Join(t.TempDir(), "verifier")
	if err := verify.AssertProtectedOutsideRepository(outside, repository); err != nil {
		t.Errorf("raiz externa recusada: %v", err)
	}
	// Prefixo textual não é ancestralidade: `<repo>-vizinho` é externo.
	if err := verify.AssertProtectedOutsideRepository(repository+"-vizinho", repository); err != nil {
		t.Errorf("vizinho textual recusado: %v", err)
	}
}

func TestProtectedPaths(t *testing.T) {
	root := filepath.Join("/var", "lib", "pwn")
	paths := verify.ProtectedPaths(root)
	if len(paths) != 2 || paths[0] != root || paths[1] != "/var/lib" {
		t.Errorf("protectedPaths = %v", paths)
	}
}

func verifierWithProject(t *testing.T, projectDir, entry string) string {
	t.Helper()
	root := newVerifier(t)
	config := verify.ReadConfig(root)
	config.Projects = map[string]json.RawMessage{projectDir: json.RawMessage(entry)}
	if err := verify.WriteJSONAtomic(verify.ConfigFile(root), config); err != nil {
		t.Fatalf("gravar a configuração: %v", err)
	}
	return root
}

func TestProjectSandbox(t *testing.T) {
	t.Run("sem configuração do projeto usa a política padrão", func(t *testing.T) {
		projectDir := t.TempDir()
		root := newVerifier(t)
		sandbox, err := verify.ProjectSandbox(projectDir, root)
		if err != nil {
			t.Fatalf("política do projeto: %v", err)
		}
		if sandbox != nil {
			t.Errorf("política = %+v, quer nil", sandbox)
		}
	})

	t.Run("HOME, montagens próprias e env entram na política", func(t *testing.T) {
		projectDir := t.TempDir()
		cache := t.TempDir()
		entry := `{"path_prepend":["/opt/toolchain/bin"],"mounts_ro":["/opt/modules"],` +
			`"mounts":[{"source":` + quote(cache) + `,"dest":"/pwn-home/cache"}],` +
			`"home":"/pwn-home","env":{"GOPROXY":"off"}}`
		root := verifierWithProject(t, projectDir, entry)

		sandbox, err := verify.ProjectSandbox(projectDir, root)
		if err != nil {
			t.Fatalf("política do projeto: %v", err)
		}
		if sandbox == nil || sandbox.Home != "/pwn-home" {
			t.Fatalf("sandbox = %+v", sandbox)
		}
		if len(sandbox.Mounts) != 1 || sandbox.Mounts[0].Source != cache || sandbox.Mounts[0].Dest != "/pwn-home/cache" {
			t.Errorf("montagens inesperadas: %+v", sandbox.Mounts)
		}
		if sandbox.Env["GOPROXY"] != "off" {
			t.Errorf("env inesperado: %+v", sandbox.Env)
		}
		policy := verify.BuildSandboxPolicy("/usr/bin/bun", nil, sandbox)
		if policy.Home != "/pwn-home" || policy.Mounts[0].Source != cache {
			t.Errorf("política inesperada: %+v", policy)
		}
		if !contains(policy.MountsRO, "/opt/modules") || !contains(policy.MountsRO, "/opt/toolchain/bin") {
			t.Errorf("mounts_ro inesperadas: %+v", policy.MountsRO)
		}
	})

	t.Run("entrada malformada falha fechada", func(t *testing.T) {
		projectDir := t.TempDir()
		cache := t.TempDir()
		cases := map[string]string{
			"mount relativo":    `{"mounts":[{"source":"relativo","dest":"/pwn-home/cache"}]}`,
			"dest reservado":    `{"mounts":[{"source":"/opt/cache","dest":"/tmp"}]}`,
			"dest duplicado":    `{"mounts":[{"source":"/opt/cache","dest":"/pwn-home/cache"},{"source":"/opt/other","dest":"/pwn-home/cache"}]}`,
			"home relativo":     `{"home":"relativo"}`,
			"home nulo":         `{"home":null}`,
			"home no repo":      `{"home":` + quote(filepath.Join(projectDir, "dentro")) + `}`,
			"home inexistente":  `{"home":"/nonexistent"}`,
			"env reservado":     `{"env":{"HOME":"/tmp"}}`,
			"env com newline":   `{"env":{"GOPROXY":"a\nb"}}`,
			"path relativo":     `{"path_prepend":["relativo"]}`,
			"mount sem destino": `{"mounts":[{"source":` + quote(cache) + `}]}`,
			"entry não objeto":  `[]`,
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
	})
}

func TestBuildSandboxPolicyDefaults(t *testing.T) {
	policy := verify.BuildSandboxPolicy("/usr/bin/bun", nil, nil)
	if policy.Home != "/nonexistent" {
		t.Errorf("home = %q", policy.Home)
	}
	if len(policy.Mounts) != 0 || len(policy.PathPrepend) != 0 {
		t.Errorf("montagens e prefixos deveriam estar vazios: %+v", policy)
	}
	if policy.Env == nil || len(policy.Env) != 0 {
		t.Errorf("env = %+v, quer mapa vazio", policy.Env)
	}
	if policy.Network || !policy.UserNamespace || !policy.PIDNamespace || policy.Engine != "bwrap" {
		t.Errorf("política inesperada: %+v", policy)
	}
	for _, mount := range []string{"/usr", "/bin", "/lib", "/lib64", "/etc"} {
		if !contains(policy.MountsRO, mount) {
			t.Errorf("mounts_ro sem %s: %+v", mount, policy.MountsRO)
		}
	}
}

func TestLooksEnvironmental(t *testing.T) {
	cases := []struct {
		output string
		want   bool
	}{
		{"error: Cannot find module 'x'", true},
		{"Module not found: ./y", true},
		{"no such file or directory", true},
		{"sh: command not found", true},
		{"error: is not in the dependency tree", true},
		{"Failed to resolve import", true},
		{"expect(received).toBe(expected) // Object.is equality", false},
		{"AssertionError: expected 2 to be 3", false},
		{"", false},
	}
	for _, testCase := range cases {
		if got := verify.LooksEnvironmental(testCase.output); got != testCase.want {
			t.Errorf("LooksEnvironmental(%q) = %v, quer %v", testCase.output, got, testCase.want)
		}
	}
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func TestListJSONFilesAndIsDirectory(t *testing.T) {
	directory := t.TempDir()
	writeFile(t, directory, "b.json", "{}")
	writeFile(t, directory, "a.json", "{}")
	writeFile(t, directory, "c.txt", "x")

	files, err := verify.ListJSONFiles(directory)
	if err != nil {
		t.Fatalf("listar: %v", err)
	}
	if len(files) != 2 || filepath.Base(files[0]) != "a.json" || filepath.Base(files[1]) != "b.json" {
		t.Errorf("arquivos = %v", files)
	}

	empty, err := verify.ListJSONFiles(filepath.Join(directory, "ausente"))
	if err != nil || len(empty) != 0 {
		t.Errorf("diretório ausente: %v, %v", empty, err)
	}

	if !verify.IsDirectory(directory) {
		t.Error("o diretório deveria ser reconhecido")
	}
	if verify.IsDirectory(filepath.Join(directory, "a.json")) || verify.IsDirectory(filepath.Join(directory, "ausente")) {
		t.Error("arquivo e caminho ausente não são diretórios")
	}
}

func TestReadConfigRejectsOtherVersions(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "config.json", `{"version":2}`)
	if config := verify.ReadConfig(root); config != nil {
		t.Errorf("config = %+v, quer nil", config)
	}
	writeFile(t, root, "config.json", `{`)
	if config := verify.ReadConfig(root); config != nil {
		t.Errorf("config inválida = %+v, quer nil", config)
	}
}

// O runtime vai para a configuração e para o digest do sandbox: um link no PATH
// pode apontar para outra versão depois da aprovação, então o caminho é o real.
func TestDefaultRuntimeResolvesSymlinks(t *testing.T) {
	bin := t.TempDir()
	real := filepath.Join(bin, "bun-1.0.0")
	if err := os.WriteFile(real, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(bin, "bun")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)

	resolved, err := filepath.EvalSymlinks(real)
	if err != nil {
		t.Fatal(err)
	}
	if got := verify.DefaultRuntime(); got != resolved {
		t.Fatalf("DefaultRuntime = %q, quer o caminho real %q", got, resolved)
	}
}
