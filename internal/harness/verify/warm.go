package verify

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// WarmOptions são as entradas de WarmOverlays.
type WarmOptions struct {
	Ctx     context.Context
	RootDir string
	// Command preenche o cache. Vazio usa `go build std` quando o projeto tem
	// go.mod.
	Command []string
	// TimeoutSeconds limita o comando. Zero usa 600.
	TimeoutSeconds int
	// VerifierRootDir é a raiz protegida. Vazio usa Root.
	VerifierRootDir string
}

// WarmResult é o desfecho do aquecimento.
type WarmResult struct {
	Overlays []ProjectMount
	Command  []string
	Output   string
	Status   int
	TimedOut bool
	Duration time.Duration
}

// DefaultWarmCommand devolve o comando de aquecimento do projeto, ou nil quando
// o tipo do projeto não é conhecido.
func DefaultWarmCommand(rootDir string) []string {
	if _, err := os.Stat(filepath.Join(rootDir, "go.mod")); err == nil {
		return []string{"go", "build", "std"}
	}
	return nil
}

// WarmOverlays preenche a origem de cada overlay do projeto. É o único momento
// em que o cache é gravável, e o sandbox não contém nenhum arquivo do projeto:
// só a toolchain roda. Depois disso, as verificações montam a origem somente
// leitura, com camada de escrita descartável.
func WarmOverlays(options WarmOptions) (WarmResult, error) {
	ctx := options.Ctx
	if ctx == nil {
		ctx = context.Background()
	}
	root, err := resolveRoot(options.VerifierRootDir)
	if err != nil {
		return WarmResult{}, err
	}
	readiness, err := RequireVerifierReady(root)
	if err != nil {
		return WarmResult{}, err
	}
	if err := AssertProtectedOutsideRepository(root, options.RootDir); err != nil {
		return WarmResult{}, err
	}
	project, err := ProjectSandbox(options.RootDir, root)
	if err != nil {
		return WarmResult{}, err
	}
	if project == nil || len(project.Overlays) == 0 {
		return WarmResult{}, unavailable(
			"o projeto não declara overlays",
			`adicione "overlays": [{"source": "<dir fora do repositório>", "dest": "<caminho no sandbox>"}] à entrada do projeto em config.json`,
		)
	}
	command := options.Command
	if len(command) == 0 {
		command = DefaultWarmCommand(options.RootDir)
	}
	if len(command) == 0 {
		return WarmResult{}, fmt.Errorf("verifier: tipo de projeto desconhecido: informe o comando depois de `--`")
	}

	for _, overlay := range project.Overlays {
		if err := os.MkdirAll(overlay.Source, 0o700); err != nil {
			return WarmResult{}, fmt.Errorf("verifier: criar %s: %w", overlay.Source, err)
		}
	}

	policy := BuildSandboxPolicy(readiness.Runtime, [][]string{command}, project)
	// Sem GOFLAGS do projeto: `-mod=vendor` falha fora de um módulo, e o
	// aquecimento roda num diretório vazio.
	delete(policy.Env, "GOFLAGS")

	scratch, err := os.MkdirTemp("", "pwn-warm-")
	if err != nil {
		return WarmResult{}, fmt.Errorf("verifier: criar o diretório temporário: %w", err)
	}
	defer func() { _ = os.RemoveAll(scratch) }()
	workDir := filepath.Join(scratch, "empty")
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		return WarmResult{}, fmt.Errorf("verifier: criar %s: %w", workDir, err)
	}

	timeoutSeconds := options.TimeoutSeconds
	if timeoutSeconds == 0 {
		timeoutSeconds = 600
	}
	started := time.Now()
	spawned, err := spawnInSandbox(ctx, readiness, policy, workDir, ExecutableBinds(command), command, timeoutSeconds*1000, true)
	if err != nil {
		return WarmResult{}, err
	}
	return WarmResult{
		Overlays: project.Overlays,
		Command:  command,
		Output:   spawned.output,
		Status:   spawned.status,
		TimedOut: spawned.timedOut,
		Duration: time.Since(started),
	}, nil
}
