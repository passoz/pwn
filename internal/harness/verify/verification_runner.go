package verify

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/passoz/pwn/internal/platform/gitx"
	"github.com/passoz/pwn/internal/platform/jsonx"
)

// CheckObservation é o resultado observado de um check.
type CheckObservation struct {
	ID           string   `json:"id"`
	Command      []string `json:"command"`
	Outcome      string   `json:"outcome"`
	ExitCode     int      `json:"exit_code"`
	OutputDigest string   `json:"output_digest"`
	OutputTail   string   `json:"output_tail"`
	Reason       string   `json:"reason,omitempty"`
	// Baseline é o resultado da mesma asserção com a implementação revertida ao
	// baseline.
	Baseline *BaselineObservation `json:"baseline,omitempty"`
}

// BaselineObservation é o resultado do check com a implementação revertida.
type BaselineObservation struct {
	ExitCode     int    `json:"exit_code"`
	OutputDigest string `json:"output_digest"`
	OutputTail   string `json:"output_tail"`
	// SuspectEnvironmental indica que a falha do baseline parece ambiente/import,
	// não a asserção.
	SuspectEnvironmental bool `json:"suspect_environmental"`
}

// VerificationRunResult é o resultado completo de uma execução no sandbox.
type VerificationRunResult struct {
	Checks           []CheckObservation `json:"checks"`
	SnapshotDigest   string             `json:"snapshot_digest"`
	DependencyDigest string             `json:"dependency_digest"`
	SandboxDigest    string             `json:"sandbox_digest"`
	SandboxPolicy    SandboxPolicy      `json:"sandbox_policy"`
}

// SandboxPolicy é a política efetiva do sandbox de avaliação.
type SandboxPolicy struct {
	Engine        string            `json:"engine"`
	Network       bool              `json:"network"`
	UserNamespace bool              `json:"user_namespace"`
	PIDNamespace  bool              `json:"pid_namespace"`
	MountsRO      []string          `json:"mounts_ro"`
	Mounts        []ProjectMount    `json:"mounts"`
	Home          string            `json:"home"`
	EnvAllowlist  []string          `json:"env_allowlist"`
	PathPrepend   []string          `json:"path_prepend"`
	Env           map[string]string `json:"env"`
}

var toolchainPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)cannot find module`),
	regexp.MustCompile(`(?i)cannot find package`),
	regexp.MustCompile(`(?i)module not found`),
	regexp.MustCompile(`(?i)no such file or directory`),
	regexp.MustCompile(`(?i)command not found`),
	regexp.MustCompile(`(?i)is not in the dependency tree`),
	regexp.MustCompile(`(?i)failed to resolve`),
}

// LooksEnvironmental informa se a saída parece erro de ambiente/import, não a
// asserção. O AC baseline não pode aceitar essa falha como prova de causalidade.
func LooksEnvironmental(output string) bool {
	for _, pattern := range toolchainPatterns {
		if pattern.MatchString(output) {
			return true
		}
	}
	return false
}

// runtimeMounts devolve o diretório do runtime quando ele não vive em /usr ou
// /bin.
func runtimeMounts(runtime string) []string {
	resolved, err := filepath.Abs(runtime)
	if err != nil {
		return nil
	}
	if strings.HasPrefix(resolved, "/usr/") || strings.HasPrefix(resolved, "/bin/") {
		return nil
	}
	return []string{filepath.Dir(filepath.Dir(resolved))}
}

func executableRoot(executable string) (string, bool) {
	if !filepath.IsAbs(executable) {
		return "", false
	}
	return filepath.Dir(filepath.Dir(executable)), true
}

// ExecutableBinds devolve os vínculos dos executáveis declarados nos checks.
//
// O plano pode citar um caminho simbólico do runtime (`…/bun/latest/bin/bun`)
// enquanto o processo real é `…/bun/1.4.2/bin/bun`. Sem ligar o diretório real
// ao caminho declarado, o sandbox executaria um caminho que não existe — e o
// check falharia por ambiente, não por comportamento.
func ExecutableBinds(command []string) [][2]string {
	if len(command) == 0 {
		return nil
	}
	executable := command[0]
	declared, ok := executableRoot(executable)
	if !ok {
		return nil
	}
	realRoot := declared
	if resolved, err := filepath.EvalSymlinks(executable); err == nil {
		if root, ok := executableRoot(resolved); ok {
			realRoot = root
		}
	}
	binds := [][2]string{{realRoot, realRoot}}
	if realRoot != declared {
		binds = append(binds, [2]string{realRoot, declared})
	}
	return binds
}

// sortedUnique devolve os valores sem repetição, em ordem de unidade de código
// UTF-16, como o .sort() do JavaScript.
func sortedUnique(values []string) []string {
	seen := make(map[string]bool, len(values))
	unique := make([]string, 0, len(values))
	for _, value := range values {
		if seen[value] {
			continue
		}
		seen[value] = true
		unique = append(unique, value)
	}
	sort.Slice(unique, func(i, j int) bool { return lessUTF16(unique[i], unique[j]) })
	return unique
}

// BuildSandboxPolicy monta a política do sandbox: o host inteiro NÃO é montado.
// Sem isso, ler a chave do verificador (ou qualquer arquivo do operador) seria
// trivial para o código avaliado.
func BuildSandboxPolicy(runtime string, commands [][]string, project *ProjectSandboxConfig) SandboxPolicy {
	mounts := []string{"/usr", "/bin", "/lib", "/lib64", "/etc"}
	mounts = append(mounts, runtimeMounts(runtime)...)
	execRoots := make([]string, 0, len(commands))
	for _, command := range commands {
		for _, bind := range ExecutableBinds(command) {
			root := bind[0]
			if strings.HasPrefix(root, "/usr/") || strings.HasPrefix(root, "/bin/") {
				continue
			}
			execRoots = append(execRoots, root)
		}
	}
	mountsRO := make([]string, 0, len(mounts)+len(execRoots))
	mountsRO = append(mountsRO, mounts...)
	mountsRO = append(mountsRO, execRoots...)

	mountsList := make([]ProjectMount, 0)
	pathPrepend := make([]string, 0)
	env := make(map[string]string)
	home := "/nonexistent"
	if project != nil {
		mountsRO = append(mountsRO, project.MountsRO...)
		mountsRO = append(mountsRO, project.PathPrepend...)
		mountsList = append(mountsList, project.Mounts...)
		pathPrepend = append(pathPrepend, project.PathPrepend...)
		if project.Home != "" {
			home = project.Home
		}
		for name, value := range project.Env {
			env[name] = value
		}
	}
	return SandboxPolicy{
		Engine:        "bwrap",
		Network:       false,
		UserNamespace: true,
		PIDNamespace:  true,
		MountsRO:      sortedUnique(mountsRO),
		Mounts:        mountsList,
		Home:          home,
		EnvAllowlist:  []string{"PATH", "TMPDIR", "LANG", "LC_ALL", "TERM"},
		PathPrepend:   pathPrepend,
		Env:           env,
	}
}

// sandboxArgs monta o argv do bwrap. As montagens extras (executáveis e
// dependências) entram DEPOIS de `--bind workDir`: uma montagem anterior seria
// encoberta pelo bind da árvore e `node_modules` desapareceria do sandbox.
func sandboxArgs(policy SandboxPolicy, workDir string, extraRoBinds [][2]string, command []string) []string {
	args := make([]string, 0, 32+2*len(policy.MountsRO)+4*len(policy.Mounts)+2*len(extraRoBinds)+len(command))
	for _, mount := range policy.MountsRO {
		args = append(args, "--ro-bind", mount, mount)
	}
	if policy.Home != "/nonexistent" {
		args = append(args, "--dir", policy.Home)
	}
	for _, mount := range policy.Mounts {
		args = append(args, "--dir", mount.Dest)
		args = append(args, "--ro-bind", mount.Source, mount.Dest)
	}
	args = append(args, "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp")
	args = append(args, "--bind", workDir, workDir)
	// Depois do bind da árvore: uma montagem anterior seria encoberta por ele.
	for _, bind := range extraRoBinds {
		args = append(args, "--ro-bind", bind[0], bind[1])
	}
	args = append(args, "--chdir", workDir)
	args = append(args, "--unshare-user", "--unshare-pid", "--unshare-net", "--die-with-parent")
	args = append(args, "--clearenv")
	args = append(args, "--setenv", "HOME", policy.Home)
	args = append(args, "--setenv", "TMPDIR", "/tmp")
	args = append(args, "--setenv", "PATH", strings.Join(append(append([]string{}, policy.PathPrepend...), "/usr/bin", "/bin"), ":"))
	for _, name := range sortedKeys(policy.Env) {
		args = append(args, "--setenv", name, policy.Env[name])
	}
	args = append(args, "--")
	args = append(args, command...)
	return args
}

func sortedKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return lessUTF16(keys[i], keys[j]) })
	return keys
}

type sandboxSpawnResult struct {
	status   int
	output   string
	timedOut bool
}

func spawnInSandbox(
	ctx context.Context,
	readiness VerifierReadiness,
	policy SandboxPolicy,
	workDir string,
	extraRoBinds [][2]string,
	command []string,
	timeoutMs int,
) (sandboxSpawnResult, error) {
	if timeoutMs > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(timeoutMs)*time.Millisecond)
		defer cancel()
	}
	args := sandboxArgs(policy, workDir, extraRoBinds, command)
	cmd := exec.CommandContext(ctx, readiness.Bwrap, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()
	timedOut := ctx.Err() == context.DeadlineExceeded
	status := 1
	if cmd.ProcessState != nil {
		if code := cmd.ProcessState.ExitCode(); code >= 0 {
			status = code
		}
	}
	if runErr != nil && !timedOut && cmd.ProcessState == nil {
		return sandboxSpawnResult{}, unavailable(
			fmt.Sprintf("isolamento indisponível: não foi possível executar %s", readiness.Bwrap),
			runErr.Error(),
		)
	}
	if ctx.Err() != nil && !timedOut {
		return sandboxSpawnResult{}, fmt.Errorf("verifier: execução do sandbox cancelada: %w", ctx.Err())
	}
	return sandboxSpawnResult{status: status, output: stdout.String() + stderr.String(), timedOut: timedOut}, nil
}

func digestOutput(output string) string { return digestBytes([]byte(output)) }

// jsonString devolve value como string JSON, com o mesmo escape do
// JSON.stringify usado nas mensagens da referência.
func jsonString(value string) string {
	data, err := jsonx.Insertion(value)
	if err != nil {
		return value
	}
	return string(data)
}

func tail(output string, limit int) string {
	trimmed := strings.TrimSpace(output)
	if len(trimmed) > limit {
		return trimmed[len(trimmed)-limit:]
	}
	return trimmed
}

// copyTree copia source em destination preservando vínculos simbólicos e modos,
// com a mesma semântica de mesclagem do cpSync recursivo.
func copyTree(source, destination string) error {
	return copyTreeEntry(source, destination)
}

func copyTreeEntry(source, destination string) error {
	info, err := os.Lstat(source)
	if err != nil {
		return fmt.Errorf("verifier: ler %s: %w", source, err)
	}
	switch {
	case info.Mode()&os.ModeSymlink != 0:
		target, err := os.Readlink(source)
		if err != nil {
			return fmt.Errorf("verifier: ler o vínculo %s: %w", source, err)
		}
		if err := os.MkdirAll(filepath.Dir(destination), 0o777); err != nil {
			return fmt.Errorf("verifier: criar %s: %w", filepath.Dir(destination), err)
		}
		if err := os.RemoveAll(destination); err != nil {
			return fmt.Errorf("verifier: remover %s: %w", destination, err)
		}
		if err := os.Symlink(target, destination); err != nil {
			return fmt.Errorf("verifier: criar o vínculo %s: %w", destination, err)
		}
		return nil
	case info.IsDir():
		if err := os.MkdirAll(destination, info.Mode().Perm()); err != nil {
			return fmt.Errorf("verifier: criar %s: %w", destination, err)
		}
		entries, err := os.ReadDir(source)
		if err != nil {
			return fmt.Errorf("verifier: listar %s: %w", source, err)
		}
		for _, entry := range entries {
			if err := copyTreeEntry(filepath.Join(source, entry.Name()), filepath.Join(destination, entry.Name())); err != nil {
				return err
			}
		}
		return nil
	case info.Mode().IsRegular():
		data, err := os.ReadFile(source)
		if err != nil {
			return fmt.Errorf("verifier: ler %s: %w", source, err)
		}
		if err := os.MkdirAll(filepath.Dir(destination), 0o777); err != nil {
			return fmt.Errorf("verifier: criar %s: %w", filepath.Dir(destination), err)
		}
		if err := os.WriteFile(destination, data, info.Mode().Perm()); err != nil {
			return fmt.Errorf("verifier: gravar %s: %w", destination, err)
		}
		return nil
	default:
		// Sockets, fifos e dispositivos não são copiados.
		return nil
	}
}

// applyBaselineImplementation reverte os arquivos de implementação ao conteúdo
// do commit aprovado.
func applyBaselineImplementation(ctx context.Context, runner *gitx.Runner, workDir string, approval Approval) error {
	for _, relative := range approval.ImplementationFiles {
		target := filepath.Join(workDir, relative)
		args := []string{"show", approval.BaselineCommit + ":" + relative}
		shown, err := runner.Run(ctx, args, gitx.Options{})
		if err != nil {
			return err
		}
		if shown.OK() {
			if err := os.WriteFile(target, shown.Stdout, 0o644); err != nil {
				return fmt.Errorf("verifier: gravar %s: %w", target, err)
			}
			continue
		}
		// Não existia no baseline: a implementação da task é o arquivo novo.
		if _, err := os.Stat(target); err == nil {
			if err := os.Remove(target); err != nil {
				return fmt.Errorf("verifier: remover %s: %w", target, err)
			}
		}
	}
	return nil
}

// RunVerificationOptions são as entradas de RunVerification.
type RunVerificationOptions struct {
	// Ctx limita a execução dos checks. Nil usa context.Background.
	Ctx      context.Context
	RootDir  string
	Approval Approval
	// TimeoutSeconds limita cada check. Zero usa 600.
	TimeoutSeconds int
	// VerifierRootDir é a raiz protegida. Vazio usa Root.
	VerifierRootDir string
}

// RunVerification executa os checks de aceitação dentro do sandbox.
//
// Regras que fazem a diferença entre "aceitação independente" e "mais um bun
// test":
//   - o diretório do candidato é uma CÓPIA do snapshot registrado;
//   - os arquivos de aceitação aprovados são restaurados da raiz protegida por
//     cima da cópia;
//   - HOME do sandbox não é o do operador, a rede está desligada e a raiz do
//     verificador não é montada;
//   - o veredicto é um resultado observado pelo verificador, nunca uma linha
//     que o candidato imprimiu se declarando aprovado.
func RunVerification(options RunVerificationOptions) (VerificationRunResult, error) {
	ctx := options.Ctx
	if ctx == nil {
		ctx = context.Background()
	}
	root, err := resolveRoot(options.VerifierRootDir)
	if err != nil {
		return VerificationRunResult{}, err
	}
	readiness, err := RequireVerifierReady(root)
	if err != nil {
		return VerificationRunResult{}, err
	}
	if err := AssertProtectedOutsideRepository(root, options.RootDir); err != nil {
		return VerificationRunResult{}, err
	}
	commands := make([][]string, 0, len(options.Approval.Checks))
	for _, check := range options.Approval.Checks {
		commands = append(commands, check.Command)
	}
	project, err := ProjectSandbox(options.RootDir, root)
	if err != nil {
		return VerificationRunResult{}, err
	}
	policy := BuildSandboxPolicy(readiness.Runtime, commands, project)
	timeoutSeconds := options.TimeoutSeconds
	if timeoutSeconds == 0 {
		timeoutSeconds = 600
	}
	timeoutMs := timeoutSeconds * 1000

	snapshot, err := CaptureSnapshot(options.RootDir)
	if err != nil {
		return VerificationRunResult{}, err
	}
	dependency, err := CaptureDependencyDigest(options.RootDir)
	if err != nil {
		return VerificationRunResult{}, err
	}
	dependencyMounts := PresentDependencyPaths(options.RootDir)

	scratch, err := os.MkdirTemp("", "pwn-verify-")
	if err != nil {
		return VerificationRunResult{}, fmt.Errorf("verifier: criar o diretório temporário: %w", err)
	}
	defer func() { _ = os.RemoveAll(scratch) }()

	workDir := filepath.Join(scratch, "candidate")
	baselineDir := filepath.Join(scratch, "baseline")
	checks := make([]CheckObservation, 0, len(options.Approval.Checks))

	if err := MaterializeSnapshot(snapshot, workDir, options.RootDir); err != nil {
		return VerificationRunResult{}, err
	}

	// Restaura o conteúdo aprovado: o que roda é a versão guardada na raiz
	// protegida, não a versão que o repositório apresenta.
	for _, entry := range options.Approval.ApprovedFiles {
		content, ok := ApprovedFileContent(options.Approval, entry.Path, root)
		if !ok {
			return VerificationRunResult{}, fmt.Errorf("arquivo aprovado ausente na raiz protegida: %s", entry.Path)
		}
		if digestBytes([]byte(content)) != entry.SHA256 {
			return VerificationRunResult{}, fmt.Errorf("arquivo aprovado corrompido na raiz protegida: %s", entry.Path)
		}
		target := filepath.Join(workDir, entry.Path)
		if err := os.WriteFile(target, []byte(content), 0o644); err != nil {
			return VerificationRunResult{}, fmt.Errorf("verifier: restaurar %s: %w", target, err)
		}
	}

	runner := gitx.New(options.RootDir)
	for _, check := range options.Approval.Checks {
		observation, err := executeCheck(ctx, executeCheckOptions{
			check:             check,
			readiness:         readiness,
			policy:            policy,
			rootDir:           options.RootDir,
			runner:            runner,
			approval:          options.Approval,
			workDir:           workDir,
			baselineDir:       baselineDir,
			execBinds:         ExecutableBinds(check.Command),
			dependencySources: dependencyMounts,
			timeoutMs:         timeoutMs,
			timeoutSeconds:    timeoutSeconds,
		})
		if err != nil {
			return VerificationRunResult{}, err
		}
		checks = append(checks, observation)
	}

	canonicalPolicy, err := jsonx.Canonical(policy)
	if err != nil {
		return VerificationRunResult{}, fmt.Errorf("verifier: serializar a política: %w", err)
	}
	return VerificationRunResult{
		Checks:           checks,
		SnapshotDigest:   snapshot.Digest,
		DependencyDigest: dependency.Digest,
		SandboxDigest:    digestBytes(canonicalPolicy),
		SandboxPolicy:    policy,
	}, nil
}

type executeCheckOptions struct {
	check             ApprovedCheck
	readiness         VerifierReadiness
	policy            SandboxPolicy
	rootDir           string
	runner            *gitx.Runner
	approval          Approval
	workDir           string
	baselineDir       string
	execBinds         [][2]string
	dependencySources []string
	timeoutMs         int
	timeoutSeconds    int
}

func executeCheck(ctx context.Context, options executeCheckOptions) (CheckObservation, error) {
	check := options.check
	bindsFor := func(tree string) [][2]string {
		binds := make([][2]string, 0, len(options.execBinds)+len(options.dependencySources))
		binds = append(binds, options.execBinds...)
		for _, source := range options.dependencySources {
			binds = append(binds, [2]string{source, filepath.Join(tree, filepath.Base(source))})
		}
		return binds
	}

	candidate, err := spawnInSandbox(ctx, options.readiness, options.policy, options.workDir, bindsFor(options.workDir), check.Command, options.timeoutMs)
	if err != nil {
		return CheckObservation{}, err
	}
	base := CheckObservation{
		ID:           check.ID,
		Command:      check.Command,
		Outcome:      "pass",
		ExitCode:     candidate.status,
		OutputDigest: digestOutput(candidate.output),
		OutputTail:   tail(candidate.output, 2000),
	}
	if candidate.timedOut {
		base.Outcome = "blocked"
		base.Reason = fmt.Sprintf("check %s excedeu %ds", check.ID, options.timeoutSeconds)
		return base, nil
	}
	if candidate.status != 0 {
		base.Outcome = "fail"
		base.Reason = fmt.Sprintf("check %s terminou com exit %d", check.ID, candidate.status)
		return base, nil
	}
	if check.ExpectOutput != nil && !strings.Contains(candidate.output, *check.ExpectOutput) {
		base.Outcome = "fail"
		base.Reason = fmt.Sprintf("check %s não produziu o texto aprovado %s", check.ID, jsonString(*check.ExpectOutput))
		return base, nil
	}
	if !check.RequireBaselineFailure {
		return base, nil
	}

	// Causalidade: a mesma asserção, com a implementação da task revertida ao
	// commit aprovado, precisa FALHAR. Um AC que passa sem a implementação não
	// aceita nada.
	if err := copyTree(options.workDir, options.baselineDir); err != nil {
		return CheckObservation{}, err
	}
	if err := applyBaselineImplementation(ctx, options.runner, options.baselineDir, options.approval); err != nil {
		return CheckObservation{}, err
	}
	baseline, err := spawnInSandbox(ctx, options.readiness, options.policy, options.baselineDir, bindsFor(options.baselineDir), check.Command, options.timeoutMs)
	if err != nil {
		return CheckObservation{}, err
	}
	suspect := LooksEnvironmental(baseline.output)
	observation := &BaselineObservation{
		ExitCode:             baseline.status,
		OutputDigest:         digestOutput(baseline.output),
		OutputTail:           tail(baseline.output, 2000),
		SuspectEnvironmental: suspect,
	}
	base.Baseline = observation
	if baseline.timedOut {
		base.Outcome = "blocked"
		base.Reason = fmt.Sprintf("baseline de %s excedeu o tempo do check", check.ID)
		return base, nil
	}
	if baseline.status == 0 {
		base.Outcome = "fail"
		base.Reason = fmt.Sprintf("%s passa sem a implementação da task (prova vácua; não demonstra causalidade)", check.ID)
		return base, nil
	}
	if suspect {
		base.Outcome = "fail"
		base.Reason = fmt.Sprintf("%s: a falha no baseline parece erro de ambiente/import; a asserção não demonstrou depender da implementação", check.ID)
		return base, nil
	}
	return base, nil
}
