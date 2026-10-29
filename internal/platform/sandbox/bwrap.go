package sandbox

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
)

// bwrapProbeTimeout limita a sondagem de suporte. Um bwrap que trava não pode
// travar o CLI: o resultado, nesse caso, é "sem suporte".
const bwrapProbeTimeout = 15 * time.Second

// bwrapProbeCache guarda o resultado por caminho resolvido do bwrap. O
// resultado só depende do binário, então a sondagem roda uma vez por processo.
var bwrapProbeCache struct {
	sync.Mutex
	results map[string]bool
}

// IsBwrapSupported informa se o host suporta bwrap para isolamento de sandbox
// no sistema operacional. Sem bwrap no PATH, devolve false.
func IsBwrapSupported() bool {
	path, err := exec.LookPath("bwrap")
	if err != nil {
		return false
	}

	bwrapProbeCache.Lock()
	supported, cached := bwrapProbeCache.results[path]
	bwrapProbeCache.Unlock()
	if cached {
		return supported
	}

	supported = probeBwrap(path)

	bwrapProbeCache.Lock()
	if bwrapProbeCache.results == nil {
		bwrapProbeCache.results = make(map[string]bool)
	}
	bwrapProbeCache.results[path] = supported
	bwrapProbeCache.Unlock()
	return supported
}

// probeBwrap executa a sondagem real: montar `/` read-only e rodar `true`.
func probeBwrap(path string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), bwrapProbeTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, path, "--ro-bind", "/", "/", "--", "true")
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	return cmd.Run() == nil
}

// BwrapOptions controla o envelope de bwrap.
type BwrapOptions struct {
	// AllowNetwork mantém a rede disponível. Sem esta opção, o envelope inclui
	// `--unshare-net`.
	AllowNetwork bool
	// ExtraWritePaths são caminhos adicionais montados como escrita. Caminho
	// inexistente é ignorado.
	ExtraWritePaths []string
	// HomeDir substitui o diretório pessoal usado na máscara de credenciais.
	// Vazio usa os.UserHomeDir.
	HomeDir string
}

// WrapWithBwrap envelopa um comando para execução isolada via bwrap:
//   - todo o sistema de arquivos montado read-only (`--ro-bind / /`);
//   - `/dev` e `/proc` mínimos e seguros;
//   - `/tmp` privado em tmpfs;
//   - somente o cwd (e os caminhos extras declarados) com permissão de escrita;
//   - rede desligada (`--unshare-net`), exceto se a política permitir;
//   - namespace de processos isolado (`--unshare-pid`);
//   - morte junto com o pai (`--die-with-parent`).
//
// As credenciais do host (`~/.ssh`, `~/.aws`) e a chave do verificador dentro da
// árvore são mascaradas para que o agente não as leia.
func WrapWithBwrap(command string, args []string, cwd string, options BwrapOptions) (string, []string) {
	realCwd := cwd
	if resolved, err := filepath.EvalSymlinks(cwd); err == nil {
		realCwd = resolved
	}

	bwrapArgs := []string{
		"--ro-bind", "/", "/",
		"--dev", "/dev",
		"--proc", "/proc",
		"--tmpfs", "/tmp",
		"--bind", realCwd, realCwd,
		"--chdir", realCwd,
		"--unshare-pid",
		"--die-with-parent",
	}

	homeDir := options.HomeDir
	if homeDir == "" {
		homeDir, _ = os.UserHomeDir()
	}
	if homeDir != "" {
		for _, sensitive := range []string{
			filepath.Join(homeDir, ".ssh"),
			filepath.Join(homeDir, ".aws"),
		} {
			if _, err := os.Stat(sensitive); err == nil {
				bwrapArgs = append(bwrapArgs, "--tmpfs", sensitive)
			}
		}
	}

	verifierKeyPath := filepath.Join(realCwd, ".pwn", ".verifier_key")
	if _, err := os.Stat(verifierKeyPath); err == nil {
		bwrapArgs = append(bwrapArgs, "--ro-bind", "/dev/null", verifierKeyPath)
	}

	for _, extra := range options.ExtraWritePaths {
		realExtra, err := filepath.EvalSymlinks(extra)
		if err != nil {
			continue
		}
		bwrapArgs = append(bwrapArgs, "--bind", realExtra, realExtra)
	}

	if !options.AllowNetwork {
		bwrapArgs = append(bwrapArgs, "--unshare-net")
	}

	bwrapArgs = append(bwrapArgs, "--", command)
	bwrapArgs = append(bwrapArgs, args...)
	return "bwrap", bwrapArgs
}
