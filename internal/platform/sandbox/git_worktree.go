// Package sandbox isola a execução do agente em um worktree Git próprio e
// oferece o envelope de bwrap para isolamento no sistema operacional.
//
// Um sandbox nasce em `.pwn/sandboxes/<run-id>` a partir do HEAD, em um branch
// `pwn-sandbox-<run-id>`. O worktree identifica o repositório exato pelo
// `git rev-parse --absolute-git-dir`: sem essa âncora, apagar o `.git` do
// sandbox faz o Git subir para o repositório-pai e o inventário do diff guard
// passa a descrever outra árvore.
package sandbox

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/passoz/pwn/internal/platform/fsx"
	"github.com/passoz/pwn/internal/platform/gitx"
)

// SandboxError é uma recusa do sandbox: o agente não pode ser executado.
type SandboxError struct {
	// RunID é o run id informado na criação.
	RunID string
	// Reason é o motivo curto, estável para comparação.
	Reason string
	// Message é a mensagem completa mostrada ao operador.
	Message string
}

func (e *SandboxError) Error() string {
	return e.Message
}

// Session descreve o sandbox criado para uma run.
type Session struct {
	RunID string
	// WorktreePath é o diretório do worktree isolado.
	WorktreePath string
	// BranchName é o branch do worktree.
	BranchName string
	// Created informa se esta chamada criou o worktree. Só `true` pode limpar.
	Created bool
	// GitDir é o `git rev-parse --absolute-git-dir` do worktree na criação.
	GitDir string
}

// Opções do lock que serializa as operações que mutam o repositório
// (`worktree add/remove`, `branch -D`): runs paralelas disputam
// `.git/index.lock`, `.git/config` e `.git/worktrees`. O timeout cobre a fila de
// N checkouts; o stale, menor, recupera o lock de um processo morto.
const (
	worktreeLockTimeout = 180 * time.Second
	worktreeLockStale   = 120 * time.Second
)

var invalidRunIDChar = regexp.MustCompile(`[^a-zA-Z0-9_-]`)

// sanitizeRunID troca todo caractere fora de `[a-zA-Z0-9_-]` por `_`, para que
// o run id nunca escape do diretório de sandboxes nem do namespace de branch.
func sanitizeRunID(runID string) string {
	return invalidRunIDChar.ReplaceAllString(runID, "_")
}

// worktreeLockOptions devolve as opções do lock de worktree.
func worktreeLockOptions() fsx.LockOptions {
	return fsx.LockOptions{Timeout: worktreeLockTimeout, Stale: worktreeLockStale}
}

// ResolveGitDir devolve o diretório git absoluto de cwd. O segundo valor é
// false quando cwd não resolve para um repositório válido, como no original.
func ResolveGitDir(ctx context.Context, cwd string) (string, bool) {
	if ctx == nil {
		ctx = context.Background()
	}
	gitDir, err := gitx.New(cwd).GitDir(ctx)
	if err != nil || gitDir == "" {
		return "", false
	}
	return gitDir, true
}

// resolveRoot devolve o diretório raiz absoluto. Vazio usa o diretório atual.
func resolveRoot(rootDir string) (string, error) {
	if rootDir == "" {
		root, err := os.Getwd()
		if err != nil {
			return "", fmt.Errorf("sandbox: obter diretório atual: %w", err)
		}
		return root, nil
	}
	root, err := filepath.Abs(rootDir)
	if err != nil {
		return "", fmt.Errorf("sandbox: resolver %s: %w", rootDir, err)
	}
	return root, nil
}

// CreateGitWorktreeSandbox cria o worktree isolado da run.
//
// Um caminho preexistente nunca é adotado. O run id é único por construção
// (timestamp + bytes aleatórios): um caminho já existente é sobra de execução
// anterior ou corrida entre runs. Reusar um diretório que não é worktree faria o
// comando rodar em qualquer lugar; reusar um worktree válido faria duas runs
// compartilharem a mesma árvore. Os dois casos devolvem SandboxError.
//
// rootDir vazio usa o diretório atual.
func CreateGitWorktreeSandbox(ctx context.Context, runID, rootDir string) (Session, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	root, err := resolveRoot(rootDir)
	if err != nil {
		return Session{}, err
	}

	sanitized := sanitizeRunID(runID)
	sandboxesDir := filepath.Join(root, ".pwn", "sandboxes")
	worktreeDir := filepath.Join(sandboxesDir, sanitized)
	branchName := "pwn-sandbox-" + sanitized

	if err := os.MkdirAll(sandboxesDir, 0o755); err != nil {
		return Session{}, fmt.Errorf("sandbox: criar %s: %w", sandboxesDir, err)
	}

	var session Session
	err = fsx.WithFileLock(filepath.Join(root, ".pwn", "git-worktree"), func() error {
		_, statErr := os.Lstat(worktreeDir)
		switch {
		case statErr == nil:
			if _, isRepo := ResolveGitDir(ctx, worktreeDir); !isRepo {
				return &SandboxError{
					RunID:  runID,
					Reason: "pre-existing path is not a git worktree",
					Message: fmt.Sprintf(
						"[SANDBOX ABORT] %s já existe e não é um worktree Git válido (%s). "+
							"Remova o diretório antes de reexecutar.",
						worktreeDir, runID,
					),
				}
			}
			return &SandboxError{
				RunID:  runID,
				Reason: "run id collision: worktree already exists",
				Message: fmt.Sprintf(
					"[SANDBOX ABORT] colisão de run id: o worktree %s já existe (%s). "+
						"Run ids são únicos por construção; reuso indica corrida ou sobra de execução anterior.",
					worktreeDir, runID,
				),
			}
		case !errors.Is(statErr, fs.ErrNotExist):
			return fmt.Errorf("sandbox: inspecionar %s: %w", worktreeDir, statErr)
		}

		runner := gitx.New(root)
		if addErr := runner.WorktreeAdd(ctx, gitx.WorktreeAddOptions{
			Path:   worktreeDir,
			Branch: branchName,
			Ref:    "HEAD",
		}); addErr != nil {
			reason := worktreeFailureReason(addErr)
			return &SandboxError{
				RunID:  runID,
				Reason: reason,
				Message: fmt.Sprintf(
					"[SANDBOX ABORT] Falha ao criar worktree para run %s. "+
						"Execução bloqueada — agente NÃO será executado no rootDir. "+
						"Motivo: %s",
					sanitized, reason,
				),
			}
		}

		gitDir, gitErr := gitx.New(worktreeDir).GitDir(ctx)
		if gitErr != nil || gitDir == "" {
			return &SandboxError{
				RunID:  runID,
				Reason: "git worktree add succeeded but rev-parse failed",
				Message: fmt.Sprintf(
					"[SANDBOX ABORT] Worktree recém-criado em %s não resolve para um repositório Git (%s).",
					worktreeDir, runID,
				),
			}
		}

		session = Session{
			RunID:        runID,
			WorktreePath: worktreeDir,
			BranchName:   branchName,
			Created:      true,
			GitDir:       gitDir,
		}
		return nil
	}, worktreeLockOptions())
	if err != nil {
		return Session{}, err
	}
	return session, nil
}

// worktreeFailureReason extrai o motivo de uma falha do `git worktree add`:
// stderr quando existe, senão o código de saída, senão a falha de infraestrutura.
func worktreeFailureReason(err error) string {
	var exitErr *gitx.ExitError
	if errors.As(err, &exitErr) {
		if exitErr.Result.Stderr != "" {
			return exitErr.Result.Stderr
		}
		return fmt.Sprintf("git worktree add exited with code %d", exitErr.Result.Exit)
	}
	return err.Error()
}

// CleanupGitWorktreeSandbox remove o worktree e o branch da sessão.
//
// A limpeza é best-effort, como no original: worktree já removido ou branch já
// apagado não são erro. O contexto cancelado não impede a remoção, porque um
// worktree órfão continua travando o repositório. Devolve erro somente quando o
// lock não pôde ser obtido.
func CleanupGitWorktreeSandbox(ctx context.Context, session Session, rootDir string) error {
	if !session.Created {
		return nil
	}
	if ctx == nil || ctx.Err() != nil {
		ctx = context.Background()
	}
	root, err := resolveRoot(rootDir)
	if err != nil {
		return err
	}

	return fsx.WithFileLock(filepath.Join(root, ".pwn", "git-worktree"), func() error {
		runner := gitx.New(root)
		_ = runner.WorktreeRemove(ctx, session.WorktreePath, true)
		_ = runner.BranchDelete(ctx, session.BranchName, true)
		return nil
	}, worktreeLockOptions())
}
