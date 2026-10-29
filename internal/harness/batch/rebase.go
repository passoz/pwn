package batch

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/passoz/pwn/internal/harness/plan"
	"github.com/passoz/pwn/internal/harness/run"
	"github.com/passoz/pwn/internal/harness/work"
	"github.com/passoz/pwn/internal/platform/fsx"
	"github.com/passoz/pwn/internal/platform/gitx"
	"github.com/passoz/pwn/internal/platform/sandbox"
)

// RebaseResult é o resultado de RebaseTask.
type RebaseResult struct {
	TaskID   string `json:"taskId"`
	Worktree string `json:"worktree"`
	// Base é o HEAD sobre o qual a entrega foi reaplicada.
	Base string `json:"base"`
	// Conflicts são os arquivos com conflito de 3-way; vazio quando a
	// reaplicação foi limpa.
	Conflicts []string `json:"conflicts"`
	// Evidence é a evidência local avaliada no worktree novo: só vale se
	// VERIFIED e sem STALE.
	Evidence work.EvidenceState `json:"evidence"`
	// PatchFile é a entrega original (diff contra a base antiga), para refazer o
	// audit se a evidência caducou.
	PatchFile string `json:"patchFile"`
}

// RebaseOptions são as entradas de RebaseTask.
type RebaseOptions struct {
	Root   string
	TaskID string
}

// RebaseTask refaz uma task sobre o HEAD atual: novo worktree no HEAD, entrega
// reaplicada com `--3way`. Conflito fica no worktree (marcadores) para o agente
// resolver: o harness nunca decide a resolução.
//
// A evidência é copiada e REAVALIADA — se um arquivo declarado mudou na mescla,
// ela fica STALE e o audit precisa ser refeito.
func RebaseTask(ctx context.Context, options RebaseOptions) (RebaseResult, error) {
	root := options.Root
	taskID := options.TaskID
	var result RebaseResult
	err := fsx.WithFileLock(manifestFile(root), func() error {
		manifest, err := ReadBatch(root)
		if err != nil {
			return err
		}
		if manifest == nil {
			return errors.New("nenhum lote ativo: prepare um com 'pwn work batch prepare'")
		}
		var task *BatchTask
		for index := range manifest.Tasks {
			if manifest.Tasks[index].ID == taskID {
				task = &manifest.Tasks[index]
				break
			}
		}
		if task == nil {
			ids := make([]string, 0, len(manifest.Tasks))
			for _, entry := range manifest.Tasks {
				ids = append(ids, entry.ID)
			}
			joined := "vazio"
			if len(ids) > 0 {
				joined = strings.Join(ids, ", ")
			}
			return fmt.Errorf("a task %s não está no lote ativo (%s)", taskID, joined)
		}
		head, err := gitx.New(root).Head(ctx)
		if err != nil {
			return err
		}
		if head != manifest.Head {
			return fmt.Errorf(
				"HEAD mudou fora do lote (esperado %s, atual %s): commits externos não são suportados — desfaça-os ou descarte o lote",
				short(manifest.Head), short(head),
			)
		}
		dirty, err := BlockingChanges(ctx, root)
		if err != nil {
			return err
		}
		if len(dirty) > 0 {
			return fmt.Errorf("a árvore principal tem alterações não commitadas (%s); commite ou descarte antes", preview(dirty))
		}
		oldBase := baseOf(*manifest, *task)
		if oldBase == head {
			return fmt.Errorf("a task %s já está sobre o HEAD atual; não há o que refazer", taskID)
		}

		capture, reasons := captureDelivery(ctx, *task, oldBase)
		if len(reasons) > 0 {
			return errors.New(strings.Join(reasons, "; "))
		}
		if len(capture.Files) == 0 {
			return fmt.Errorf("a task %s não tem alterações para reaplicar", taskID)
		}

		session, err := sandbox.CreateGitWorktreeSandbox(ctx, manifest.BatchID+"-"+taskID+"-"+randomSuffix(), root)
		if err != nil {
			return err
		}
		patchFile := session.WorktreePath + patchSuffix
		cleanup := func() {
			_ = sandbox.CleanupGitWorktreeSandbox(ctx, session, root)
			_ = os.Remove(patchFile)
		}

		injected, err := run.PrepareSandbox(session.WorktreePath, root)
		if err != nil {
			cleanup()
			return err
		}
		markdownPath := plan.TasksMarkdownPath(manifest.WorkID, root)
		relative, err := filepath.Rel(root, markdownPath)
		if err != nil {
			cleanup()
			return err
		}
		planTarget := filepath.Join(session.WorktreePath, relative)
		if err := os.MkdirAll(filepath.Dir(planTarget), 0o777); err != nil {
			cleanup()
			return fmt.Errorf("batch: criar %s: %w", filepath.Dir(planTarget), err)
		}
		content, err := os.ReadFile(markdownPath)
		if err != nil {
			cleanup()
			return fmt.Errorf("batch: ler %s: %w", markdownPath, err)
		}
		if err := os.WriteFile(planTarget, content, 0o644); err != nil {
			cleanup()
			return fmt.Errorf("batch: copiar o plano para %s: %w", planTarget, err)
		}
		if err := copyTaskEvidence(task.Worktree, session.WorktreePath, manifest.WorkID, taskID); err != nil {
			cleanup()
			return err
		}
		if err := os.WriteFile(patchFile, capture.Patch, 0o644); err != nil {
			cleanup()
			return fmt.Errorf("batch: gravar %s: %w", patchFile, err)
		}

		runner := gitx.New(session.WorktreePath)
		applyErr := runner.Apply(ctx, capture.Patch, gitx.ApplyOptions{ThreeWay: true})
		conflictDiff, err := runner.Diff(ctx, gitx.DiffOptions{
			NameOnly:       true,
			NullTerminated: true,
			DiffFilter:     "U",
		})
		if err != nil {
			cleanup()
			return fmt.Errorf("batch: listar conflitos em %s: %w", session.WorktreePath, err)
		}
		conflicts := splitNUL(conflictDiff)
		// Falha sem conflito (patch corrompido, caminho inexistente): nada a
		// resolver; o worktree antigo segue intacto.
		if applyErr != nil && len(conflicts) == 0 {
			cleanup()
			return fmt.Errorf("git apply --3way falhou sem gerar conflitos: %s", gitDetail(applyErr))
		}

		replaced := *task
		replaced.RunID = session.RunID
		replaced.Worktree = session.WorktreePath
		replaced.Branch = session.BranchName
		replaced.GitDir = session.GitDir
		replaced.Injected = injected
		replaced.Base = head
		updated := *manifest
		updated.Tasks = make([]BatchTask, 0, len(manifest.Tasks))
		for _, entry := range manifest.Tasks {
			if entry.ID == taskID {
				updated.Tasks = append(updated.Tasks, replaced)
				continue
			}
			updated.Tasks = append(updated.Tasks, entry)
		}
		if err := writeManifest(root, updated); err != nil {
			cleanup()
			return err
		}
		if err := dropTask(ctx, *task, root); err != nil {
			return err
		}
		evidence, err := localEvidence(session.WorktreePath, manifest.WorkID, taskID)
		if err != nil {
			return err
		}
		result = RebaseResult{
			TaskID:    taskID,
			Worktree:  session.WorktreePath,
			Base:      head,
			Conflicts: conflicts,
			Evidence:  evidence,
			PatchFile: patchFile,
		}
		return nil
	}, lockOptions())
	if err != nil {
		return RebaseResult{}, err
	}
	return result, nil
}

// AbortBatch descarta o lote ativo: remove worktrees e branches (o trabalho não
// integrado se perde). Devolve nil quando não havia lote.
func AbortBatch(ctx context.Context, root string) (*BatchManifest, error) {
	var result *BatchManifest
	err := fsx.WithFileLock(manifestFile(root), func() error {
		manifest, err := ReadBatch(root)
		if err != nil {
			return err
		}
		if manifest == nil {
			return nil
		}
		for _, task := range manifest.Tasks {
			if err := dropTask(ctx, task, root); err != nil {
				return err
			}
		}
		if err := os.Remove(manifestFile(root)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("batch: remover o manifesto: %w", err)
		}
		result = manifest
		return nil
	}, lockOptions())
	if err != nil {
		return nil, err
	}
	return result, nil
}

func randomSuffix() string {
	var buffer [3]byte
	if _, err := rand.Read(buffer[:]); err != nil {
		return "000000"
	}
	return hex.EncodeToString(buffer[:])
}
