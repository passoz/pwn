// Package proc executa jobs em pool com concorrência limitada, captura de
// stdout/stderr e timeout com morte do grupo de processos.
package proc

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// Job é um comando a executar.
type Job struct {
	ID      string
	Command []string
	// Dir é o diretório de trabalho. Vazio herda o do processo atual.
	Dir string
	// Env é acrescentado ao ambiente do processo atual. Vazio herda o ambiente.
	Env map[string]string
}

// Result é o resultado observável de um Job.
type Result struct {
	ID       string
	Status   int
	Stdout   string
	Stderr   string
	Duration time.Duration
	TimedOut bool
}

// Options controla RunPool.
type Options struct {
	// Concurrency é o número máximo de jobs simultâneos. Zero ou negativo vale 1.
	Concurrency int
	// Timeout mata o job quando expira. Zero desabilita o timeout.
	Timeout time.Duration
	// OnResult é chamado a cada job concluído, na ordem de conclusão. As chamadas
	// são serializadas; o callback não deve bloquear.
	OnResult func(Result)
}

// DefaultConcurrency devolve max(1, min(NumCPU-1, 8)).
//
// Diferença de plataforma: o TypeScript usa os.availableParallelism(), que
// respeita limites de CPU do processo (cgroup/affinity); aqui usamos
// runtime.NumCPU(), que em Go pode reportar o total da máquina. O teto de 8
// limita o impacto em máquinas grandes.
func DefaultConcurrency() int {
	n := runtime.NumCPU() - 1
	if n < 1 {
		n = 1
	}
	if n > 8 {
		n = 8
	}
	return n
}

// RunPool executa jobs com no máximo opts.Concurrency simultâneos e devolve os
// resultados na ordem de jobs, independentemente da ordem de conclusão.
func RunPool(jobs []Job, opts Options) []Result {
	results := make([]Result, len(jobs))
	if len(jobs) == 0 {
		return results
	}
	limit := opts.Concurrency
	if limit < 1 {
		limit = 1
	}
	if limit > len(jobs) {
		limit = len(jobs)
	}

	var next atomic.Int64
	var callbackMu sync.Mutex
	var wg sync.WaitGroup
	for range limit {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				index := int(next.Add(1)) - 1
				if index >= len(jobs) {
					return
				}
				result := runOne(jobs[index], opts.Timeout)
				results[index] = result
				if opts.OnResult != nil {
					callbackMu.Lock()
					opts.OnResult(result)
					callbackMu.Unlock()
				}
			}
		}()
	}
	wg.Wait()
	return results
}

func runOne(job Job, timeout time.Duration) Result {
	started := time.Now()
	result := Result{ID: job.ID}
	finish := func() Result {
		result.Duration = time.Since(started)
		return result
	}

	if len(job.Command) == 0 {
		result.Status = 127
		result.Stderr = "falha ao iniciar processo: comando vazio\n"
		return finish()
	}

	cmd := exec.Command(job.Command[0], job.Command[1:]...)
	cmd.Dir = job.Dir
	if len(job.Env) > 0 {
		env := os.Environ()
		for key, value := range job.Env {
			env = append(env, key+"="+value)
		}
		cmd.Env = env
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	// Grupo próprio: matar só o filho deixaria os netos (sleep, go test) vivos
	// segurando os pipes, e o pool esperaria EOF indefinidamente.
	configureProcessGroup(cmd)

	if err := cmd.Start(); err != nil {
		result.Status = 127
		result.Stderr = fmt.Sprintf("falha ao iniciar processo: %v\n", err)
		return finish()
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	var waitErr error
	if timeout > 0 {
		timer := time.NewTimer(timeout)
		select {
		case waitErr = <-done:
			timer.Stop()
		case <-timer.C:
			result.TimedOut = true
			killProcessGroup(cmd)
			// Espera o Wait para não deixar goroutine nem pipe pendente. Com o
			// grupo morto por SIGKILL o Wait retorna logo.
			waitErr = <-done
		}
	} else {
		waitErr = <-done
	}

	if result.TimedOut {
		// Convenção do pwn: 137 (128 + SIGKILL) quando o timeout dispara.
		result.Status = 137
	} else {
		result.Status = exitStatus(waitErr)
	}
	result.Stdout = stdout.String()
	result.Stderr = stderr.String()
	return finish()
}

func exitStatus(err error) int {
	if err == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		if status, ok := exitErr.Sys().(syscall.WaitStatus); ok && status.Signaled() {
			// Node reporta 128 para morte por sinal; mantém a paridade.
			return 128
		}
		if code := exitErr.ExitCode(); code >= 0 {
			return code
		}
	}
	return 1
}
