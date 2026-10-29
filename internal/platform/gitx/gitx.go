// Package gitx executa o git como processo filho, sem shell, e devolve a saída
// tipada. Cada método corresponde a uma operação que o core do pwn usa: ler
// HEAD, comparar árvores, aplicar patch, criar e remover worktrees.
//
// O código de saída diferente de zero não é erro de infraestrutura: os métodos
// que exigem sucesso devolvem *ExitError; Run devolve o código no Result.
package gitx

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// DefaultMaxBuffer limita cada fluxo capturado (stdout e stderr). O mesmo
// limite do runGit de referência para patch binário de 64 MiB.
const DefaultMaxBuffer = 64 * 1024 * 1024

// Runner executa git em um diretório de trabalho.
type Runner struct {
	// Dir é o diretório padrão dos comandos. Vazio usa o diretório atual.
	Dir string
	// Env acrescenta variáveis ao ambiente herdado. Vazio herda o ambiente.
	Env []string
	// MaxBuffer limita cada fluxo capturado. Zero usa DefaultMaxBuffer.
	MaxBuffer int
}

// New cria um Runner que executa git em dir.
func New(dir string) *Runner {
	return &Runner{Dir: dir}
}

// Options ajusta uma execução isolada.
type Options struct {
	// Dir substitui o Dir do Runner.
	Dir string
	// Stdin é enviado ao processo; nil usa /dev/null.
	Stdin []byte
	// Env acrescenta variáveis ao ambiente herdado.
	Env []string
	// MaxBuffer substitui o limite do Runner quando maior que zero.
	MaxBuffer int
}

// Result é a saída de uma execução de git.
type Result struct {
	// Stdout é a saída de stdout, byte a byte, sem trim.
	Stdout []byte
	// Stderr é a saída de stderr com os espaços das pontas removidos.
	Stderr string
	// Exit é o código de saída. -1 indica que o processo não iniciou ou foi morto.
	Exit int
}

// OK informa se o git terminou com sucesso.
func (r Result) OK() bool {
	return r.Exit == 0
}

// ExitError é um git que terminou com código diferente de zero.
type ExitError struct {
	// Args são os argumentos passados ao git.
	Args []string
	// Result é a saída capturada.
	Result Result
}

func (e *ExitError) Error() string {
	detail := e.Result.Stderr
	if detail == "" {
		detail = fmt.Sprintf("exit %d", e.Result.Exit)
	}
	return fmt.Sprintf("gitx: git %s falhou: %s", strings.Join(e.Args, " "), detail)
}

// Run executa git com args e devolve stdout, stderr e o código de saída.
//
// O erro cobre somente falha de infraestrutura: git ausente, contexto
// cancelado ou saída acima de MaxBuffer. Um git que termina com código
// diferente de zero devolve Result com o código e err nil.
func (r *Runner) Run(ctx context.Context, args []string, opts Options) (Result, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	limit := opts.MaxBuffer
	if limit <= 0 {
		limit = r.MaxBuffer
	}
	if limit <= 0 {
		limit = DefaultMaxBuffer
	}

	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = r.dir(opts)
	cmd.Env = append(append(os.Environ(), r.Env...), opts.Env...)
	if len(opts.Stdin) > 0 {
		cmd.Stdin = bytes.NewReader(opts.Stdin)
	}
	stdout := newLimitedBuffer(limit)
	stderr := newLimitedBuffer(limit)
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	runErr := cmd.Run()

	res := Result{Stdout: stdout.buf.Bytes(), Stderr: strings.TrimSpace(stderr.buf.String()), Exit: -1}
	if cmd.ProcessState != nil {
		res.Exit = cmd.ProcessState.ExitCode()
	}

	if stdout.overflow || stderr.overflow {
		return res, fmt.Errorf("gitx: saída de git %s excedeu %d bytes", strings.Join(args, " "), limit)
	}
	if ctx.Err() != nil {
		return res, fmt.Errorf("gitx: git %s cancelado: %w", strings.Join(args, " "), ctx.Err())
	}
	if runErr != nil {
		var exitErr *exec.ExitError
		if !errors.As(runErr, &exitErr) {
			return res, fmt.Errorf("gitx: executar git %s: %w", strings.Join(args, " "), runErr)
		}
	}
	return res, nil
}

func (r *Runner) dir(opts Options) string {
	if opts.Dir != "" {
		return opts.Dir
	}
	return r.Dir
}

// output executa git e exige sucesso, devolvendo stdout sem os espaços das pontas.
func (r *Runner) output(ctx context.Context, args ...string) (string, error) {
	out, err := r.bytes(ctx, args...)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// bytes executa git e exige sucesso, devolvendo stdout intacto.
func (r *Runner) bytes(ctx context.Context, args ...string) ([]byte, error) {
	res, err := r.Run(ctx, args, Options{})
	if err != nil {
		return nil, err
	}
	if !res.OK() {
		return nil, &ExitError{Args: args, Result: res}
	}
	return res.Stdout, nil
}

var errBufferOverflow = errors.New("gitx: buffer cheio")

// limitedBuffer acumula até limit bytes e sinaliza o excesso. O erro interrompe
// a cópia do os/exec: a saída nunca é truncada em silêncio.
type limitedBuffer struct {
	buf      bytes.Buffer
	limit    int
	overflow bool
}

func newLimitedBuffer(limit int) *limitedBuffer {
	return &limitedBuffer{limit: limit}
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	remaining := b.limit - b.buf.Len()
	if remaining <= 0 {
		b.overflow = true
		return 0, errBufferOverflow
	}
	if len(p) > remaining {
		n, _ := b.buf.Write(p[:remaining])
		b.overflow = true
		return n, errBufferOverflow
	}
	return b.buf.Write(p)
}
