// Package fsx contém as primitivas de sistema de arquivos usadas pelo core do
// pwn: trava entre processos, anexação de linha sob trava e escrita atômica.
package fsx

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// Padrões de LockOptions (espelham src/core/fs-lock.ts).
const (
	DefaultTimeout = 30 * time.Second
	DefaultStale   = 60 * time.Second
	DefaultRetry   = 25 * time.Millisecond
)

// LockOptions controla a aquisição da trava. Campo zero usa o padrão
// correspondente; valores negativos também usam o padrão.
type LockOptions struct {
	// Timeout é o tempo máximo esperando a trava.
	Timeout time.Duration
	// Stale é a idade a partir da qual a trava é considerada abandonada.
	Stale time.Duration
	// Retry é o intervalo entre tentativas.
	Retry time.Duration
}

func (o LockOptions) withDefaults() LockOptions {
	if o.Timeout <= 0 {
		o.Timeout = DefaultTimeout
	}
	if o.Stale <= 0 {
		o.Stale = DefaultStale
	}
	if o.Retry <= 0 {
		o.Retry = DefaultRetry
	}
	return o
}

// LockTimeoutError indica que a trava não foi obtida dentro do timeout.
type LockTimeoutError struct {
	Target  string
	Timeout time.Duration
}

func (e *LockTimeoutError) Error() string {
	return fmt.Sprintf("lock de %s não obtido em %s", e.Target, e.Timeout)
}

// WithFileLock executa fn com exclusão mútua entre processos sobre target.
//
// A aquisição é atômica: cria o diretório "<target>.lock" com os.Mkdir. Se o
// diretório já existir e a idade (mtime) passar de opts.Stale, o dono é
// considerado morto e a trava é tomada. A espera é ativa, com time.Sleep, para
// manter o mesmo desenho do pwn TypeScript e não depender de flock.
//
// A trava NÃO é reentrante: chamar WithFileLock para o mesmo target dentro de
// fn causa timeout.
func WithFileLock(target string, fn func() error, options LockOptions) error {
	opts := options.withDefaults()
	lockDir := target + ".lock"
	if err := os.MkdirAll(filepath.Dir(lockDir), 0o755); err != nil {
		return fmt.Errorf("fsx: criar diretório da trava %s: %w", lockDir, err)
	}
	deadline := time.Now().Add(opts.Timeout)

	for {
		err := os.Mkdir(lockDir, 0o755)
		if err == nil {
			break
		}
		if !errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("fsx: obter trava %s: %w", lockDir, err)
		}
		info, statErr := os.Stat(lockDir)
		if statErr != nil {
			// O dono liberou a trava entre o Mkdir e o Stat: tenta de novo.
			continue
		}
		if time.Since(info.ModTime()) > opts.Stale {
			// Mesma janela TOCTOU do original: entre o Stat e o RemoveAll outro
			// processo pode tomar a trava. RemoveAll é idempotente e a recriação
			// posterior não é afetada por um RemoveAll de diretório inexistente.
			if rmErr := os.RemoveAll(lockDir); rmErr != nil {
				return fmt.Errorf("fsx: remover trava obsoleta %s: %w", lockDir, rmErr)
			}
			continue
		}
		if !time.Now().Before(deadline) {
			return &LockTimeoutError{Target: target, Timeout: opts.Timeout}
		}
		time.Sleep(opts.Retry)
	}

	defer func() {
		// RemoveAll ignora trava já removida por outro processo.
		_ = os.RemoveAll(lockDir)
	}()
	return fn()
}

// AppendLine acrescenta uma linha a target sob trava. A linha recebe "\n" se
// ainda não terminar com ele. A trava é necessária porque a cadeia e as
// métricas são lidas por outros processos.
func AppendLine(target, line string, options LockOptions) error {
	return WithFileLock(target, func() error {
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return fmt.Errorf("fsx: criar diretório de %s: %w", target, err)
		}
		data := line
		if len(data) == 0 || data[len(data)-1] != '\n' {
			data += "\n"
		}
		f, err := os.OpenFile(target, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return fmt.Errorf("fsx: abrir %s: %w", target, err)
		}
		_, writeErr := f.WriteString(data)
		if closeErr := f.Close(); writeErr == nil {
			writeErr = closeErr
		}
		if writeErr != nil {
			return fmt.Errorf("fsx: anexar em %s: %w", target, writeErr)
		}
		return nil
	}, options)
}
