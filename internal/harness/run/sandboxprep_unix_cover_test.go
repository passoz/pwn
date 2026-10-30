//go:build unix

package run

import (
	"path/filepath"
	"syscall"
	"testing"
)

func TestPathFingerprintSpecialFileIsOther(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "fila")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo indisponível: %v", err)
	}
	if got := PathFingerprint(fifo); got != "other" {
		t.Fatalf("assinatura da fifo = %q, esperava other", got)
	}
}
