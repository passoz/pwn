package fsx

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// WriteFileAtomic grava content em target com tmp + rename: leitores nunca
// veem o arquivo pela metade. O tmp fica no mesmo diretório do alvo para que o
// rename seja atômico no mesmo sistema de arquivos.
func WriteFileAtomic(target, content string) error {
	dir := filepath.Dir(target)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("fsx: criar diretório de %s: %w", target, err)
	}
	tmp := fmt.Sprintf("%s.%d.%s.tmp", target, os.Getpid(), randomSuffix())
	if err := os.WriteFile(tmp, []byte(content), 0o644); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("fsx: gravar tmp de %s: %w", target, err)
	}
	if err := os.Rename(tmp, target); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("fsx: renomear tmp para %s: %w", target, err)
	}
	return nil
}

func randomSuffix() string {
	var buf [6]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(buf[:])
}
