// Package logx fornece o logger estruturado do pwn.
//
// O formato é JSON, uma linha por evento, com nível e atributos tipados. O
// destino é sempre um arquivo quando ele é configurado; stderr é opcional para
// não alterar o contrato de saída do CLI. Segredos conhecidos são redigidos
// antes da serialização.
package logx

import (
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Options descreve o destino e o nível do logger.
type Options struct {
	// Level é um de debug, info, warn ou error. Vazio vale info.
	Level string
	// File é o caminho do arquivo de log. Vazio desliga o arquivo.
	File string
	// Stderr espelha os eventos em stderr.
	Stderr bool
}

// Logger embrulha slog com o fechamento do arquivo de destino.
type Logger struct {
	*slog.Logger
	closers []io.Closer
}

// Close fecha os destinos abertos pelo logger.
func (l *Logger) Close() error {
	if l == nil {
		return nil
	}
	var first error
	for _, closer := range l.closers {
		if err := closer.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// Discard devolve um logger que não escreve nada.
func Discard() *Logger {
	return &Logger{Logger: slog.New(slog.NewJSONHandler(io.Discard, nil))}
}

// Open monta o logger a partir das opções. O diretório do arquivo é criado.
func Open(options Options) (*Logger, error) {
	writers := make([]io.Writer, 0, 2)
	closers := make([]io.Closer, 0, 1)

	if options.File != "" {
		dir := filepath.Dir(options.File)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
		file, err := os.OpenFile(options.File, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return nil, err
		}
		writers = append(writers, file)
		closers = append(closers, file)
	}
	if options.Stderr {
		writers = append(writers, os.Stderr)
	}

	writer := io.Discard
	if len(writers) == 1 {
		writer = writers[0]
	} else if len(writers) > 1 {
		writer = io.MultiWriter(writers...)
	}

	handler := slog.NewJSONHandler(writer, &slog.HandlerOptions{
		Level:       ParseLevel(options.Level),
		ReplaceAttr: sanitizeAttr,
	})
	return &Logger{Logger: slog.New(handler), closers: closers}, nil
}

// ParseLevel converte o nome do nível. Um valor desconhecido vale info.
func ParseLevel(raw string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// Chaves cujo valor nunca deve chegar ao arquivo.
var secretKey = regexp.MustCompile(`(?i)(authorization|api[-_]?key|access[-_]?token|refresh[-_]?token|token|secret|password|passwd|credential|private[-_]?key)`)

// Formas de segredo embutidas em texto livre: Bearer, chaves sk- e atribuições.
var secretValue = regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9._~+/=-]{8,}|sk-[A-Za-z0-9_-]{8,}|(?:api[_-]?key|token|secret|password)\s*[=:]\s*\S+`)

// MaxValueLength limita o tamanho de um valor textual no log.
const MaxValueLength = 4096

// sanitizeAttr redige segredos e limita valores longos antes da serialização.
func sanitizeAttr(_ []string, attr slog.Attr) slog.Attr {
	if secretKey.MatchString(attr.Key) {
		return slog.String(attr.Key, "[REDACTED]")
	}
	if attr.Value.Kind() != slog.KindString {
		return attr
	}
	value := secretValue.ReplaceAllString(attr.Value.String(), "[REDACTED]")
	if len(value) > MaxValueLength {
		value = value[:MaxValueLength] + "…"
	}
	return slog.String(attr.Key, value)
}

// IsLoopback informa se o host aponta para a própria máquina.
func IsLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
