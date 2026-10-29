package work

import (
	"bytes"
	"encoding/json"
	"time"

	"github.com/passoz/pwn/internal/platform/fsx"
)

// unmarshalJSON lê JSON preservando números como float64 — a mesma leitura que
// `JSON.parse` faz — para que valores não tipados cheguem às funções auxiliares
// da mesma forma que na referência.
func unmarshalJSON(data []byte, value any) error {
	return json.Unmarshal(data, value)
}

// marshalIndent devolve o JSON com indentação de dois espaços, sem quebra de
// linha final, como `JSON.stringify(value, null, 2)`.
func marshalIndent(value any) (string, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		return "", err
	}
	return trimFinalNewline(buffer.String()), nil
}

// marshalDocument devolve o JSON indentado com a quebra de linha final que os
// artefatos do Work usam.
func marshalDocument(value any) (string, error) {
	content, err := marshalIndent(value)
	if err != nil {
		return "", err
	}
	return content + "\n", nil
}

func trimFinalNewline(value string) string {
	for len(value) > 0 && value[len(value)-1] == '\n' {
		value = value[:len(value)-1]
	}
	return value
}

// writeFileAtomic grava o arquivo por tmp + rename.
func writeFileAtomic(path, content string) error {
	return fsx.WriteFileAtomic(path, content)
}

// writeJSON grava value como documento JSON indentado.
func writeJSON(path string, value any) error {
	content, err := marshalDocument(value)
	if err != nil {
		return err
	}
	return writeFileAtomic(path, content)
}

// nowISO devolve o instante atual em ISO-8601 UTC, como
// `new Date().toISOString()`.
func nowISO() string {
	return time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
}

// nonNil devolve values ou um slice vazio, para que o JSON emitido tenha `[]` e
// não `null` nos campos que o schema exige como array.
func nonNil(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}
