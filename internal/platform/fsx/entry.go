package fsx

import (
	"os"
	"path/filepath"
)

// IsDirectEntry informa se modulePath é o programa invocado neste processo.
//
// Equivale a isDirectEntry de src/core/entry-guard.ts, adaptado: o TypeScript
// compara process.argv[1] com a URL do módulo; em Go não existe URL de módulo,
// então o chamador passa o caminho do arquivo principal e a comparação usa
// os.Args[0].
//
// A comparação é feita sobre caminhos reais (symlinks resolvidos). Se qualquer
// um dos caminhos não puder ser resolvido, o resultado é false, como no
// original: num binário empacotado o entrypoint vive num VFS e nenhum
// subcomando é invocado por caminho de arquivo.
func IsDirectEntry(modulePath string) bool {
	if modulePath == "" || len(os.Args) == 0 || os.Args[0] == "" {
		return false
	}
	invoked, err := filepath.EvalSymlinks(os.Args[0])
	if err != nil {
		return false
	}
	module, err := filepath.EvalSymlinks(modulePath)
	if err != nil {
		return false
	}
	invokedAbs, err := filepath.Abs(invoked)
	if err != nil {
		return false
	}
	moduleAbs, err := filepath.Abs(module)
	if err != nil {
		return false
	}
	return invokedAbs == moduleAbs
}
