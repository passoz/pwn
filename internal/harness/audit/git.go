package audit

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/passoz/pwn/internal/platform/gitx"
)

// requireCleanBaseline exige repositório git e árvore limpa nos caminhos
// declarados.
func requireCleanBaseline(paths []string) error {
	if _, err := os.Stat(".git"); err != nil {
		return fmt.Errorf("git repository required to prove implementation removal")
	}
	args := append([]string{"status", "--porcelain=v1", "--"}, paths...)
	result, err := gitx.New("").Run(context.Background(), args, gitx.Options{})
	if err != nil {
		return err
	}
	combined := strings.TrimSpace(string(result.Stdout) + result.Stderr)
	if !result.OK() {
		return fmt.Errorf("git status failed: %s", combined)
	}
	if combined != "" {
		return fmt.Errorf("baseline invalid: declared files already have changes; isolate or checkpoint them first")
	}
	return nil
}

// gitHead devolve o commit em HEAD.
func gitHead() (string, error) {
	result, err := gitx.New("").Run(context.Background(), []string{"rev-parse", "--verify", "HEAD"}, gitx.Options{})
	if err != nil {
		return "", err
	}
	if !result.OK() {
		return "", fmt.Errorf("baseline exige um commit em HEAD: a remoção da implementação restaura o conteúdo a partir dele")
	}
	return strings.TrimSpace(string(result.Stdout)), nil
}

// requireTracked exige que o arquivo existente esteja versionado.
func requireTracked(filePath string) error {
	result, err := gitx.New("").Run(
		context.Background(),
		[]string{"ls-files", "--error-unmatch", "--", filePath},
		gitx.Options{},
	)
	if err != nil {
		return err
	}
	if !result.OK() {
		return fmt.Errorf(
			"arquivo de implementação existe mas não está versionado: %s (o mutation check restaura a partir do commit)",
			filePath,
		)
	}
	return nil
}

// snapshotChanges compara o snapshot gravado com o estado atual dos arquivos.
func snapshotChanges(before Snapshot, files []string) ([]string, error) {
	current, err := snapshot(files)
	if err != nil {
		return nil, err
	}
	return changed(before, current), nil
}

// ensureDisjoint recusa sobreposição entre implementação e testes.
func ensureDisjoint(implementation, tests []string) error {
	testSet := make(map[string]struct{}, len(tests))
	for _, filePath := range tests {
		testSet[filePath] = struct{}{}
	}
	overlap := make([]string, 0)
	for _, filePath := range uniqueSorted(implementation) {
		if _, ok := testSet[filePath]; ok {
			overlap = append(overlap, filePath)
		}
	}
	if len(overlap) > 0 {
		return fmt.Errorf("implementation/test files overlap: %s", strings.Join(overlap, ", "))
	}
	return nil
}

func joinOrDash(values []string) string {
	if len(values) == 0 {
		return "—"
	}
	return strings.Join(values, ", ")
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
