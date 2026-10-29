package verify

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var envNamePattern = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)

// ProjectSandbox devolve a política de sandbox do projeto em projectDir.
//
// Falha fechada: entrada malformada devolve *VerificationUnavailable; nunca cai
// silenciosamente na política padrão.
func ProjectSandbox(projectDir, root string) (*ProjectSandboxConfig, error) {
	resolved, err := resolveRoot(root)
	if err != nil {
		return nil, err
	}
	config := ReadConfig(resolved)
	if config == nil || len(config.Projects) == 0 {
		return nil, nil
	}
	target, err := filepath.EvalSymlinks(projectDir)
	if err != nil {
		return nil, fmt.Errorf("verifier: resolver o projeto %s: %w", projectDir, err)
	}

	// A ordem das chaves é lexicográfica para que dois projetos com o mesmo
	// alvo real escolham a mesma entrada em qualquer plataforma.
	keys := make([]string, 0, len(config.Projects))
	for key := range config.Projects {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	match := ""
	for _, key := range keys {
		candidate, err := filepath.EvalSymlinks(key)
		if err != nil {
			continue
		}
		if candidate == target {
			match = key
			break
		}
	}
	if match == "" {
		return nil, nil
	}

	where := fmt.Sprintf("projects[%q]", match)
	var decoded any
	if err := json.Unmarshal(config.Projects[match], &decoded); err != nil {
		return nil, unavailable(where+" inválido", fmt.Sprintf("JSON inválido: %v", err))
	}
	entry, ok := decoded.(map[string]any)
	if !ok {
		return nil, unavailable(where+" inválido", "esperado objeto")
	}

	absolutePaths := func(value any, present bool, field string) ([]string, error) {
		if !present {
			return []string{}, nil
		}
		items, ok := value.([]any)
		if !ok {
			return nil, unavailable(
				fmt.Sprintf("%s.%s inválido", where, field),
				"esperado array de caminhos absolutos",
			)
		}
		cleaned := make([]string, 0, len(items))
		for index, item := range items {
			path, ok := cleanAbsolute(item)
			if !ok {
				return nil, unavailable(
					fmt.Sprintf("%s.%s[%d] inválido", where, field, index),
					"esperado caminho absoluto",
				)
			}
			cleaned = append(cleaned, path)
		}
		return cleaned, nil
	}

	mounts := make([]ProjectMount, 0)
	if raw, has := entry["mounts"]; has && raw != nil {
		items, ok := raw.([]any)
		if !ok {
			return nil, unavailable(fmt.Sprintf("%s.mounts inválido", where), "esperado array de {source, dest}")
		}
		destinations := make(map[string]bool, len(items))
		for index, item := range items {
			fields, isObject := item.(map[string]any)
			if !isObject {
				return nil, unavailable(
					fmt.Sprintf("%s.mounts[%d] inválido", where, index),
					"esperado {source, dest} com caminhos absolutos",
				)
			}
			source, sourceOK := cleanAbsolute(fields["source"])
			dest, destOK := cleanAbsolute(fields["dest"])
			if !sourceOK || !destOK {
				return nil, unavailable(
					fmt.Sprintf("%s.mounts[%d] inválido", where, index),
					"esperado {source, dest} com caminhos absolutos",
				)
			}
			if reservedMountDest[dest] {
				return nil, unavailable(
					fmt.Sprintf("%s.mounts[%d].dest reservado", where, index),
					fmt.Sprintf("%s é reservado pelo sandbox", dest),
				)
			}
			if destinations[dest] {
				return nil, unavailable(
					fmt.Sprintf("%s.mounts[%d].dest duplicado", where, index),
					fmt.Sprintf("%s já é destino de outra montagem", dest),
				)
			}
			destinations[dest] = true
			mounts = append(mounts, ProjectMount{Source: source, Dest: dest})
		}
	}

	overlays := make([]ProjectMount, 0)
	if raw, has := entry["overlays"]; has && raw != nil {
		items, ok := raw.([]any)
		if !ok {
			return nil, unavailable(fmt.Sprintf("%s.overlays inválido", where), "esperado array de {source, dest}")
		}
		destinations := make(map[string]bool, len(items))
		for index, item := range items {
			fields, isObject := item.(map[string]any)
			source, sourceOK := cleanAbsolute(fields["source"])
			dest, destOK := cleanAbsolute(fields["dest"])
			if !isObject || !sourceOK || !destOK {
				return nil, unavailable(
					fmt.Sprintf("%s.overlays[%d] inválido", where, index),
					"esperado {source, dest} com caminhos absolutos",
				)
			}
			// O repositório avaliado não controla o cache: a origem fica fora dele.
			if inside(target, source) {
				return nil, unavailable(
					fmt.Sprintf("%s.overlays[%d].source inválido", where, index),
					"a origem do overlay não pode ficar dentro do repositório avaliado",
				)
			}
			if reservedMountDest[dest] || destinations[dest] {
				return nil, unavailable(
					fmt.Sprintf("%s.overlays[%d].dest inválido", where, index),
					fmt.Sprintf("%s é reservado ou repetido", dest),
				)
			}
			destinations[dest] = true
			overlays = append(overlays, ProjectMount{Source: source, Dest: dest})
		}
	}

	home := ""
	if raw, has := entry["home"]; has {
		cleaned, ok := cleanAbsolute(raw)
		if !ok || cleaned == "/nonexistent" || inside(target, cleaned) {
			return nil, unavailable(
				fmt.Sprintf("%s.home inválido", where),
				"esperado caminho absoluto fora do repositório",
			)
		}
		home = cleaned
	}

	env := make(map[string]string)
	if raw, has := entry["env"]; has && raw != nil {
		fields, ok := raw.(map[string]any)
		if !ok {
			return nil, unavailable(fmt.Sprintf("%s.env inválido", where), "esperado objeto de variáveis")
		}
		for name, value := range fields {
			text, isText := value.(string)
			if !envNamePattern.MatchString(name) || reservedSandboxEnv[name] || !isText || containsNewline(text) {
				return nil, unavailable(
					fmt.Sprintf("%s.env.%s inválido", where, name),
					"nome ou valor não permitido",
				)
			}
			env[name] = text
		}
	}

	// A ordem das validações segue a referência: path_prepend e mounts_ro são
	// validados depois de mounts, home e env.
	prepend, err := absolutePaths(entry["path_prepend"], hasKey(entry, "path_prepend"), "path_prepend")
	if err != nil {
		return nil, err
	}
	mountsRO, err := absolutePaths(entry["mounts_ro"], hasKey(entry, "mounts_ro"), "mounts_ro")
	if err != nil {
		return nil, err
	}

	return &ProjectSandboxConfig{
		PathPrepend: prepend,
		MountsRO:    mountsRO,
		Mounts:      mounts,
		Overlays:    overlays,
		Home:        home,
		Env:         env,
	}, nil
}

func hasKey(entry map[string]any, key string) bool {
	_, has := entry[key]
	return has
}

func containsNewline(value string) bool {
	return strings.Contains(value, "\n")
}
