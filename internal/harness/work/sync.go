package work

import (
	"fmt"
	"os"
	"path/filepath"
)

// panoramaToManifest mapeia o panorama do plano no vocabulário canônico do
// manifest. Todo destino pertence a WorkManifestStates; um panorama fora do
// mapa cai em `invalid`.
var panoramaToManifest = map[string]WorkManifestState{
	"COMPLETE": StateCompleted,
	// Tasks aceitas mas gates globais sem evidência: o Work ainda não terminou.
	"TASKS COMPLETE":     StateActive,
	"NOT STARTED":        StatePlanned,
	"NO TASKS":           StatePlanned,
	"BLOCKED":            StateBlocked,
	"IN PROGRESS":        StateActive,
	"INVALID PLAN":       StateActive,
	"STALE EVIDENCE":     StateActive,
	"INCONSISTENT STATE": StateActive,
	"INCONSISTENT ORDER": StateActive,
}

// ManifestAbsent é o retorno de SyncWorkManifest quando não há manifest.
const ManifestAbsent = "manifest-ausente"

// SyncWorkManifest projeta o estado real do Work no manifest v3.
//
// Escreve via UpdateManifest, portanto o estado é sempre validado contra o
// vocabulário canônico.
func SyncWorkManifest(workID, rootDir string) (string, error) {
	if rootDir == "" {
		rootDir = "."
	}
	manifestFile := filepath.Join(rootDir, ".work", workID+".json")
	if _, err := os.Stat(manifestFile); err != nil {
		if os.IsNotExist(err) {
			return ManifestAbsent, nil
		}
		return "", fmt.Errorf("work: ler manifest %s: %w", manifestFile, err)
	}

	panoramaState := "planned"
	status, err := CollectPlanStatus(workID, rootDir)
	if err != nil {
		// Plano ilegível é estado `invalid`, como o `catch` da referência.
		panoramaState = "invalid"
	} else {
		panoramaState = status.Panorama.State
	}
	state, ok := panoramaToManifest[panoramaState]
	if !ok {
		state = StateInvalid
	}
	if !IsWorkManifestState(string(state)) {
		return "", fmt.Errorf("estado de manifest inválido derivado do panorama: %s", state)
	}
	if _, err := UpdateManifest(rootDir, workID, ManifestChanges{State: &state}); err != nil {
		return "", err
	}
	return string(state), nil
}
