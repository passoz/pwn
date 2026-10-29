package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/passoz/pwn/internal/platform/cryptox"
	"github.com/passoz/pwn/internal/platform/fsx"
	"github.com/passoz/pwn/internal/platform/jsonx"
)

// stateVersion é a versão do estado por task; 2 = baseline amarrado ao plano.
const stateVersion = 2

// genesisHash é o prev_hash da primeira entrada da cadeia.
const genesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// FileDigest é o hash de um arquivo no instante do instantâneo.
type FileDigest struct {
	Exists bool    `json:"exists"`
	SHA256 *string `json:"sha256"`
}

// Snapshot mapeia caminho para o digest do arquivo.
type Snapshot map[string]FileDigest

// FrozenTest é um teste de aceitação congelado no contrato: caminho e sha256 do
// conteúdo aprovado.
type FrozenTest struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// ContractRef identifica o contrato V4 que o baseline amarrou.
type ContractRef struct {
	ID     string `json:"id"`
	SHA256 string `json:"sha256"`
}

// Vacuity é o resultado do mesmo comando de AC com a implementação removida.
type Vacuity struct {
	ExitCode int    `json:"exit_code"`
	Verdict  string `json:"verdict"`
}

// AuditCheckRecord é o resultado gravado de um check (AC-n, VISUAL, ...).
type AuditCheckRecord struct {
	Command     []string `json:"command"`
	Expect      *string  `json:"expect"`
	ExitCode    int      `json:"exit_code"`
	Verdict     string   `json:"verdict"`
	Log         string   `json:"log"`
	LogSHA256   *string  `json:"log_sha256"`
	RecordedAt  string   `json:"recorded_at"`
	GreenSHA256 string   `json:"green_sha256,omitempty"`
	Vacuity     *Vacuity `json:"vacuity,omitempty"`
}

// State é o estado persistente de evidência de uma task.
type State struct {
	Task                   string                      `json:"task"`
	CreatedAt              string                      `json:"created_at"`
	StateVersion           int                         `json:"state_version"`
	BaselineCommit         string                      `json:"baseline_commit"`
	PlanPath               string                      `json:"plan_path"`
	TaskDefinitionSHA256   string                      `json:"task_definition_sha256"`
	Contract               *ContractRef                `json:"contract"`
	FrozenTests            []FrozenTest                `json:"frozen_tests"`
	ImplementationFiles    []string                    `json:"implementation_files"`
	TestFiles              []string                    `json:"test_files"`
	BaselineImplementation Snapshot                    `json:"baseline_implementation"`
	BaselineTests          Snapshot                    `json:"baseline_tests"`
	RedTests               *Snapshot                   `json:"red_tests"`
	RedCommand             []string                    `json:"red_command"`
	RedExpect              string                      `json:"red_expect"`
	GreenImplementation    Snapshot                    `json:"green_implementation"`
	GreenTests             Snapshot                    `json:"green_tests"`
	GreenExpect            *string                     `json:"green_expect"`
	AuditChecks            map[string]AuditCheckRecord `json:"audit_checks"`
}

// workPaths são os diretórios de evidência do Work.
type workPaths struct {
	logDir   string
	stateDir string
}

var workIDPattern = regexp.MustCompile(`^\d{4}$`)

// configureWork resolve os diretórios de evidência do Work. O identificador é
// quatro dígitos ou `legacy`.
func configureWork(workID string) (workPaths, error) {
	if workID == "legacy" {
		logDir := filepath.Join(".todo", "evidence")
		return workPaths{logDir: logDir, stateDir: filepath.Join(logDir, "state")}, nil
	}
	if !workIDPattern.MatchString(workID) {
		return workPaths{}, fmt.Errorf("invalid Work ID: %s; expected four digits or legacy", workID)
	}
	logDir := filepath.Join(".todo", "evidence", workID)
	return workPaths{logDir: logDir, stateDir: filepath.Join(logDir, "state")}, nil
}

func sha256Hex(data []byte) string {
	return cryptox.SHA256Hex(data)
}

// digest lê o digest de um caminho. Caminho ausente não é erro; caminho que não
// é arquivo regular é violação.
func digest(filePath string) (FileDigest, error) {
	info, err := os.Stat(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return FileDigest{Exists: false, SHA256: nil}, nil
		}
		return FileDigest{}, err
	}
	if !info.Mode().IsRegular() {
		return FileDigest{}, fmt.Errorf("not a regular file: %s", filePath)
	}
	content, err := os.ReadFile(filePath)
	if err != nil {
		return FileDigest{}, err
	}
	sum := sha256Hex(content)
	return FileDigest{Exists: true, SHA256: &sum}, nil
}

func snapshot(paths []string) (Snapshot, error) {
	result := make(Snapshot, len(paths))
	for _, filePath := range paths {
		entry, err := digest(filePath)
		if err != nil {
			return nil, err
		}
		result[filePath] = entry
	}
	return result, nil
}

func statePath(paths workPaths, task string) string {
	return filepath.Join(paths.stateDir, task+".json")
}

// tryLoadState devolve o estado ou o motivo de ele não existir, para que a ação
// relate auditoria INCOMPLETA em vez de violação.
func tryLoadState(paths workPaths, task string) (*State, string) {
	data, err := os.ReadFile(statePath(paths, task))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Sprintf("baseline not found for task %s; run baseline first", task)
		}
		return nil, fmt.Sprintf("state unreadable for task %s: %v", task, err)
	}
	var state State
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Sprintf("state unreadable for task %s: %v", task, err)
	}
	return &state, ""
}

// saveState grava o estado com as chaves de topo ordenadas e dois espaços de
// recuo, como o JSON.stringify da referência.
func saveState(paths workPaths, state *State) error {
	record := map[string]any{
		"task":                    state.Task,
		"created_at":              state.CreatedAt,
		"state_version":           state.StateVersion,
		"baseline_commit":         state.BaselineCommit,
		"plan_path":               state.PlanPath,
		"task_definition_sha256":  state.TaskDefinitionSHA256,
		"contract":                state.Contract,
		"frozen_tests":            nonNilFrozen(state.FrozenTests),
		"implementation_files":    nonNilStrings(state.ImplementationFiles),
		"test_files":              nonNilStrings(state.TestFiles),
		"baseline_implementation": nonNilSnapshot(state.BaselineImplementation),
		"baseline_tests":          nonNilSnapshot(state.BaselineTests),
		"red_tests":               state.RedTests,
	}
	if state.RedTests != nil {
		record["red_command"] = nonNilStrings(state.RedCommand)
		record["red_expect"] = state.RedExpect
	}
	if state.GreenImplementation != nil || state.GreenTests != nil {
		record["green_implementation"] = state.GreenImplementation
		record["green_tests"] = state.GreenTests
		record["green_expect"] = state.GreenExpect
	}
	if state.AuditChecks != nil {
		record["audit_checks"] = state.AuditChecks
	}

	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(record); err != nil {
		return err
	}
	return fsx.WriteFileAtomic(statePath(paths, state.Task), buffer.String())
}

func nonNilStrings(value []string) []string {
	if value == nil {
		return []string{}
	}
	return value
}

func nonNilFrozen(value []FrozenTest) []FrozenTest {
	if value == nil {
		return []FrozenTest{}
	}
	return value
}

func nonNilSnapshot(value Snapshot) Snapshot {
	if value == nil {
		return Snapshot{}
	}
	return value
}

// changed devolve os caminhos cujo digest mudou entre dois instantâneos.
func changed(before, after Snapshot) []string {
	paths := make(map[string]struct{}, len(before)+len(after))
	for filePath := range before {
		paths[filePath] = struct{}{}
	}
	for filePath := range after {
		paths[filePath] = struct{}{}
	}
	result := make([]string, 0, len(paths))
	for filePath := range paths {
		left, leftOK := before[filePath]
		right, rightOK := after[filePath]
		if leftOK != rightOK || !sameDigest(left, right) {
			result = append(result, filePath)
		}
	}
	sort.Strings(result)
	return result
}

func sameDigest(left, right FileDigest) bool {
	if left.Exists != right.Exists {
		return false
	}
	if left.SHA256 == nil || right.SHA256 == nil {
		return left.SHA256 == nil && right.SHA256 == nil
	}
	return *left.SHA256 == *right.SHA256
}

// ChainEntry é uma entrada da cadeia de hash local dos logs.
type ChainEntry struct {
	Sequence     int      `json:"sequence"`
	Timestamp    string   `json:"timestamp"`
	Task         string   `json:"task"`
	Check        string   `json:"check"`
	Command      []string `json:"command"`
	ExitCode     int      `json:"exit_code"`
	OutputSHA256 string   `json:"output_sha256"`
	PrevHash     string   `json:"prev_hash"`
	EntryHash    string   `json:"entry_hash"`
}

func nowISO() string {
	return time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
}

// appendEvidenceChain anexa uma entrada à cadeia, com leitura e append na mesma
// seção crítica.
func appendEvidenceChain(paths workPaths, task, check string, command []string, exitCode int, output string) (ChainEntry, error) {
	if err := os.MkdirAll(paths.logDir, 0o755); err != nil {
		return ChainEntry{}, err
	}
	chainPath := filepath.Join(paths.logDir, task+"-chain.jsonl")
	var entry ChainEntry
	err := fsx.WithFileLock(chainPath, func() error {
		entries := make([]ChainEntry, 0, 4)
		if data, err := os.ReadFile(chainPath); err == nil {
			for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
				if line == "" {
					continue
				}
				var parsed ChainEntry
				if json.Unmarshal([]byte(line), &parsed) != nil {
					// Linha corrompida não reseta as entradas anteriores válidas.
					continue
				}
				entries = append(entries, parsed)
			}
		}

		prevHash := genesisHash
		if len(entries) > 0 {
			prevHash = entries[len(entries)-1].EntryHash
		}
		entry = ChainEntry{
			Sequence:     len(entries) + 1,
			Timestamp:    nowISO(),
			Task:         task,
			Check:        check,
			Command:      append([]string(nil), command...),
			ExitCode:     exitCode,
			OutputSHA256: sha256Hex([]byte(output)),
			PrevHash:     prevHash,
		}
		payload, err := jsonx.Canonical([]any{
			prevHash,
			entry.Sequence,
			entry.Timestamp,
			task,
			check,
			entry.Command,
			exitCode,
			entry.OutputSHA256,
		})
		if err != nil {
			return err
		}
		entry.EntryHash = sha256Hex(payload)

		line, err := jsonx.Insertion(entry)
		if err != nil {
			return err
		}
		file, err := os.OpenFile(chainPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return err
		}
		_, writeErr := file.Write(append(line, '\n'))
		closeErr := file.Close()
		if writeErr != nil {
			return writeErr
		}
		return closeErr
	}, fsx.LockOptions{})
	return entry, err
}

// writeLog grava o log do check com a cadeia e devolve o caminho.
func writeLog(paths workPaths, task, check string, command []string, exitCode int, output, verdict, extra string) (string, error) {
	if err := os.MkdirAll(paths.logDir, 0o755); err != nil {
		return "", err
	}
	entry, err := appendEvidenceChain(paths, task, check, command, exitCode, output)
	if err != nil {
		return "", err
	}
	filePath := filepath.Join(paths.logDir, task+"-"+strings.ToLower(check)+".log")
	quoted := make([]string, len(command))
	for index, token := range command {
		quoted[index] = shellQuote(token)
	}
	content := fmt.Sprintf(
		"TASK: %s\nCHECK: %s\nCOMMAND: %s\nEXIT: %d\nOUTPUT:\n%s\n%sVERDICT: %s\nCHAIN_HASH: %s\n",
		task, check, strings.Join(quoted, " "), exitCode, output, extra, verdict, entry.EntryHash,
	)
	if err := fsx.WriteFileAtomic(filePath, content); err != nil {
		return "", err
	}
	return filePath, nil
}
