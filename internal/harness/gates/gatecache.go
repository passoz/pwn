package gates

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/passoz/pwn/internal/assets"
	"github.com/passoz/pwn/internal/harness/contract"
	"github.com/passoz/pwn/internal/platform/fsx"
	"github.com/passoz/pwn/internal/platform/jsonx"
)

// GateCacheVersion é a versão do formato de cache. Um cache gravado por outra
// versão nunca é servido.
const GateCacheVersion = "2"

// HarnessVersion é a versão do harness que gravou o cache, lida do VERSION
// embutido — nunca de uma cópia literal, que sairia de sincronia no próximo
// bump e faria cache velho passar por atual.
func HarnessVersion() string {
	return assets.Version()
}

// GateCacheEnvelope é o envelope persistido em disco: metadados de versão, o
// GateOutput completo e a assinatura HMAC.
type GateCacheEnvelope struct {
	GateVersion    string      `json:"gate_version"`
	HarnessVersion string      `json:"harness_version"`
	LawsSHA256     string      `json:"laws_sha256"`
	ComputedAt     string      `json:"computed_at"`
	Output         *GateOutput `json:"output"`
	Signature      string      `json:"signature,omitempty"`
}

var (
	verifierKeyMutex sync.Mutex
	sessionKey       string
)

// GetVerifierKey devolve a chave de verificação para o HMAC dos vereditos.
//
// A ordem é: PWN_VERIFIER_KEY, .pwn/.verifier_key e, por último, uma chave
// aleatória gerada sob trava. A gravação usa tmp com modo 0600 e rename, para
// que leitores nunca vejam a chave pela metade nem com permissão frouxa.
func GetVerifierKey(workDir string) string {
	if key := strings.TrimSpace(os.Getenv("PWN_VERIFIER_KEY")); key != "" {
		return key
	}
	keyPath := filepath.Join(workDir, ".pwn", ".verifier_key")
	if info, err := os.Stat(keyPath); err == nil {
		if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
			_ = os.Chmod(keyPath, 0o600)
		}
		if data, err := os.ReadFile(keyPath); err == nil {
			if existing := strings.TrimSpace(string(data)); existing != "" {
				return existing
			}
		}
	}

	verifierKeyMutex.Lock()
	existing := sessionKey
	verifierKeyMutex.Unlock()
	if existing != "" {
		return existing
	}

	generated := randomKey()
	result := ""
	err := fsx.WithFileLock(keyPath, func() error {
		if data, err := os.ReadFile(keyPath); err == nil {
			if raced := strings.TrimSpace(string(data)); raced != "" {
				result = raced
				return nil
			}
		}
		tmp := keyPath + "." + strconv.Itoa(os.Getpid()) + ".tmp"
		if err := os.WriteFile(tmp, []byte(generated), 0o600); err != nil {
			return err
		}
		if err := os.Rename(tmp, keyPath); err != nil {
			_ = os.Remove(tmp)
			return err
		}
		result = generated
		return nil
	}, fsx.LockOptions{})
	if err != nil || result == "" {
		// Sem disco gravável (por exemplo, fs somente-leitura): retém a chave em
		// memória para a sessão.
		verifierKeyMutex.Lock()
		sessionKey = generated
		verifierKeyMutex.Unlock()
		return generated
	}
	return result
}

// ReadVerifierKey lê a chave SEM criá-la. Devolve "" quando não há
// PWN_VERIFIER_KEY nem .pwn/.verifier_key. Gerar uma chave nova aqui
// invalidaria em silêncio tudo o que já foi assinado.
func ReadVerifierKey(workDir string) string {
	if key := strings.TrimSpace(os.Getenv("PWN_VERIFIER_KEY")); key != "" {
		return key
	}
	data, err := os.ReadFile(filepath.Join(workDir, ".pwn", ".verifier_key"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func randomKey() string {
	buffer := make([]byte, 32)
	if _, err := rand.Read(buffer); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	return hex.EncodeToString(buffer)
}

// sortedInputPairs devolve os pares de input ordenados pela chave, como o
// Object.keys(...).sort() do TypeScript.
func sortedInputPairs(inputVersions InputVersions) [][2]string {
	pairs := make([][2]string, 0, len(inputVersions))
	for _, field := range inputVersions {
		pairs = append(pairs, [2]string{field.Key, jsScalarString(field.Value)})
	}
	sort.SliceStable(pairs, func(i, j int) bool { return pairs[i][0] < pairs[j][0] })
	return pairs
}

// canonicalGatePayload é a forma canônica assinada. A ordem dos campos é a do
// TypeScript.
func canonicalGatePayload(
	gate string,
	workID string,
	inputVersions InputVersions,
	result string,
	findings []contract.Finding,
	summary Summary,
	lawsSHA256 string,
	gateVersion string,
	harnessVersion string,
) (string, error) {
	if findings == nil {
		findings = []contract.Finding{}
	}
	payload := []any{
		gate,
		workID,
		sortedInputPairs(inputVersions),
		result,
		findings,
		summary,
		lawsSHA256,
		gateVersion,
		harnessVersion,
	}
	data, err := jsonx.Insertion(payload)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// SignVerdict assina o veredito com HMAC-SHA256 da chave do verificador.
func SignVerdict(output GateOutput, workDir, lawsSHA256 string) (string, error) {
	payload, err := canonicalGatePayload(
		output.Gate,
		output.WorkID,
		output.InputVersions,
		string(output.Result),
		output.Findings,
		output.Summary,
		lawsSHA256,
		GateCacheVersion,
		HarnessVersion(),
	)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, []byte(GetVerifierKey(workDir)))
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// VerifyVerdict confere a assinatura de um veredito em tempo constante.
func VerifyVerdict(output GateOutput, workDir, lawsSHA256, signature, gateVersion, harnessVersion string) bool {
	payload, err := canonicalGatePayload(
		output.Gate,
		output.WorkID,
		output.InputVersions,
		string(output.Result),
		output.Findings,
		output.Summary,
		lawsSHA256,
		gateVersion,
		harnessVersion,
	)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, []byte(GetVerifierKey(workDir)))
	mac.Write([]byte(payload))
	expected := hex.EncodeToString(mac.Sum(nil))
	if len(signature) != len(expected) {
		return false
	}
	return hmac.Equal([]byte(signature), []byte(expected))
}

// gateCacheDir é `.pwn/gate-cache/` sob o workDir informado.
func gateCacheDir(workDir string) string {
	return filepath.Join(workDir, ".pwn", "gate-cache")
}

// gateCacheFilePath é o caminho determinístico para um par gate + hashes.
func gateCacheFilePath(gate, workDir string, inputVersions InputVersions) string {
	return filepath.Join(gateCacheDir(workDir), gate+"-"+GateCacheKey(gate, inputVersions)+".json")
}

// GateCacheKey devolve a chave estável do par gate + hashes de input.
// Independente da ordem das chaves: as entradas são ordenadas antes do hash.
// O resultado é SHA-256 de JSON.stringify([gate, entradas]) truncado em 12
// caracteres hexadecimais.
func GateCacheKey(gate string, inputVersions InputVersions) string {
	payload, err := jsonx.Insertion([]any{gate, sortedInputPairs(inputVersions)})
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:])[:12]
}

// ReadGateCache lê o cache. Devolve nil quando o arquivo está ausente, é
// corrompido, quando as versões divergem ou quando a assinatura não confere.
func ReadGateCache(gate, workDir string, inputVersions InputVersions) *GateOutput {
	file := gateCacheFilePath(gate, workDir, inputVersions)
	data, err := os.ReadFile(file)
	if err != nil {
		return nil
	}
	var envelope GateCacheEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return nil
	}
	if envelope.GateVersion != GateCacheVersion {
		return nil
	}
	if envelope.HarnessVersion != HarnessVersion() {
		return nil
	}
	if envelope.LawsSHA256 != "" && envelope.LawsSHA256 != assets.LawsDigest() {
		return nil
	}
	if envelope.Output == nil {
		return nil
	}
	output := *envelope.Output
	if output.Gate != gate {
		return nil
	}

	cachedVersions := output.InputVersions
	if len(inputVersions) != len(cachedVersions) {
		return nil
	}
	for _, requested := range inputVersions {
		value, ok := cachedVersions.Get(requested.Key)
		if !ok || value != jsScalarString(requested.Value) {
			return nil
		}
	}

	// A assinatura HMAC é estritamente obrigatória na versão 2.
	if envelope.Signature == "" {
		return nil
	}
	lawsSHA256 := envelope.LawsSHA256
	if lawsSHA256 == "" {
		lawsSHA256 = assets.LawsDigest()
	}
	if !VerifyVerdict(output, workDir, lawsSHA256, envelope.Signature, envelope.GateVersion, envelope.HarnessVersion) {
		return nil
	}
	return &output
}

// WriteGateCache grava o output do gate no cache. Um erro de IO é devolvido
// ao chamador; o cache é uma otimização e nunca interrompe o gate.
func WriteGateCache(output GateOutput, workDir string) error {
	if err := os.MkdirAll(gateCacheDir(workDir), 0o755); err != nil {
		return err
	}
	lawsSHA256 := assets.LawsDigest()
	signature, err := SignVerdict(output, workDir, lawsSHA256)
	if err != nil {
		return err
	}
	envelope := GateCacheEnvelope{
		GateVersion:    GateCacheVersion,
		HarnessVersion: HarnessVersion(),
		LawsSHA256:     lawsSHA256,
		ComputedAt:     time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
		Output:         &output,
		Signature:      signature,
	}
	data, err := marshalEnvelope(envelope)
	if err != nil {
		return err
	}
	return fsx.WriteFileAtomic(gateCacheFilePath(output.Gate, workDir, output.InputVersions), data)
}

// marshalEnvelope emite o envelope com dois espaços de indentação, sem escapar
// HTML, como o JSON.stringify(envelope, null, 2) do TypeScript.
//
// O output é serializado por MarshalOutput e embutido como texto: json.Indent
// só acrescenta espaços, então <, > e & permanecem literais.
func marshalEnvelope(envelope GateCacheEnvelope) (string, error) {
	output := []byte("null")
	if envelope.Output != nil {
		serialized, err := MarshalOutput(*envelope.Output)
		if err != nil {
			return "", err
		}
		output = serialized
	}
	parts := make([]string, 0, 6)
	appendField := func(name, value string) {
		parts = append(parts, quoteJSON(name)+":"+value)
	}
	appendField("gate_version", quoteJSON(envelope.GateVersion))
	appendField("harness_version", quoteJSON(envelope.HarnessVersion))
	appendField("laws_sha256", quoteJSON(envelope.LawsSHA256))
	appendField("computed_at", quoteJSON(envelope.ComputedAt))
	appendField("output", string(output))
	if envelope.Signature != "" {
		appendField("signature", quoteJSON(envelope.Signature))
	}
	compact := []byte("{" + strings.Join(parts, ",") + "}")
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, compact, "", "  "); err != nil {
		return "", err
	}
	return pretty.String(), nil
}

// quoteJSON devolve o valor como string JSON, com o escape do JSON.stringify.
func quoteJSON(value string) string {
	data, err := jsonx.Insertion(value)
	if err != nil {
		return "\"\""
	}
	return string(data)
}

// removeCacheDir remove os arquivos de cache de um diretório e devolve quantos
// removeu.
func removeCacheDir(dir string) int {
	removed := 0
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		if err := os.Remove(filepath.Join(dir, entry.Name())); err == nil {
			removed++
		}
	}
	if remaining, err := os.ReadDir(dir); err == nil && len(remaining) == 0 {
		_ = os.Remove(dir)
	}
	return removed
}

// ClearGateCache remove o cache de gates. Com workDir, remove o cache daquele
// diretório; com workDir vazio, remove o cache do diretório atual e de todos os
// Works sob `.pwn/work/*`.
func ClearGateCache(workDir string) int {
	if workDir != "" {
		return removeCacheDir(gateCacheDir(workDir))
	}

	root, err := os.Getwd()
	if err != nil {
		return 0
	}
	removed := removeCacheDir(gateCacheDir(root))
	workRoot := filepath.Join(root, ".pwn", "work")
	entries, err := os.ReadDir(workRoot)
	if err != nil {
		return removed
	}
	for _, entry := range entries {
		if entry.IsDir() {
			removed += removeCacheDir(gateCacheDir(filepath.Join(workRoot, entry.Name())))
		}
	}
	return removed
}
