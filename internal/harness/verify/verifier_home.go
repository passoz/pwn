// Package verify porta a aceitação independente de src/core/verifier-home.ts,
// src/core/acceptance-approval.ts, src/core/candidate-snapshot.ts,
// src/core/verification-runner.ts, src/core/verification-receipt.ts e
// src/core/acceptance-flow.ts.
//
// A raiz do verificador fica FORA da árvore do projeto: configuração, chaves e
// registros. O candidato pode escrever o repositório inteiro; nada daqui pode
// estar em um caminho que ele controle, senão a autoridade de conclusão volta a
// ser do próprio candidato.
//
// PWN_VERIFIER_HOME redireciona a raiz. É configuração do operador e a única
// forma de mover a raiz (testes e instalações isoladas).
package verify

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/passoz/pwn/internal/platform/cryptox"
)

// HomeEnv é a variável que redireciona a raiz do verificador.
const HomeEnv = "PWN_VERIFIER_HOME"

// VerificationUnavailable marca um pré-requisito ausente do verificador. Nunca
// vira "aceito" e nunca é ignorado: a camada de comando o traduz em exit 2.
type VerificationUnavailable struct {
	// Message é a mensagem curta entregue ao operador.
	Message string
	// Detail indica a ação corretiva.
	Detail string
}

// Error devolve a mensagem curta.
func (e *VerificationUnavailable) Error() string { return e.Message }

// IsUnavailable informa se err é um pré-requisito ausente do verificador.
func IsUnavailable(err error) bool {
	var unavailable *VerificationUnavailable
	return errors.As(err, &unavailable)
}

func unavailable(message, detail string) error {
	return &VerificationUnavailable{Message: message, Detail: detail}
}

// VerifierConfig é o conteúdo de config.json, escrito pelo operador.
type VerifierConfig struct {
	Version    int             `json:"version"`
	VerifierID string          `json:"verifier_id"`
	CreatedAt  string          `json:"created_at"`
	Runtime    RuntimeConfig   `json:"runtime"`
	Isolation  IsolationConfig `json:"isolation"`
	// Projects guarda os ajustes de sandbox por raiz de projeto. Ausente usa a
	// política padrão.
	Projects map[string]json.RawMessage `json:"projects,omitempty"`
}

// RuntimeConfig é o runtime aprovado para executar os checks de aceitação.
type RuntimeConfig struct {
	Bun string `json:"bun"`
}

// IsolationConfig é o isolamento exigido: sem ele não existe aceitação
// independente.
type IsolationConfig struct {
	Mode    string  `json:"mode"`
	Bwrap   *string `json:"bwrap"`
	Network bool    `json:"network"`
}

// ProjectMount é uma montagem somente leitura com destino diferente da origem,
// por exemplo um cache em um HOME fixo do sandbox.
type ProjectMount struct {
	Source string `json:"source"`
	Dest   string `json:"dest"`
}

// ProjectSandboxConfig são os ajustes de sandbox de um projeto. Vêm da raiz
// protegida: o repositório avaliado não os controla.
type ProjectSandboxConfig struct {
	// PathPrepend são diretórios absolutos prefixados ao PATH; montados somente
	// leitura.
	PathPrepend []string `json:"path_prepend"`
	// MountsRO são diretórios absolutos extras montados somente leitura.
	MountsRO []string `json:"mounts_ro"`
	// Mounts são montagens somente leitura com destino próprio.
	Mounts []ProjectMount `json:"mounts"`
	// Overlays são caches pré-aquecidos: Source (lower, somente leitura) montado
	// em Dest com camada de escrita em tmpfs, descartada ao fim da execução. O
	// código avaliado lê o cache e nunca o altera. Extensão do Go: o verificador
	// TypeScript ignora a chave.
	Overlays []ProjectMount `json:"overlays,omitempty"`
	// Home é o HOME do sandbox. Vazio usa "/nonexistent".
	Home string `json:"home,omitempty"`
	// Env são variáveis fixas do sandbox. HOME, PATH e TMPDIR são reservadas.
	Env map[string]string `json:"env"`
}

var reservedSandboxEnv = map[string]bool{"HOME": true, "PATH": true, "TMPDIR": true}

var reservedMountDest = map[string]bool{"/": true, "/tmp": true, "/proc": true, "/dev": true}

// cleanAbsolute devolve um caminho absoluto normalizado, ou ok=false quando o
// valor não é um caminho utilizável.
func cleanAbsolute(value any) (string, bool) {
	text, ok := value.(string)
	if !ok || !filepath.IsAbs(text) {
		return "", false
	}
	normalized := filepath.Clean(text)
	if normalized == string(filepath.Separator) {
		return normalized, true
	}
	return strings.TrimRight(normalized, string(filepath.Separator)), true
}

func inside(parent, child string) bool {
	return child == parent || strings.HasPrefix(child, parent+string(filepath.Separator))
}

// Root devolve a raiz do verificador: PWN_VERIFIER_HOME quando definida, senão
// ~/.config/pwn/verifier.
func Root() (string, error) {
	if override := strings.TrimSpace(os.Getenv(HomeEnv)); override != "" {
		return filepath.Abs(override)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("verifier: resolver o diretório pessoal: %w", err)
	}
	return filepath.Join(home, ".config", "pwn", "verifier"), nil
}

// resolveRoot resolve a raiz: vazia usa Root.
func resolveRoot(root string) (string, error) {
	if strings.TrimSpace(root) == "" {
		return Root()
	}
	return filepath.Abs(root)
}

// ConfigFile devolve o caminho de config.json.
func ConfigFile(root string) string { return filepath.Join(root, "config.json") }

// KeysDir devolve o diretório das chaves.
func KeysDir(root string) string { return filepath.Join(root, "keys") }

// PrivateKeyFile devolve o caminho da chave privada Ed25519 em PKCS#8 PEM.
func PrivateKeyFile(root string) string {
	return filepath.Join(KeysDir(root), "verifier-private.pem")
}

// PublicKeyFile devolve o caminho da chave pública Ed25519 em SPKI PEM.
func PublicKeyFile(root string) string {
	return filepath.Join(KeysDir(root), "verifier-public.pem")
}

// ApprovalsDir devolve o diretório dos pacotes de aprovação.
func ApprovalsDir(root string) string { return filepath.Join(root, "approvals") }

// ApprovalFilesDir devolve o diretório dos arquivos aprovados de um pacote.
func ApprovalFilesDir(approvalID, root string) string {
	return filepath.Join(ApprovalsDir(root), approvalID, "files")
}

// ReceiptDir devolve o diretório dos recibos.
func ReceiptDir(root string) string { return filepath.Join(root, "receipts") }

// DefaultRuntime devolve o caminho do executável que roda o verificador.
func DefaultRuntime() string {
	// O runtime aprovado é o ambiente que executa os checks. Prefira um
	// interpretador conhecido, como o TypeScript fazia com o próprio Bun; o
	// executável do pwn fica como último recurso.
	for _, name := range []string{"bun", "go"} {
		if found, ok := FindExecutable(name); ok {
			// O caminho real vai para a configuração e para o sandbox: um link
			// como `.../bun/latest` pode apontar para outra versão depois da
			// aprovação sem que o recibo perceba.
			if real, err := filepath.EvalSymlinks(found); err == nil {
				return real
			}
			return found
		}
	}
	executable, err := os.Executable()
	if err != nil {
		return ""
	}
	return executable
}

// FindExecutable procura name no PATH. ok=false quando não existe.
func FindExecutable(name string) (string, bool) {
	found, err := exec.LookPath(name)
	if err != nil || found == "" {
		return "", false
	}
	return found, true
}

// WriteJSONAtomic grava value como JSON indentado com escrita atômica: um
// leitor nunca observa o arquivo truncado.
func WriteJSONAtomic(file string, value any) error {
	if err := os.MkdirAll(filepath.Dir(file), 0o777); err != nil {
		return fmt.Errorf("verifier: criar %s: %w", filepath.Dir(file), err)
	}
	temporary := fmt.Sprintf("%s.tmp-%d", file, os.Getpid())
	buffer := &strings.Builder{}
	encoder := json.NewEncoder(buffer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		return fmt.Errorf("verifier: serializar %s: %w", file, err)
	}
	if err := os.WriteFile(temporary, []byte(buffer.String()), 0o644); err != nil {
		return fmt.Errorf("verifier: gravar %s: %w", temporary, err)
	}
	if err := os.Rename(temporary, file); err != nil {
		return fmt.Errorf("verifier: publicar %s: %w", file, err)
	}
	return nil
}

// WriteFileAtomic grava content em file com escrita atômica e modo opcional.
func WriteFileAtomic(file, content string, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(file), 0o777); err != nil {
		return fmt.Errorf("verifier: criar %s: %w", filepath.Dir(file), err)
	}
	temporary := fmt.Sprintf("%s.tmp-%d", file, os.Getpid())
	if err := os.WriteFile(temporary, []byte(content), 0o644); err != nil {
		return fmt.Errorf("verifier: gravar %s: %w", temporary, err)
	}
	if err := os.Chmod(temporary, mode); err != nil {
		return fmt.Errorf("verifier: ajustar modo de %s: %w", temporary, err)
	}
	if err := os.Rename(temporary, file); err != nil {
		return fmt.Errorf("verifier: publicar %s: %w", file, err)
	}
	return nil
}

func ensurePrivateDir(directory string) error {
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("verifier: criar %s: %w", directory, err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		// Sistemas sem semântica POSIX de permissão não têm como aplicar.
		return nil
	}
	return nil
}

// ReadConfig lê config.json. Devolve nil quando o arquivo não existe, não é
// JSON ou declara versão diferente de 1.
func ReadConfig(root string) *VerifierConfig {
	data, err := os.ReadFile(ConfigFile(root))
	if err != nil {
		return nil
	}
	var config VerifierConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil
	}
	if config.Version != 1 {
		return nil
	}
	return &config
}

// Initialization é o resultado de InitializeVerifierHome.
type Initialization struct {
	Root    string
	Config  VerifierConfig
	Created bool
}

// InitializeVerifierHome cria a raiz protegida quando ausente: diretório 0700,
// par de chaves Ed25519 e configuração com runtime e isolamento detectados no
// host.
func InitializeVerifierHome(root string) (Initialization, error) {
	resolved, err := resolveRoot(root)
	if err != nil {
		return Initialization{}, err
	}
	existing := ReadConfig(resolved)
	for _, directory := range []string{resolved, KeysDir(resolved), ApprovalsDir(resolved), ReceiptDir(resolved)} {
		if err := ensurePrivateDir(directory); err != nil {
			return Initialization{}, err
		}
	}

	_, privateErr := os.Stat(PrivateKeyFile(resolved))
	_, publicErr := os.Stat(PublicKeyFile(resolved))
	if privateErr != nil || publicErr != nil {
		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return Initialization{}, fmt.Errorf("verifier: gerar par de chaves: %w", err)
		}
		privatePEM, err := encodePrivateKeyPEM(privateKey)
		if err != nil {
			return Initialization{}, err
		}
		publicPEM, err := encodePublicKeyPEM(publicKey)
		if err != nil {
			return Initialization{}, err
		}
		if err := WriteFileAtomic(PrivateKeyFile(resolved), privatePEM, 0o600); err != nil {
			return Initialization{}, err
		}
		if err := WriteFileAtomic(PublicKeyFile(resolved), publicPEM, 0o600); err != nil {
			return Initialization{}, err
		}
	}

	if existing != nil {
		return Initialization{Root: resolved, Config: *existing, Created: false}, nil
	}

	hostname, err := os.Hostname()
	if err != nil {
		return Initialization{}, fmt.Errorf("verifier: resolver o hostname: %w", err)
	}
	bwrap, hasBwrap := FindExecutable("bwrap")
	config := VerifierConfig{
		Version:    1,
		VerifierID: fmt.Sprintf("%s-%s", hostname, DigestOfText(resolved)[:8]),
		CreatedAt:  isoNow(),
		Runtime:    RuntimeConfig{Bun: DefaultRuntime()},
		Isolation: IsolationConfig{
			Mode:    "bwrap",
			Bwrap:   optionalPath(bwrap, hasBwrap),
			Network: false,
		},
	}
	if err := WriteJSONAtomic(ConfigFile(resolved), config); err != nil {
		return Initialization{}, err
	}
	return Initialization{Root: resolved, Config: config, Created: true}, nil
}

func optionalPath(path string, present bool) *string {
	if !present {
		return nil
	}
	return &path
}

func isoNow() string {
	return time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
}

func encodePrivateKeyPEM(privateKey ed25519.PrivateKey) (string, error) {
	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return "", fmt.Errorf("verifier: exportar a chave privada: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), nil
}

func encodePublicKeyPEM(publicKey ed25519.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", fmt.Errorf("verifier: exportar a chave pública: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), nil
}

func readPrivateKeyFile(file string) ed25519.PrivateKey {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil
	}
	privateKey, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil
	}
	return privateKey
}

func readPublicKeyFile(file string) ed25519.PublicKey {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil
	}
	publicKey, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil
	}
	return publicKey
}

// LoadPrivateKey devolve a chave privada do verificador: só o processo que
// avalia pode carregá-la. ok=false quando ausente ou inválida.
func LoadPrivateKey(root string) (ed25519.PrivateKey, bool) {
	key := readPrivateKeyFile(PrivateKeyFile(root))
	return key, key != nil
}

// LoadPublicKey devolve a chave pública do verificador. ok=false quando ausente
// ou inválida.
func LoadPublicKey(root string) (ed25519.PublicKey, bool) {
	key := readPublicKeyFile(PublicKeyFile(root))
	return key, key != nil
}

// PublicKeyFingerprint devolve o SHA-256 hexadecimal do SubjectPublicKeyInfo DER
// da chave pública. Identifica quem assinou sem expor a privada.
func PublicKeyFingerprint(root string) (string, bool) {
	publicKey, ok := LoadPublicKey(root)
	if !ok {
		return "", false
	}
	fingerprint, err := cryptox.PublicKeyFingerprint(publicKey)
	if err != nil {
		return "", false
	}
	return fingerprint, true
}

// VerifierReadiness é o conjunto de pré-requisitos verificados.
type VerifierReadiness struct {
	Root                 string
	Config               VerifierConfig
	Runtime              string
	Bwrap                string
	PublicKeyFingerprint string
}

// RequireVerifierReady confere runtime, bwrap e chave pública. Sem qualquer um
// deles não há aceitação independente.
func RequireVerifierReady(root string) (VerifierReadiness, error) {
	resolved, err := resolveRoot(root)
	if err != nil {
		return VerifierReadiness{}, err
	}
	config := ReadConfig(resolved)
	if config == nil {
		return VerifierReadiness{}, unavailable(
			fmt.Sprintf("verificador independente não configurado em %s", resolved),
			"inicialize com 'pwn verify init' antes de pedir aceitação",
		)
	}
	runtime := config.Runtime.Bun
	if runtime == "" || !pathExists(runtime) {
		shown := runtime
		if shown == "" {
			shown = "(vazio)"
		}
		return VerifierReadiness{}, unavailable(
			fmt.Sprintf("runtime aprovado do verificador não encontrado: %s", shown),
			"reinstale o verificador ou atualize a configuração protegida",
		)
	}
	if config.Isolation.Bwrap == nil || *config.Isolation.Bwrap == "" || !pathExists(*config.Isolation.Bwrap) {
		return VerifierReadiness{}, unavailable(
			"isolamento indisponível: sem bwrap não existe aceitação independente",
			"instale bubblewrap ou marque a verificação como indisponível (nunca execute no host)",
		)
	}
	fingerprint, ok := PublicKeyFingerprint(resolved)
	if !ok {
		return VerifierReadiness{}, unavailable(
			fmt.Sprintf("chave pública do verificador ausente em %s", PublicKeyFile(resolved)),
			"gere o par de chaves com 'pwn verify init'",
		)
	}
	return VerifierReadiness{
		Root:                 resolved,
		Config:               *config,
		Runtime:              runtime,
		Bwrap:                *config.Isolation.Bwrap,
		PublicKeyFingerprint: fingerprint,
	}, nil
}

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// ProtectedPaths devolve os diretórios que o sandbox de avaliação nunca pode
// enxergar.
func ProtectedPaths(root string) []string {
	return []string{root, filepath.Dir(root)}
}

// AssertProtectedOutsideRepository recusa a raiz protegida dentro do projeto
// avaliado: ela seria copiada para o snapshot, ficaria visível ao código
// avaliado e poderia ser alterada por ele.
func AssertProtectedOutsideRepository(root, repositoryRoot string) error {
	verified, err := filepath.Abs(root)
	if err != nil {
		return fmt.Errorf("verifier: resolver %s: %w", root, err)
	}
	repository, err := filepath.Abs(repositoryRoot)
	if err != nil {
		return fmt.Errorf("verifier: resolver %s: %w", repositoryRoot, err)
	}
	if verified == repository || strings.HasPrefix(verified, repository+string(filepath.Separator)) {
		return unavailable(
			fmt.Sprintf("raiz do verificador dentro do repositório avaliado: %s", verified),
			fmt.Sprintf("mova-a para fora de %s (padrão: ~/.config/pwn/verifier) ou aponte PWN_VERIFIER_HOME para um caminho externo", repository),
		)
	}
	return nil
}

// ListJSONFiles lista os arquivos .json de um diretório, em ordem. Diretório
// ausente devolve lista vazia; falha de leitura devolve erro.
func ListJSONFiles(directory string) ([]string, error) {
	entries, err := os.ReadDir(directory)
	if errors.Is(err, fs.ErrNotExist) {
		return []string{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("verifier: listar %s: %w", directory, err)
	}
	files := make([]string, 0, len(entries))
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".json") {
			files = append(files, filepath.Join(directory, entry.Name()))
		}
	}
	sort.Strings(files)
	return files, nil
}

// IsDirectory informa se target existe e é um diretório.
func IsDirectory(target string) bool {
	stats, err := os.Stat(target)
	return err == nil && stats.IsDir()
}

// DigestOfFile devolve o SHA-256 do conteúdo de file em hexadecimal.
func DigestOfFile(file string) (string, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return "", fmt.Errorf("verifier: ler %s: %w", file, err)
	}
	return DigestOfText(string(data)), nil
}

// DigestOfText devolve o SHA-256 de um texto UTF-8 em hexadecimal.
func DigestOfText(value string) string {
	return cryptox.SHA256HexText(value)
}

// digestBytes devolve o SHA-256 de bytes em hexadecimal.
func digestBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
