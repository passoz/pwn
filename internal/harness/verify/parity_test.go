package verify_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/passoz/pwn/internal/harness/verify"
	"github.com/passoz/pwn/internal/platform/cryptox"
	"github.com/passoz/pwn/internal/platform/jsonx"
)

type parityTreeEntry struct {
	Path    string `json:"path"`
	Content string `json:"content"`
	Symlink string `json:"symlink"`
}

type parityFixture struct {
	Note     string `json:"note"`
	Verifier struct {
		Config        map[string]any `json:"config"`
		PrivateKeyPEM string         `json:"private_key_pem"`
		PublicKeyPEM  string         `json:"public_key_pem"`
		Fingerprint   string         `json:"fingerprint"`
	} `json:"verifier"`
	ApprovalContent verify.ApprovalContent     `json:"approval_content"`
	ApprovalID      string                     `json:"approval_id"`
	Receipt         verify.VerificationReceipt `json:"receipt"`
	Snapshot        struct {
		Tree   []parityTreeEntry      `json:"tree"`
		Files  []verify.SnapshotEntry `json:"files"`
		Digest string                 `json:"digest"`
	} `json:"snapshot"`
	Dependency struct {
		Manifests map[string]string       `json:"manifests"`
		Files     []verify.DependencyFile `json:"files"`
		Digest    string                  `json:"digest"`
	} `json:"dependency"`
}

func loadParity(t *testing.T) parityFixture {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "parity", "verify", "fixture.json"))
	if err != nil {
		t.Fatalf("ler a fixture de paridade: %v", err)
	}
	var fixture parityFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatalf("decodificar a fixture de paridade: %v", err)
	}
	return fixture
}

func verifierFromFixture(t *testing.T, fixture parityFixture) string {
	t.Helper()
	root := t.TempDir()
	writeFile(t, root, "keys/verifier-private.pem", fixture.Verifier.PrivateKeyPEM)
	writeFile(t, root, "keys/verifier-public.pem", fixture.Verifier.PublicKeyPEM)
	config, err := json.Marshal(fixture.Verifier.Config)
	if err != nil {
		t.Fatalf("serializar a configuração da fixture: %v", err)
	}
	writeFile(t, root, "config.json", string(config)+"\n")
	return root
}

// A fixture foi gerada pelo bun a partir da referência TypeScript. A assinatura
// Ed25519 é determinística: se os bytes canônicos divergissem, a assinatura
// recalculada aqui não seria igual.
func TestReceiptParityWithTypeScriptFixture(t *testing.T) {
	fixture := loadParity(t)
	root := verifierFromFixture(t, fixture)

	canonicalContent, err := jsonx.Canonical(fixture.ApprovalContent)
	if err != nil {
		t.Fatalf("canonicalizar o conteúdo da aprovação: %v", err)
	}
	if digest := cryptox.SHA256Hex(canonicalContent); digest != fixture.ApprovalID {
		t.Errorf("approval_id = %s, quer %s", digest, fixture.ApprovalID)
	}

	fingerprint, ok := verify.PublicKeyFingerprint(root)
	if !ok {
		t.Fatal("chave pública da fixture não carregou")
	}
	if fingerprint != fixture.Verifier.Fingerprint {
		t.Errorf("fingerprint = %s, quer %s", fingerprint, fixture.Verifier.Fingerprint)
	}

	if !verify.SignatureIsValid(fixture.Receipt, root) {
		t.Fatal("o recibo da fixture não verifica")
	}
	canonicalBase, err := jsonx.Canonical(fixture.Receipt.ReceiptBase)
	if err != nil {
		t.Fatalf("canonicalizar o recibo: %v", err)
	}
	if digest := cryptox.SHA256Hex(canonicalBase); digest != fixture.Receipt.ReceiptID {
		t.Errorf("receipt_id = %s, quer %s", digest, fixture.Receipt.ReceiptID)
	}

	canonicalSubject, err := jsonx.Canonical(fixture.Receipt.ReceiptSubject)
	if err != nil {
		t.Fatalf("canonicalizar o sujeito: %v", err)
	}
	privateKey, ok := verify.LoadPrivateKey(root)
	if !ok {
		t.Fatal("chave privada da fixture não carregou")
	}
	signature, err := cryptox.SignBase64(privateKey, canonicalSubject)
	if err != nil {
		t.Fatalf("assinar o sujeito: %v", err)
	}
	if signature != fixture.Receipt.Signature {
		t.Errorf("assinatura recalculada diverge da fixture:\n%s\n%s", signature, fixture.Receipt.Signature)
	}

	forged := fixture.Receipt
	forged.Outcome = "fail"
	if verify.SignatureIsValid(forged, root) {
		t.Error("um recibo adulterado não pode verificar")
	}
}

func TestSnapshotParityWithTypeScriptFixture(t *testing.T) {
	fixture := loadParity(t)
	rootDir := t.TempDir()
	for _, entry := range fixture.Snapshot.Tree {
		if entry.Symlink != "" {
			target := filepath.Join(rootDir, entry.Path)
			if err := os.MkdirAll(filepath.Dir(target), 0o777); err != nil {
				t.Fatalf("criar %s: %v", filepath.Dir(target), err)
			}
			if err := os.Symlink(entry.Symlink, target); err != nil {
				t.Fatalf("criar o vínculo %s: %v", target, err)
			}
			continue
		}
		writeFile(t, rootDir, entry.Path, entry.Content)
	}

	snapshot, err := verify.CaptureSnapshot(rootDir)
	if err != nil {
		t.Fatalf("capturar o snapshot: %v", err)
	}
	if snapshot.Digest != fixture.Snapshot.Digest {
		t.Errorf("digest do snapshot = %s, quer %s", snapshot.Digest, fixture.Snapshot.Digest)
	}
	if !reflect.DeepEqual(snapshot.Files, fixture.Snapshot.Files) {
		t.Errorf("entradas do snapshot divergem:\n%+v\n%+v", snapshot.Files, fixture.Snapshot.Files)
	}
	for _, entry := range snapshot.Files {
		for _, excluded := range []string{".git", ".todo", "node_modules"} {
			if entry.Path == excluded || len(entry.Path) > len(excluded) && entry.Path[:len(excluded)+1] == excluded+"/" {
				t.Errorf("%s não deveria entrar no snapshot", entry.Path)
			}
		}
	}
}

func TestDependencyDigestParityWithTypeScriptFixture(t *testing.T) {
	fixture := loadParity(t)
	rootDir := t.TempDir()
	for relative, content := range fixture.Dependency.Manifests {
		writeFile(t, rootDir, relative, content)
	}
	dependency, err := verify.CaptureDependencyDigest(rootDir)
	if err != nil {
		t.Fatalf("capturar as dependências: %v", err)
	}
	if dependency.Digest != fixture.Dependency.Digest {
		t.Errorf("dependency digest = %s, quer %s", dependency.Digest, fixture.Dependency.Digest)
	}
	if !reflect.DeepEqual(dependency.Files, fixture.Dependency.Files) {
		t.Errorf("manifestos divergem:\n%+v\n%+v", dependency.Files, fixture.Dependency.Files)
	}
}
