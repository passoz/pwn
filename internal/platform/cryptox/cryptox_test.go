package cryptox

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type goldenVectors struct {
	CanonicalJSON string `json:"canonical_json"`
	SHA256        string `json:"sha256"`
	HMACSHA256    string `json:"hmac_sha256"`
	Ed25519       string `json:"ed25519_signature"`
}

type goldenKey struct {
	Private string `json:"private"`
	Public  string `json:"public"`
}

func goldenFile(t *testing.T, name string) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return filepath.Join(dir, "testdata", "golden", "golden", name)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("go.mod não encontrado a partir de %s", dir)
		}
		dir = parent
	}
}

func loadJSON[T any](t *testing.T, name string) T {
	t.Helper()
	data, err := os.ReadFile(goldenFile(t, name))
	if err != nil {
		t.Fatalf("ler %s: %v", name, err)
	}
	var value T
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatalf("decodificar %s: %v", name, err)
	}
	return value
}

func TestGoldenVectors(t *testing.T) {
	vectors := loadJSON[goldenVectors](t, "vectors.json")
	if got := SHA256Hex([]byte("pwn-golden")); got != vectors.SHA256 {
		t.Fatalf("SHA256 = %s, want %s", got, vectors.SHA256)
	}
	if got := HMACSHA256Hex([]byte("pwn-golden-key"), []byte("pwn-golden")); got != vectors.HMACSHA256 {
		t.Fatalf("HMAC = %s, want %s", got, vectors.HMACSHA256)
	}
}

func TestEd25519GoldenSignature(t *testing.T) {
	vectors := loadJSON[goldenVectors](t, "vectors.json")
	key := loadJSON[goldenKey](t, "ed25519-key.json")

	privateKey, err := PrivateKeyFromJWK(key.Public, key.Private)
	if err != nil {
		t.Fatalf("PrivateKeyFromJWK: %v", err)
	}
	publicKey, err := PublicKeyFromJWK(key.Public)
	if err != nil {
		t.Fatalf("PublicKeyFromJWK: %v", err)
	}

	signature, err := SignBase64(privateKey, []byte(vectors.CanonicalJSON))
	if err != nil {
		t.Fatalf("SignBase64: %v", err)
	}
	if signature != vectors.Ed25519 {
		t.Fatalf("assinatura = %s, want %s", signature, vectors.Ed25519)
	}

	raw, err := base64.StdEncoding.DecodeString(vectors.Ed25519)
	if err != nil {
		t.Fatalf("decodificar assinatura: %v", err)
	}
	if !Verify(publicKey, []byte(vectors.CanonicalJSON), raw) {
		t.Fatal("Verify rejeitou a assinatura do vetor")
	}
	if Verify(publicKey, []byte(vectors.CanonicalJSON+"x"), raw) {
		t.Fatal("Verify aceitou mensagem alterada")
	}
	if VerifyBase64(publicKey, []byte(vectors.CanonicalJSON), "!!!") {
		t.Fatal("VerifyBase64 aceitou base64 inválido")
	}
}

func TestPublicKeyFingerprint(t *testing.T) {
	key := loadJSON[goldenKey](t, "ed25519-key.json")
	publicKey, err := PublicKeyFromJWK(key.Public)
	if err != nil {
		t.Fatalf("PublicKeyFromJWK: %v", err)
	}
	const want = "9e24d5be4a503879de6054453377155b2869a24a39624c335e8365873d1006f3"
	got, err := PublicKeyFingerprint(publicKey)
	if err != nil {
		t.Fatalf("PublicKeyFingerprint: %v", err)
	}
	if got != want {
		t.Fatalf("fingerprint = %s, want %s", got, want)
	}
}

func TestInvalidKeys(t *testing.T) {
	if _, err := PrivateKeyFromJWK("", ""); err == nil {
		t.Fatal("chave vazia aceita")
	}
	key := loadJSON[goldenKey](t, "ed25519-key.json")
	other := ed25519.PublicKey(bytes.Repeat([]byte{0x42}, ed25519.PublicKeySize))
	if _, err := PrivateKeyFromJWK(base64.RawURLEncoding.EncodeToString(other), key.Private); err == nil {
		t.Fatal("par público/privado divergente aceito")
	}
	if _, err := Sign(nil, []byte("x")); err == nil {
		t.Fatal("assinatura com chave inválida aceita")
	}
}
