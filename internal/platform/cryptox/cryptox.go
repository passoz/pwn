// Package cryptox reúne as primitivas criptográficas do verificador
// independente: SHA-256, HMAC-SHA256, Ed25519 e impressão digital de chave.
//
// O Node assina com Ed25519 puro (algoritmo null) e exporta a chave pública em
// SubjectPublicKeyInfo DER. As funções deste pacote reproduzem esses bytes.
package cryptox

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
)

// SHA256 devolve o SHA-256 de data.
func SHA256(data []byte) [32]byte {
	return sha256.Sum256(data)
}

// SHA256Hex devolve o SHA-256 de data em hexadecimal minúsculo.
func SHA256Hex(data []byte) string {
	sum := SHA256(data)
	return hex.EncodeToString(sum[:])
}

// SHA256HexText devolve o SHA-256 de um texto UTF-8 em hexadecimal minúsculo.
func SHA256HexText(text string) string {
	return SHA256Hex([]byte(text))
}

// HMACSHA256 devolve o HMAC-SHA256 de data com a chave key.
func HMACSHA256(key, data []byte) [32]byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	var sum [32]byte
	copy(sum[:], mac.Sum(nil))
	return sum
}

// HMACSHA256Hex devolve o HMAC-SHA256 de data em hexadecimal minúsculo.
func HMACSHA256Hex(key, data []byte) string {
	sum := HMACSHA256(key, data)
	return hex.EncodeToString(sum[:])
}

// Sign assina message com a chave privada Ed25519.
func Sign(privateKey ed25519.PrivateKey, message []byte) ([]byte, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("cryptox: chave privada Ed25519 inválida: %d bytes", len(privateKey))
	}
	return ed25519.Sign(privateKey, message), nil
}

// SignBase64 assina message e devolve a assinatura em base64 padrão.
func SignBase64(privateKey ed25519.PrivateKey, message []byte) (string, error) {
	signature, err := Sign(privateKey, message)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(signature), nil
}

// Verify confere a assinatura Ed25519 de message.
func Verify(publicKey ed25519.PublicKey, message, signature []byte) bool {
	if len(publicKey) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(publicKey, message, signature)
}

// VerifyBase64 confere uma assinatura Ed25519 codificada em base64 padrão.
func VerifyBase64(publicKey ed25519.PublicKey, message []byte, signature string) bool {
	decoded, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false
	}
	return Verify(publicKey, message, decoded)
}

// ErrInvalidKey marca uma chave pública ou privada malformada.
var ErrInvalidKey = errors.New("cryptox: chave inválida")

// PrivateKeyFromJWK monta uma chave privada Ed25519 a partir das partes públicas
// e privadas de um JWK OKP (base64url sem padding), como no arquivo de chave do
// verificador. A parte pública precisa ter 32 bytes.
func PrivateKeyFromJWK(publicPart, privatePart string) (ed25519.PrivateKey, error) {
	publicKey, err := PublicKeyFromJWK(publicPart)
	if err != nil {
		return nil, err
	}
	seed, err := decodeBase64URL(privatePart)
	if err != nil {
		return nil, fmt.Errorf("%w: d: %v", ErrInvalidKey, err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("%w: d com %d bytes", ErrInvalidKey, len(seed))
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	if !ed25519.PublicKey(privateKey[ed25519.SeedSize:]).Equal(publicKey) {
		return nil, fmt.Errorf("%w: a parte pública não corresponde à privada", ErrInvalidKey)
	}
	return privateKey, nil
}

// PublicKeyFromJWK monta uma chave pública Ed25519 a partir de x (base64url
// sem padding).
func PublicKeyFromJWK(publicPart string) (ed25519.PublicKey, error) {
	bytes, err := decodeBase64URL(publicPart)
	if err != nil {
		return nil, fmt.Errorf("%w: x: %v", ErrInvalidKey, err)
	}
	if len(bytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: x com %d bytes", ErrInvalidKey, len(bytes))
	}
	return ed25519.PublicKey(bytes), nil
}

func decodeBase64URL(value string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(value)
}

// SPKI devolve a chave pública no formato SubjectPublicKeyInfo DER, o mesmo
// formato que o Node exporta em key.export({type: "spki", format: "der"}).
//
// DER de Ed25519: SEQUENCE { SEQUENCE { OID 1.3.101.112 }, BIT STRING 0x00||key }.
func SPKI(publicKey ed25519.PublicKey) ([]byte, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: chave pública com %d bytes", ErrInvalidKey, len(publicKey))
	}
	der := make([]byte, 0, 44)
	der = append(der, 0x30, 0x2a) // SEQUENCE de 42 bytes
	der = append(der, 0x30, 0x05) // SEQUENCE de 5 bytes
	der = append(der, 0x06, 0x03, 0x2b, 0x65, 0x70)
	der = append(der, 0x03, 0x21, 0x00) // BIT STRING de 33 bytes, 0 bits não usados
	der = append(der, publicKey...)
	return der, nil
}

// PublicKeyFingerprint devolve o SHA-256 hexadecimal do SubjectPublicKeyInfo
// DER da chave pública.
func PublicKeyFingerprint(publicKey ed25519.PublicKey) (string, error) {
	der, err := SPKI(publicKey)
	if err != nil {
		return "", err
	}
	return SHA256Hex(der), nil
}
