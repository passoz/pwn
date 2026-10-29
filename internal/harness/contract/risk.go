package contract

import (
	"strings"
	"unicode"
)

// RiskAcceptance é um critério de aceite reduzido ao texto usado na
// classificação de risco.
type RiskAcceptance struct {
	Command     string
	Description string
}

// RiskSignals são as declarações da task que alimentam DeriveTaskRisk.
type RiskSignals struct {
	Title          string
	Behavior       string
	Components     []string
	Files          []string
	RedCommand     string
	RedDescription string
	Acceptance     []RiskAcceptance
}

// RISK_L3_KEYWORDS é a lista explícita de superfícies sensíveis.
var riskL3Keywords = []string{
	"auth", "autentica", "login", "signin", "signup", "password", "senha", "credencial",
	"sessao", "session", "token", "cookie", "rbac", "permissao", "autorizacao", "papel",
	"seguranca", "security", "hardening", "webhook", "hmac", "assinatura", "signature",
	"pagamento", "payment", "estorno", "refund", "crypto", "secret", "csrf", "cors",
	"rate limit", "rate-limit", "privacidade", "privacy", "lgpd", "middleware", "bcrypt",
	"argon2", "hash", "csrf", "oauth",
}

// riskL1Keywords é a lista de mudanças sem comportamento observável.
var riskL1Keywords = []string{
	"readme", "documentacao", "documentation", "comentario", "formatacao", "estilo",
	"tipografia", "copy", "changelog", "licenca", "license",
}

// DeriveTaskRisk classifica o risco a partir das declarações da própria task.
//
// A ordem é a da referência: L3 quando qualquer palavra sensível aparece; L1
// quando só aparece vocabulário de documentação; L2 nos demais casos. L4 nunca é
// atribuído por heurística.
func DeriveTaskRisk(signals RiskSignals) RiskLevel {
	parts := []string{
		signals.Title,
		signals.Behavior,
		strings.Join(signals.Components, " "),
		strings.Join(signals.Files, " "),
		signals.RedCommand,
		signals.RedDescription,
	}
	for _, acceptance := range signals.Acceptance {
		parts = append(parts, acceptance.Command, acceptance.Description)
	}
	text := normalizeText(strings.Join(parts, " "))

	for _, keyword := range riskL3Keywords {
		if strings.Contains(text, keyword) {
			return RiskL3
		}
	}
	for _, keyword := range riskL1Keywords {
		if strings.Contains(text, keyword) {
			return RiskL1
		}
	}
	return RiskL2
}

// normalizeText replica `value.normalize('NFD').replace(/[\u0300-\u036f]/g, ”).toLowerCase()`.
//
// A biblioteca padrão não tem normalização Unicode. O mapa cobre as letras
// latinas que o NFD decompõe em letra base mais marca combinante, que é o caso
// do português e do inglês técnico. Letras sem decomposição canônica (ø, ł, ß,
// æ) permanecem, como no TypeScript.
func normalizeText(value string) string {
	var builder strings.Builder
	builder.Grow(len(value))
	for _, char := range value {
		if char >= 0x0300 && char <= 0x036F {
			continue
		}
		lower := unicode.ToLower(char)
		if base, ok := accentFold[lower]; ok {
			builder.WriteString(base)
			continue
		}
		builder.WriteRune(lower)
	}
	return builder.String()
}

var accentFold = map[rune]string{
	'á': "a", 'à': "a", 'â': "a", 'ã': "a", 'ä': "a", 'å': "a",
	'ā': "a", 'ă': "a", 'ą': "a",
	'ç': "c", 'ć': "c", 'ĉ': "c", 'ċ': "c", 'č': "c",
	'ď': "d",
	'è': "e", 'é': "e", 'ê': "e", 'ë': "e", 'ē': "e", 'ĕ': "e",
	'ė': "e", 'ę': "e", 'ě': "e",
	'ĝ': "g", 'ğ': "g", 'ġ': "g", 'ģ': "g",
	'ĥ': "h",
	'ì': "i", 'í': "i", 'î': "i", 'ï': "i", 'ĩ': "i", 'ī': "i",
	'ĭ': "i", 'į': "i", 'ı': "i",
	'ĵ': "j",
	'ķ': "k",
	'ĺ': "l", 'ļ': "l", 'ľ': "l",
	'ñ': "n", 'ń': "n", 'ņ': "n", 'ň': "n",
	'ò': "o", 'ó': "o", 'ô': "o", 'õ': "o", 'ö': "o", 'ō': "o",
	'ŏ': "o", 'ő': "o",
	'ŕ': "r", 'ŗ': "r", 'ř': "r",
	'ś': "s", 'ŝ': "s", 'ş': "s", 'š': "s",
	'ť': "t", 'ţ': "t",
	'ù': "u", 'ú': "u", 'û': "u", 'ü': "u", 'ũ': "u", 'ū': "u",
	'ŭ': "u", 'ů': "u", 'ű': "u", 'ų': "u",
	'ŵ': "w",
	'ý': "y", 'ÿ': "y", 'ŷ': "y",
	'ź': "z", 'ż': "z", 'ž': "z",
}
