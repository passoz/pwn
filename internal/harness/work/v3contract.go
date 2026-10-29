package work

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/passoz/pwn/internal/harness/contract"
	"github.com/passoz/pwn/internal/harness/plan"
)

// gateCommands extrai os comandos entre crases dos gates globais.
func gateCommands(planValue plan.Plan) []string {
	commands := make([]string, 0)
	for _, gate := range planValue.GlobalGates {
		for _, command := range inlineCode(gate) {
			if command != "" {
				commands = append(commands, command)
			}
		}
	}
	return commands
}

// DeriveContract deriva o contrato V4 congelado de uma task importada.
// Cada comando e caminho sai das declarações RED/AC/Files da própria task, mais
// os gates globais do plano.
func DeriveContract(planValue plan.Plan, task plan.PlanTask, workID string, risk contract.RiskLevel) (contract.TaskContractV4, error) {
	writeAllow := unique(append(append(append([]string{}, task.ImplementationFiles...), task.TestFiles...), task.Files...))
	commands := unique(append(append([]string{}, planCommands(task)...), gateCommands(planValue)...))

	scenarios := make([]contract.Scenario, 0, len(task.AcceptanceCriteria))
	for index, entry := range task.AcceptanceCriteria {
		behavior := task.Behavior
		if behavior == "" {
			behavior = task.Title
		}
		description := entry.Description
		if description == "" {
			description = "a aceitação é satisfeita"
		}
		scenarios = append(scenarios, contract.Scenario{
			ID:    fmt.Sprintf("SCENARIO-%s-%02d", task.ID, index+1),
			Given: "Dado o comportamento declarado: " + behavior,
			When:  "Quando `" + entry.Command + "` é executado",
			Then:  "Então " + description,
		})
	}

	scopeAllow := writeAllow
	if len(scopeAllow) == 0 {
		scopeAllow = []string{"src/**", "tests/**"}
	}
	options := &contract.DefaultOptions{WriteAllow: scopeAllow}
	if len(scenarios) > 0 {
		options.Scenarios = scenarios
	}
	derived, err := contract.CreateDefaultContractV4(task.ID, workID, task.Title, risk, options)
	if err != nil {
		return contract.TaskContractV4{}, err
	}
	derived.ValidationStrategy = contract.StrategyTDDStrict
	if len(commands) > 0 {
		derived.AcceptanceContract.Commands = commands
	} else {
		derived.AcceptanceContract.Commands = []string{"bun test"}
	}
	derived.ChangeContract.TargetFiles = writeAllow
	components := task.Components
	if len(components) == 0 {
		components = []string{"jachegai-bun"}
	}
	derived.ChangeContract.AffectedComponents = components
	derived.BehavioralContract.Scenarios = scenarios
	if len(task.Files) > 0 {
		derived.ScopeContract.OutOfScope = []string{"Arquivos fora de: " + strings.Join(writeAllow, ", ")}
	}
	return derived, nil
}

// planCommands devolve os comandos das ACs da task.
func planCommands(task plan.PlanTask) []string {
	commands := make([]string, 0, len(task.AcceptanceCriteria))
	for _, entry := range task.AcceptanceCriteria {
		if entry.Command != "" {
			commands = append(commands, entry.Command)
		}
	}
	return commands
}

// tokens divide o texto em tokens normalizados, sem acento e no singular
// quando o plural tem mais de quatro letras.
func tokens(value string) []string {
	normalized := normalizeText(value)
	raw := strings.FieldsFunc(normalized, func(character rune) bool {
		return !(character >= 'a' && character <= 'z') && !(character >= '0' && character <= '9')
	})
	result := make([]string, 0, len(raw))
	for _, token := range raw {
		if len(token) > 4 && strings.HasSuffix(token, "s") {
			token = strings.TrimSuffix(token, "s")
		}
		if len(token) > 3 {
			result = append(result, token)
		}
	}
	return result
}

// capabilityAlias é um conjunto explícito e revisável de palavras por
// capacidade. O vocabulário em português e inglês é mapeado nos nomes em inglês
// da system spec; o que não está aqui cai na sobreposição simples de tokens.
type capabilityAlias struct {
	capability *regexp.Regexp
	words      []string
}

var capabilityAliases = []capabilityAlias{
	{regexp.MustCompile(`(?i)identity|access`), []string{"auth", "autenticacao", "authentication", "login", "logout", "session", "sessao", "signin", "signup", "cadastro", "registro", "rbac", "role", "papel", "credential", "credencial", "senha", "password", "cookie", "principal", "better"}},
	{regexp.MustCompile(`(?i)public experience`), []string{"publico", "public", "visitor", "visitante", "landing", "discovery", "descoberta"}},
	{regexp.MustCompile(`(?i)customer`), []string{"cliente", "customer", "profile", "perfil", "address", "endereco", "favorito", "favorite", "privacidade", "privacy", "lgpd", "titular", "exportacao", "export"}},
	{regexp.MustCompile(`(?i)seller`), []string{"lojista", "seller", "store", "loja", "vendedor"}},
	{regexp.MustCompile(`(?i)catalog`), []string{"catalogo", "catalog", "produto", "product"}},
	{regexp.MustCompile(`(?i)inventory`), []string{"estoque", "inventory", "inventario", "stock"}},
	{regexp.MustCompile(`(?i)cart|checkout`), []string{"carrinho", "cart", "checkout", "cesta", "basket"}},
	{regexp.MustCompile(`(?i)order`), []string{"pedido", "order", "status", "entrega", "lifecycle", "ciclo"}},
	{regexp.MustCompile(`(?i)courier|delivery`), []string{"entregador", "courier", "delivery", "entrega", "motoboy", "coleta", "pickup"}},
	{regexp.MustCompile(`(?i)payment`), []string{"pagamento", "payment", "cobranca", "transacao"}},
	{regexp.MustCompile(`(?i)fee|invoice`), []string{"taxa", "fee", "fatura", "invoice", "comissao"}},
	{regexp.MustCompile(`(?i)support`), []string{"suporte", "support", "ticket", "chamado", "disputa"}},
	{regexp.MustCompile(`(?i)administration`), []string{"admin", "administrador", "administracao", "moderacao", "moderation"}},
	{regexp.MustCompile(`(?i)audit`), []string{"auditoria", "audit", "historico", "history", "append"}},
	{regexp.MustCompile(`(?i)notification`), []string{"notificacao", "notification", "email", "push", "aviso"}},
	{regexp.MustCompile(`(?i)background work`), []string{"job", "worker", "fila", "queue", "background", "assincrono", "async"}},
	{regexp.MustCompile(`(?i)file storage`), []string{"arquivo", "file", "upload", "storage", "imagem", "image"}},
	{regexp.MustCompile(`(?i)observability`), []string{"observabilidade", "observability", "health", "healthz", "readyz", "metrica", "metrics", "log"}},
}

// capabilityHaystack é o texto usado para casar a task com o mapa: título,
// comportamento, arquivos e — principalmente — RED + ACs, onde o resultado
// observável (por exemplo `/healthz`) costuma viver.
func capabilityHaystack(task plan.PlanTask) string {
	parts := []string{
		task.Title,
		task.Behavior,
		strings.Join(task.Components, " "),
		strings.Join(task.Files, " "),
		task.Red.Command,
		task.Red.Description,
	}
	for _, entry := range task.AcceptanceCriteria {
		parts = append(parts, entry.Command, entry.Description)
	}
	return strings.Join(parts, " ")
}

// normalizeText remove acentos e converte para minúsculas.
func normalizeText(value string) string {
	var builder strings.Builder
	for _, character := range value {
		mapped := stripDiacritic(character)
		if mapped == 0 {
			continue
		}
		builder.WriteRune(mapped)
	}
	return strings.ToLower(builder.String())
}

// riskL3Keywords são superfícies sensíveis: autenticação, sessões,
// credenciais, pagamentos, webhooks, CORS/CSRF/rate limit, privacidade/LGPD e
// middleware de autorização.
var riskL3Keywords = []string{
	"auth", "autentica", "login", "signin", "signup", "password", "senha", "credencial",
	"sessao", "session", "token", "cookie", "rbac", "permissao", "autorizacao", "papel",
	"seguranca", "security", "hardening", "webhook", "hmac", "assinatura", "signature",
	"pagamento", "payment", "estorno", "refund", "crypto", "secret", "csrf", "cors",
	"rate limit", "rate-limit", "privacidade", "privacy", "lgpd", "middleware", "bcrypt",
	"argon2", "hash", "oauth",
}

// riskL1Keywords são mudanças de documentação/formatação.
var riskL1Keywords = []string{
	"readme", "documentacao", "documentation", "comentario", "formatacao", "estilo",
	"tipografia", "copy", "changelog", "licenca", "license",
}

// DeriveTaskRisk classifica o risco de uma task importada a partir das próprias
// declarações.
//
// L3 cobre superfícies sensíveis; L1 cobre documentação; o resto é L2. L4 nunca
// é automático: suspender para revisão humana é decisão do operador.
func DeriveTaskRisk(task plan.PlanTask) contract.RiskLevel {
	text := normalizeText(capabilityHaystack(task))
	for _, keyword := range riskL3Keywords {
		if strings.Contains(text, keyword) {
			return contract.RiskL3
		}
	}
	for _, keyword := range riskL1Keywords {
		if strings.Contains(text, keyword) {
			return contract.RiskL1
		}
	}
	return contract.RiskL2
}

// MapTaskToCapability mapeia a task para uma capability do mapa.
func MapTaskToCapability(task plan.PlanTask, capabilityMap CapabilityMap) (string, int) {
	haystack := tokens(capabilityHaystack(task))
	bestID := "CAP-001"
	if len(capabilityMap.Capabilities) > 0 {
		bestID = capabilityMap.Capabilities[0].ID
	}
	bestScore := 0
	for _, capability := range capabilityMap.Capabilities {
		needles := tokens(capability.Name)
		score := 0
		for _, needle := range needles {
			for _, token := range haystack {
				if token == needle {
					score++
					break
				}
			}
		}
		for _, alias := range capabilityAliases {
			if !alias.capability.MatchString(capability.Name) {
				continue
			}
			for _, word := range alias.words {
				for _, token := range haystack {
					if token == word {
						score += 2
						break
					}
				}
			}
			break
		}
		if score > bestScore {
			bestID = capability.ID
			bestScore = score
		}
	}
	return bestID, bestScore
}

// RiskCandidate descreve uma task para o decisor de risco.
type RiskCandidate struct {
	Task          string             `json:"task"`
	Title         string             `json:"title"`
	Description   string             `json:"description"`
	Files         []string           `json:"files"`
	Deterministic contract.RiskLevel `json:"deterministic"`
}

// RiskRaise é uma elevação de risco decidida pelo decisor.
type RiskRaise struct {
	Task       string             `json:"task"`
	From       contract.RiskLevel `json:"from"`
	To         contract.RiskLevel `json:"to"`
	Confidence float64            `json:"confidence"`
	DecisionID string             `json:"decision_id"`
}

// RiskDecision é a resposta do decisor.
type RiskDecision struct {
	Raises  []RiskRaise `json:"raises"`
	Reasons []string    `json:"reasons"`
}

// RiskDecider decide elevar o risco determinístico de uma task.
//
// A interface é deliberadamente pequena: o pacote não importa
// `internal/harness/decider`. A raiz de composição liga o decisor real.
// Um decisor nunca rebaixa o risco; elevações acima de L3 são recusadas, porque
// L4 suspende a execução para revisão humana.
type RiskDecider interface {
	RaiseRisk(ctx context.Context, workID string, candidates []RiskCandidate) (RiskDecision, error)
}

// applyRiskDecider aplica as elevações decididas, com no máximo L3.
func applyRiskDecider(ctx context.Context, decider RiskDecider, workID string, tasks []plan.PlanTask, mapping []RiskMappingEntry, warnings *[]string) error {
	if decider == nil {
		return nil
	}
	candidates := make([]RiskCandidate, 0, len(tasks))
	for _, task := range tasks {
		deterministic := contract.RiskL2
		for _, entry := range mapping {
			if entry.Task == task.ID {
				deterministic = entry.Risk
				break
			}
		}
		candidates = append(candidates, RiskCandidate{
			Task:          task.ID,
			Title:         task.Title,
			Description:   task.Behavior,
			Files:         nonNil(task.Files),
			Deterministic: deterministic,
		})
	}
	decision, err := decider.RaiseRisk(ctx, workID, candidates)
	if err != nil {
		*warnings = append(*warnings, "--risk auto: "+err.Error()+"; risco heurístico mantido.")
		return nil
	}
	if len(decision.Raises) == 0 {
		reasons := "sem elevação"
		if len(decision.Reasons) > 0 {
			reasons = strings.Join(decision.Reasons, "; ")
		}
		*warnings = append(*warnings, "--risk auto: "+reasons+"; risco heurístico mantido.")
		return nil
	}
	for _, raise := range decision.Raises {
		target := -1
		for index := range mapping {
			if mapping[index].Task == raise.Task {
				target = index
				break
			}
		}
		if target == -1 {
			*warnings = append(*warnings, fmt.Sprintf(
				"--risk auto: o decisor citou a task %s, que não existe no plano; elevação ignorada.", raise.Task))
			continue
		}
		if raise.To != contract.RiskL2 && raise.To != contract.RiskL3 {
			*warnings = append(*warnings, fmt.Sprintf(
				"Task %s: risco %s do decisor recusado (só L2/L3 são automáticos; L4 exige decisão humana).", raise.Task, raise.To))
			continue
		}
		if riskRank(raise.To) <= riskRank(mapping[target].Risk) {
			*warnings = append(*warnings, fmt.Sprintf(
				"Task %s: risco %s do decisor ignorado (o decisor nunca rebaixa nem mantém; atual %s).",
				raise.Task, raise.To, mapping[target].Risk))
			continue
		}
		previous := mapping[target].Risk
		mapping[target].Risk = raise.To
		*warnings = append(*warnings, fmt.Sprintf(
			"Task %s: risco elevado pelo decisor de %s para %s (confiança %.2f, registro %s).",
			raise.Task, previous, raise.To, raise.Confidence, raise.DecisionID))
	}
	return nil
}

// riskRank ordena os níveis de risco. Nível inválido devolve -1.
func riskRank(level contract.RiskLevel) int {
	return level.Rank()
}
