package decider

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/passoz/pwn/internal/harness/contract"
	"github.com/passoz/pwn/internal/platform/cryptox"
	"github.com/passoz/pwn/internal/platform/gitx"
	"github.com/passoz/pwn/internal/platform/jsonx"
)

// Quem decide cada ponto do operador.
//
// - Sem configuração do decisor no projeto (ou `enabled: false`): comportamento
//   padrão, o humano decide e nenhum modelo é chamado.
// - Configuração habilitada: o decisor decide por padrão, dentro do escopo e do
//   teto de risco.
// - `--operator human` (ou `PWN_OPERATOR=human`) devolve a decisão ao humano
//   numa execução.
// - Falha fechada: decisor indisponível ou incerto devolve a decisão ao humano.

// OperatorEnv é a variável que pede o operador desta execução.
const OperatorEnv = "PWN_OPERATOR"

// OperatorMode é o operador pedido para a execução.
type OperatorMode string

const (
	// OperatorHuman devolve as decisões ao humano nesta execução.
	OperatorHuman OperatorMode = "human"
	// OperatorDecider exige que o decisor governa os pontos.
	OperatorDecider OperatorMode = "decider"
)

// Adapters são os adaptadores disponíveis, por provedor.
var Adapters = map[string]Adapter{"jev": JevAdapter}

// OperatorModeFromEnv devolve o modo pedido para esta execução. Present=false
// significa padrão do projeto e nenhuma variável definida.
func OperatorModeFromEnv() (mode OperatorMode, present bool, err error) {
	raw := strings.TrimSpace(os.Getenv(OperatorEnv))
	if raw == "" {
		return "", false, nil
	}
	switch OperatorMode(raw) {
	case OperatorHuman:
		return OperatorHuman, true, nil
	case OperatorDecider:
		return OperatorDecider, true, nil
	}
	return "", true, fmt.Errorf("%s inválido: '%s' (use human ou decider)", OperatorEnv, raw)
}

// ProjectRoot devolve a raiz Git do projeto: a configuração vale de qualquer
// subdiretório. Sem repositório Git devolve rootDir.
func ProjectRoot(rootDir string) string {
	runner := gitx.New(rootDir)
	result, err := runner.Run(context.Background(), []string{"rev-parse", "--show-toplevel"}, gitx.Options{})
	if err != nil || !result.OK() {
		return rootDir
	}
	if top := strings.TrimSpace(string(result.Stdout)); top != "" {
		return top
	}
	return rootDir
}

// Governance é a resposta de Govern.
type Governance struct {
	// Config é a configuração habilitada que governa o ponto; nil quando o
	// humano decide.
	Config *Config
	// Reason é nil no comportamento padrão silencioso; texto explica ao
	// operador por que o decisor não governa o ponto.
	Reason *string
}

// Govern responde se o decisor governa este ponto. `reason` nil é comportamento
// padrão silencioso (sem decisor configurado ou humano pedido).
func Govern(rootDir string, point DecisionPoint, risk *contract.RiskLevel, root string) (Governance, error) {
	mode, present, err := OperatorModeFromEnv()
	if err != nil {
		return Governance{}, err
	}
	if present && mode == OperatorHuman {
		return Governance{}, nil
	}
	resolved, err := resolveRoot(root)
	if err != nil {
		return Governance{}, err
	}
	identity := ProjectRoot(rootDir)
	config, err := ReadConfig(identity, resolved)
	if err != nil {
		return Governance{}, err
	}
	if config == nil || !config.Enabled {
		if present && mode == OperatorDecider {
			return Governance{}, fmt.Errorf("--operator decider pedido, mas este projeto não tem decisor configurado (pwn decider set --decider <provedor:modelo>)")
		}
		return Governance{}, nil
	}
	if !containsPoint(config.Scope, point) {
		reason := fmt.Sprintf("ponto '%s' fora do escopo do decisor", point)
		return Governance{Reason: &reason}, nil
	}
	if risk != nil && risk.Rank() > config.MaxRisk.Rank() {
		reason := fmt.Sprintf("risco %s acima do teto do decisor (%s): decisão do operador", *risk, config.MaxRisk)
		return Governance{Reason: &reason}, nil
	}
	return Governance{Config: config}, nil
}

func containsPoint(points []DecisionPoint, point DecisionPoint) bool {
	for _, candidate := range points {
		if candidate == point {
			return true
		}
	}
	return false
}

// Judgment é o que a política conclui das respostas; função pura, testável sem
// rede.
type Judgment struct {
	Outcome Outcome  `json:"outcome"`
	Action  *string  `json:"action"`
	Reasons []string `json:"reasons"`
}

// Policy governa um ponto de decisão. Judge é puro.
type Policy struct {
	Point      DecisionPoint
	Thresholds map[string]any
	Judge      func(answers map[string]Answer) Judgment
}

// ResultKind indica se o chamador segue o caminho humano ou tem um registro.
type ResultKind string

const (
	// ResultHuman indica que o decisor não governa o ponto.
	ResultHuman ResultKind = "human"
	// ResultDecided indica que há registro assinado.
	ResultDecided ResultKind = "decided"
)

// DecisionResult é o resultado de Decide.
type DecisionResult struct {
	Kind   ResultKind
	Reason *string
	Record *DecisionRecord
}

// DecideOptions são as entradas de Decide.
type DecideOptions struct {
	Context      context.Context
	RootDir      string
	WorkID       string
	TaskID       string
	Risk         *contract.RiskLevel
	Policy       Policy
	Request      func() (Request, error)
	VerifierRoot string
}

func connect(config *Config) (Adapter, Connection, error) {
	provider, model, _ := strings.Cut(config.Decider, ":")
	adapter, ok := Adapters[provider]
	if !ok {
		return nil, Connection{}, fmt.Errorf("provedor sem adaptador: %s", config.Decider)
	}
	key := strings.TrimSpace(os.Getenv(config.KeyEnv))
	if key == "" {
		return nil, Connection{}, fmt.Errorf("$%s não está definida", config.KeyEnv)
	}
	return adapter, Connection{Model: model, Key: key, Endpoint: config.Endpoint}, nil
}

// Decide executa um ponto de decisão. Devolve ResultHuman quando o decisor não
// governa o ponto, ou o registro assinado. Indisponibilidade vira registro
// `escalate`: o chamador segue o caminho humano e mostra os motivos.
func Decide(options DecideOptions) (DecisionResult, error) {
	resolved, err := resolveRoot(options.VerifierRoot)
	if err != nil {
		return DecisionResult{}, err
	}
	governed, err := Govern(options.RootDir, options.Policy.Point, options.Risk, resolved)
	if err != nil {
		return DecisionResult{}, err
	}
	if governed.Config == nil {
		return DecisionResult{Kind: ResultHuman, Reason: governed.Reason}, nil
	}
	config := governed.Config
	identity, err := ProjectIdentity(ProjectRoot(options.RootDir))
	if err != nil {
		return DecisionResult{}, err
	}
	base := DecisionContent{
		Point:      options.Policy.Point,
		Project:    identity,
		WorkID:     options.WorkID,
		TaskID:     options.TaskID,
		Decider:    config.Decider,
		Thresholds: options.Policy.Thresholds,
	}
	escalate := func(reason string, request *Request) (DecisionResult, error) {
		content := base
		content.Outcome = OutcomeEscalate
		content.Reasons = []string{"decisor indisponível: " + reason}
		if request != nil {
			digest, err := stateDigest(*request)
			if err != nil {
				return DecisionResult{}, err
			}
			content.StateSHA = &digest
			content.Questions = request.Questions
		}
		record, err := RecordDecision(content, options.RootDir, resolved)
		if err != nil {
			return DecisionResult{}, err
		}
		return DecisionResult{Kind: ResultDecided, Record: &record}, nil
	}

	adapter, connection, err := connect(config)
	if err != nil {
		return escalate(err.Error(), nil)
	}
	request, err := options.Request()
	if err != nil {
		return DecisionResult{}, err
	}
	ctx := options.Context
	if ctx == nil {
		ctx = context.Background()
	}
	response, err := adapter(ctx, connection, request)
	if err != nil {
		var unavailable *UnavailableError
		if errors.As(err, &unavailable) {
			return escalate(unavailable.Message, &request)
		}
		return DecisionResult{}, err
	}
	judgment := options.Policy.Judge(response.Answers)
	digest, err := stateDigest(request)
	if err != nil {
		return DecisionResult{}, err
	}
	model := response.Model
	content := base
	content.Model = &model
	content.StateSHA = &digest
	content.Questions = request.Questions
	content.Answers = response.Answers
	content.Usage = response.Usage
	content.Outcome = judgment.Outcome
	content.Action = judgment.Action
	content.Reasons = judgment.Reasons
	record, err := RecordDecision(content, options.RootDir, resolved)
	if err != nil {
		return DecisionResult{}, err
	}
	return DecisionResult{Kind: ResultDecided, Record: &record}, nil
}

func stateDigest(request Request) (string, error) {
	canonical, err := jsonx.Canonical(request.State)
	if err != nil {
		return "", fmt.Errorf("decider: serializar o estado: %w", err)
	}
	return cryptox.SHA256Hex(canonical), nil
}

// RuleDecisionOptions são as entradas de RecordRuleDecision.
type RuleDecisionOptions struct {
	RootDir string
	WorkID  string
	TaskID  string
	Point   DecisionPoint
	Action  string
	Reasons []string
}

// RecordRuleDecision grava uma decisão por regra (sem modelo), assinada como as
// demais.
func RecordRuleDecision(options RuleDecisionOptions, root string) (DecisionRecord, error) {
	identity, err := ProjectIdentity(ProjectRoot(options.RootDir))
	if err != nil {
		return DecisionRecord{}, err
	}
	action := options.Action
	return RecordDecision(DecisionContent{
		Point:      options.Point,
		Project:    identity,
		WorkID:     options.WorkID,
		TaskID:     options.TaskID,
		Decider:    "rule",
		Thresholds: map[string]any{},
		Outcome:    OutcomeApprove,
		Action:     &action,
		Reasons:    options.Reasons,
	}, options.RootDir, root)
}

// DecisionReference devolve a referência citada nos artefatos que o decisor
// autoriza (ex.: `approved_by`).
func DecisionReference(record DecisionRecord) string {
	name := record.Decider
	if record.Model != nil {
		name = *record.Model
	}
	return "decider:" + name + "#" + record.DecisionID
}

// DescribeDecision devolve as linhas para o operador: o que foi decidido, por
// quem e por quê.
func DescribeDecision(record DecisionRecord) []string {
	labels := map[Outcome]string{OutcomeApprove: "APROVADO", OutcomeReject: "REJEITADO", OutcomeEscalate: "PARA O OPERADOR"}
	label := labels[record.Outcome]
	if label == "" {
		label = string(record.Outcome)
	}
	action := ""
	if record.Action != nil {
		action = " (" + *record.Action + ")"
	}
	name := record.Decider
	if record.Model != nil {
		name = *record.Model
	}
	lines := []string{fmt.Sprintf("[DECISOR] %s%s — %s, registro %s", label, action, name, record.DecisionID)}
	for _, reason := range record.Reasons {
		lines = append(lines, "  · "+reason)
	}
	return lines
}
