// Package decider porta o operador-decisor de src/core/decider/*.ts.
//
// As políticas falam só nas primitivas deste pacote; cada adaptador traduz para
// o seu provedor. O modelo escolhe entre opções fechadas: `noul` (sim/não com
// probabilidade), `choice` (uma opção de um conjunto) e `score` (nível de uma
// rubrica ordenada).
//
// A decisão vive na raiz do verificador, assinada com a chave Ed25519 do
// verificador. Qualquer desvio de resposta é indisponibilidade, nunca aprovação:
// o chamador segue o caminho humano.
package decider

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
)

// QuestionType é o tipo de pergunta respondida pelo modelo.
type QuestionType string

const (
	// QuestionNoul pede sim/não com probabilidade.
	QuestionNoul QuestionType = "noul"
	// QuestionChoice pede uma opção de um conjunto fechado.
	QuestionChoice QuestionType = "choice"
	// QuestionScore pede um nível de uma rubrica ordenada.
	QuestionScore QuestionType = "score"
)

// Text é o texto de uma pergunta ou de um critério: string, objeto ou lista.
type Text = any

// Question é uma pergunta feita ao modelo. Criteria depende do tipo: para
// `noul` é NoulCriteria, para `choice` é ChoiceCriteria e para `score` é uma
// lista de Text.
type Question struct {
	Type         QuestionType `json:"type"`
	Instructions Text         `json:"instructions"`
	Criteria     any          `json:"criteria,omitempty"`
}

// NoulCriteria declara o significado de cada lado da pergunta `noul`.
type NoulCriteria struct {
	True  Text `json:"true"`
	False Text `json:"false"`
}

// ChoiceCriteria mapeia cada opção ao seu significado. Um valor nulo significa
// opção sem descrição.
type ChoiceCriteria map[string]Text

// Answer é a resposta validada de uma pergunta.
type Answer struct {
	Type          QuestionType       `json:"type"`
	Noul          *float64           `json:"noul,omitempty"`
	Choice        string             `json:"choice,omitempty"`
	Probabilities map[string]float64 `json:"probabilities,omitempty"`
	Confidence    *float64           `json:"confidence,omitempty"`
	Score         *float64           `json:"score,omitempty"`
}

// Request é o estado e as perguntas de um ponto de decisão. O estado é montado
// pelo código; o adaptador o envia rotulado como dados, nunca como instrução.
type Request struct {
	State     map[string]any      `json:"state"`
	Questions map[string]Question `json:"questions"`
}

// Usage é o consumo informado pelo provedor.
type Usage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

// Response é a resposta validada do modelo.
type Response struct {
	// Model é o modelo exato que respondeu (ex.: `jev-1.13.0`), não o alias
	// pedido.
	Model   string            `json:"model"`
	Answers map[string]Answer `json:"answers"`
	Usage   *Usage            `json:"usage"`
}

// Connection é a conexão resolvida com o provedor: o adaptador recebe a chave,
// nunca o arquivo de configuração.
type Connection struct {
	Model    string
	Key      string
	Endpoint *string
}

// Adapter chama o provedor e devolve a resposta validada. Falha de rede,
// HTTP de erro ou resposta fora do contrato devolve UnavailableError.
type Adapter func(ctx context.Context, connection Connection, request Request) (Response, error)

// UnavailableError marca decisor indisponível ou resposta fora do contrato: a
// decisão volta para o humano.
type UnavailableError struct {
	Message string
}

// Error devolve a mensagem curta.
func (e *UnavailableError) Error() string { return e.Message }

// IsUnavailable informa se err é indisponibilidade do decisor.
func IsUnavailable(err error) bool {
	_, ok := err.(*UnavailableError)
	return ok
}

func unavailablef(format string, args ...any) error {
	return &UnavailableError{Message: fmt.Sprintf(format, args...)}
}

// ValidateResponse confere a resposta contra as perguntas feitas: uma resposta
// por pergunta, do mesmo tipo, com números no intervalo. Qualquer desvio é
// indisponibilidade, nunca aprovação.
func ValidateResponse(request Request, raw []byte) (Response, error) {
	var envelope struct {
		Model   json.RawMessage            `json:"model"`
		Answers map[string]json.RawMessage `json:"answers"`
		Usage   *struct {
			InputTokens  *float64 `json:"input_tokens"`
			OutputTokens *float64 `json:"output_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return Response{}, unavailablef("resposta do decisor não é um objeto JSON")
	}
	var model string
	if err := json.Unmarshal(envelope.Model, &model); err != nil || model == "" {
		return Response{}, unavailablef("resposta do decisor sem 'model'")
	}
	if envelope.Answers == nil {
		return Response{}, unavailablef("resposta do decisor sem 'answers'")
	}
	answers := make(map[string]Answer, len(request.Questions))
	for id, question := range request.Questions {
		body, present := envelope.Answers[id]
		if !present {
			return Response{}, unavailablef("resposta sem '%s' do tipo %s", id, question.Type)
		}
		answer, err := validateAnswer(id, question, body)
		if err != nil {
			return Response{}, err
		}
		answers[id] = answer
	}
	var usage *Usage
	if envelope.Usage != nil && envelope.Usage.InputTokens != nil && envelope.Usage.OutputTokens != nil {
		usage = &Usage{InputTokens: int(*envelope.Usage.InputTokens), OutputTokens: int(*envelope.Usage.OutputTokens)}
	}
	return Response{Model: model, Answers: answers, Usage: usage}, nil
}

func validateAnswer(id string, question Question, raw json.RawMessage) (Answer, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
		return Answer{}, unavailablef("resposta sem '%s' do tipo %s", id, question.Type)
	}
	var kind QuestionType
	if err := json.Unmarshal(fields["type"], &kind); err != nil || kind != question.Type {
		return Answer{}, unavailablef("resposta sem '%s' do tipo %s", id, question.Type)
	}
	switch question.Type {
	case QuestionNoul:
		value, ok := numberField(fields, "noul")
		if !ok || !isProbability(value) {
			return Answer{}, unavailablef("'%s': noul fora de [0,1]", id)
		}
		return Answer{Type: QuestionNoul, Noul: &value}, nil
	case QuestionChoice:
		options, err := choiceOptions(question)
		if err != nil {
			return Answer{}, err
		}
		var choice string
		if err := json.Unmarshal(fields["choice"], &choice); err != nil || !contains(options, choice) {
			return Answer{}, unavailablef("'%s': opção fora do conjunto (%s)", id, joinComma(options))
		}
		probabilities, confidence, err := distribution(fields)
		if err != nil {
			return Answer{}, unavailablef("'%s': probabilidades/confiança inválidas", id)
		}
		return Answer{Type: QuestionChoice, Choice: choice, Probabilities: probabilities, Confidence: &confidence}, nil
	case QuestionScore:
		scale, err := scoreScale(question)
		if err != nil {
			return Answer{}, err
		}
		value, ok := numberField(fields, "score")
		if !ok || value < 0 || value > float64(scale-1) {
			return Answer{}, unavailablef("'%s': score fora de [0,%d]", id, scale-1)
		}
		probabilities, confidence, err := distribution(fields)
		if err != nil {
			return Answer{}, unavailablef("'%s': probabilidades/confiança inválidas", id)
		}
		return Answer{Type: QuestionScore, Score: &value, Probabilities: probabilities, Confidence: &confidence}, nil
	default:
		return Answer{}, unavailablef("'%s': tipo de pergunta desconhecido (%s)", id, question.Type)
	}
}

func numberField(fields map[string]json.RawMessage, name string) (float64, bool) {
	value, present := fields[name]
	if !present {
		return 0, false
	}
	var number float64
	if err := json.Unmarshal(value, &number); err != nil {
		return 0, false
	}
	return number, true
}

func isProbability(value float64) bool {
	return value >= 0 && value <= 1
}

func distribution(fields map[string]json.RawMessage) (map[string]float64, float64, error) {
	probabilities := map[string]float64{}
	if value, present := fields["probabilities"]; present {
		if err := json.Unmarshal(value, &probabilities); err != nil {
			return nil, 0, err
		}
	} else {
		return nil, 0, fmt.Errorf("sem probabilidades")
	}
	for _, probability := range probabilities {
		if !isProbability(probability) {
			return nil, 0, fmt.Errorf("probabilidade fora de [0,1]")
		}
	}
	confidence, present := numberField(fields, "confidence")
	if !present || !isProbability(confidence) {
		return nil, 0, fmt.Errorf("confiança inválida")
	}
	return probabilities, confidence, nil
}

func choiceOptions(question Question) ([]string, error) {
	switch criteria := question.Criteria.(type) {
	case ChoiceCriteria:
		return sortedKeys(criteria), nil
	case map[string]any:
		options := make([]string, 0, len(criteria))
		for option := range criteria {
			options = append(options, option)
		}
		sort.Strings(options)
		return options, nil
	default:
		return nil, unavailablef("pergunta de escolha sem critérios")
	}
}

func scoreScale(question Question) (int, error) {
	switch criteria := question.Criteria.(type) {
	case []any:
		return len(criteria), nil
	case []string:
		return len(criteria), nil
	default:
		return 0, unavailablef("pergunta de score sem rubrica")
	}
}

func sortedKeys(criteria ChoiceCriteria) []string {
	options := make([]string, 0, len(criteria))
	for option := range criteria {
		options = append(options, option)
	}
	sort.Strings(options)
	return options
}

func contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func joinComma(values []string) string {
	result := ""
	for index, value := range values {
		if index > 0 {
			result += ", "
		}
		result += value
	}
	return result
}
