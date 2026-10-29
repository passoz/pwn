package decider

import (
	"strings"
	"testing"
)

func TestValidateResponse(t *testing.T) {
	request := Request{
		State: map[string]any{},
		Questions: map[string]Question{
			"a": {Type: QuestionNoul, Instructions: "x"},
			"b": {Type: QuestionScore, Instructions: "y", Criteria: []string{"0", "1"}},
			"c": {Type: QuestionChoice, Instructions: "z", Criteria: ChoiceCriteria{"adequate": "ok", "too_broad": "não"}},
		},
	}
	valid := `{"model":"m","answers":{
		"a":{"type":"noul","noul":0.5},
		"b":{"type":"score","score":1,"probabilities":{"1":1},"confidence":1},
		"c":{"type":"choice","choice":"adequate","probabilities":{"adequate":0.8},"confidence":0.8}
	},"usage":{"input_tokens":3,"output_tokens":2}}`

	tests := []struct {
		name    string
		body    string
		wantErr string
	}{
		{name: "válida", body: valid},
		{name: "não é objeto", body: `[]`, wantErr: "não é um objeto JSON"},
		{name: "JSON quebrado", body: `{`, wantErr: "não é um objeto JSON"},
		{name: "sem model", body: `{"answers":{}}`, wantErr: "sem 'model'"},
		{name: "model vazio", body: `{"model":"","answers":{}}`, wantErr: "sem 'model'"},
		{name: "sem answers", body: `{"model":"m"}`, wantErr: "sem 'answers'"},
		{name: "resposta ausente", body: `{"model":"m","answers":{"a":{"type":"noul","noul":0.5},"b":{"type":"score","score":1,"probabilities":{},"confidence":1}}}`, wantErr: "resposta sem 'c'"},
		{name: "tipo trocado", body: `{"model":"m","answers":{"a":{"type":"score","score":1,"probabilities":{},"confidence":1},"b":{"type":"score","score":1,"probabilities":{},"confidence":1},"c":{"type":"choice","choice":"adequate","probabilities":{},"confidence":1}}}`, wantErr: "'a' do tipo noul"},
		{name: "noul fora do intervalo", body: `{"model":"m","answers":{"a":{"type":"noul","noul":1.5},"b":{"type":"score","score":1,"probabilities":{},"confidence":1},"c":{"type":"choice","choice":"adequate","probabilities":{},"confidence":1}}}`, wantErr: "noul fora de [0,1]"},
		{name: "escolha fora do conjunto", body: `{"model":"m","answers":{"a":{"type":"noul","noul":0.5},"b":{"type":"score","score":1,"probabilities":{},"confidence":1},"c":{"type":"choice","choice":"maybe","probabilities":{},"confidence":1}}}`, wantErr: "opção fora do conjunto"},
		{name: "score acima da rubrica", body: `{"model":"m","answers":{"a":{"type":"noul","noul":0.5},"b":{"type":"score","score":2,"probabilities":{},"confidence":1},"c":{"type":"choice","choice":"adequate","probabilities":{},"confidence":1}}}`, wantErr: "score fora de [0,1]"},
		{name: "confiança inválida", body: `{"model":"m","answers":{"a":{"type":"noul","noul":0.5},"b":{"type":"score","score":1,"probabilities":{},"confidence":1},"c":{"type":"choice","choice":"adequate","probabilities":{},"confidence":1.2}}}`, wantErr: "confiança inválidas"},
		{name: "probabilidade inválida", body: `{"model":"m","answers":{"a":{"type":"noul","noul":0.5},"b":{"type":"score","score":1,"probabilities":{"1":-1},"confidence":1},"c":{"type":"choice","choice":"adequate","probabilities":{},"confidence":1}}}`, wantErr: "probabilidades/confiança inválidas"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response, err := ValidateResponse(request, []byte(test.body))
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("erro = %v, quer %q", err, test.wantErr)
				}
				if !IsUnavailable(err) {
					t.Fatalf("erro não é indisponibilidade: %T", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ValidateResponse: %v", err)
			}
			if response.Model != "m" || response.Usage == nil || response.Usage.InputTokens != 3 {
				t.Fatalf("response = %+v", response)
			}
			if response.Answers["a"].Noul == nil || *response.Answers["a"].Noul != 0.5 {
				t.Fatalf("answer a = %+v", response.Answers["a"])
			}
		})
	}
}

func TestValidateResponseOmitsMissingUsage(t *testing.T) {
	request := Request{Questions: map[string]Question{"a": {Type: QuestionNoul}}}
	response, err := ValidateResponse(request, []byte(`{"model":"m","answers":{"a":{"type":"noul","noul":1}},"usage":{"input_tokens":1}}`))
	if err != nil {
		t.Fatalf("ValidateResponse: %v", err)
	}
	if response.Usage != nil {
		t.Fatalf("usage parcial deveria ser nulo: %+v", response.Usage)
	}
}
