package decider

import (
	"strings"
	"testing"
)

func TestValidateResponseCriteriaShapesAndMalformedAnswers(t *testing.T) {
	envelope := func(answer string) []byte {
		return []byte(`{"model":"m","answers":{"q":` + answer + `}}`)
	}
	dist := `"probabilities":{"x":0.5},"confidence":0.5`
	tests := []struct {
		name     string
		question Question
		body     string
		wantErr  string
	}{
		{
			name:     "resposta não é objeto",
			question: Question{Type: QuestionNoul},
			body:     `5`,
			wantErr:  "resposta sem 'q' do tipo noul",
		},
		{
			name:     "resposta nula",
			question: Question{Type: QuestionNoul},
			body:     `null`,
			wantErr:  "resposta sem 'q' do tipo noul",
		},
		{
			name:     "campo type ausente",
			question: Question{Type: QuestionNoul},
			body:     `{"noul":0.5}`,
			wantErr:  "resposta sem 'q' do tipo noul",
		},
		{
			name:     "noul ausente",
			question: Question{Type: QuestionNoul},
			body:     `{"type":"noul"}`,
			wantErr:  "noul fora de [0,1]",
		},
		{
			name:     "noul não numérico",
			question: Question{Type: QuestionNoul},
			body:     `{"type":"noul","noul":"alto"}`,
			wantErr:  "noul fora de [0,1]",
		},
		{
			name:     "noul negativo",
			question: Question{Type: QuestionNoul},
			body:     `{"type":"noul","noul":-0.1}`,
			wantErr:  "noul fora de [0,1]",
		},
		{
			name:     "tipo de pergunta desconhecido",
			question: Question{Type: QuestionType("ranking")},
			body:     `{"type":"ranking"}`,
			wantErr:  "tipo de pergunta desconhecido (ranking)",
		},
		{
			name:     "escolha sem critérios",
			question: Question{Type: QuestionChoice},
			body:     `{"type":"choice","choice":"a",` + dist + `}`,
			wantErr:  "pergunta de escolha sem critérios",
		},
		{
			name:     "escolha com critérios genéricos",
			question: Question{Type: QuestionChoice, Criteria: map[string]any{"a": "x", "b": "y"}},
			body:     `{"type":"choice","choice":"b",` + dist + `}`,
		},
		{
			name:     "escolha com critérios genéricos e opção fora",
			question: Question{Type: QuestionChoice, Criteria: map[string]any{"a": "x", "b": "y"}},
			body:     `{"type":"choice","choice":"c",` + dist + `}`,
			wantErr:  "opção fora do conjunto (a, b)",
		},
		{
			name:     "escolha não string",
			question: Question{Type: QuestionChoice, Criteria: ChoiceCriteria{"a": "x"}},
			body:     `{"type":"choice","choice":3,` + dist + `}`,
			wantErr:  "opção fora do conjunto (a)",
		},
		{
			name:     "escolha sem probabilidades",
			question: Question{Type: QuestionChoice, Criteria: ChoiceCriteria{"a": "x"}},
			body:     `{"type":"choice","choice":"a","confidence":1}`,
			wantErr:  "probabilidades/confiança inválidas",
		},
		{
			name:     "probabilidades com formato errado",
			question: Question{Type: QuestionChoice, Criteria: ChoiceCriteria{"a": "x"}},
			body:     `{"type":"choice","choice":"a","probabilities":[1],"confidence":1}`,
			wantErr:  "probabilidades/confiança inválidas",
		},
		{
			name:     "score sem rubrica",
			question: Question{Type: QuestionScore},
			body:     `{"type":"score","score":0,` + dist + `}`,
			wantErr:  "pergunta de score sem rubrica",
		},
		{
			name:     "score com rubrica genérica",
			question: Question{Type: QuestionScore, Criteria: []any{"a", "b", "c"}},
			body:     `{"type":"score","score":2,` + dist + `}`,
		},
		{
			name:     "score com rubrica genérica acima do limite",
			question: Question{Type: QuestionScore, Criteria: []any{"a", "b", "c"}},
			body:     `{"type":"score","score":3,` + dist + `}`,
			wantErr:  "score fora de [0,2]",
		},
		{
			name:     "score negativo",
			question: Question{Type: QuestionScore, Criteria: []string{"a", "b"}},
			body:     `{"type":"score","score":-1,` + dist + `}`,
			wantErr:  "score fora de [0,1]",
		},
		{
			name:     "score ausente",
			question: Question{Type: QuestionScore, Criteria: []string{"a", "b"}},
			body:     `{"type":"score",` + dist + `}`,
			wantErr:  "score fora de [0,1]",
		},
		{
			name:     "score sem confiança",
			question: Question{Type: QuestionScore, Criteria: []string{"a", "b"}},
			body:     `{"type":"score","score":1,"probabilities":{}}`,
			wantErr:  "probabilidades/confiança inválidas",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := Request{Questions: map[string]Question{"q": test.question}}
			response, err := ValidateResponse(request, envelope(test.body))
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("erro = %v, quer %q", err, test.wantErr)
				}
				if !IsUnavailable(err) {
					t.Fatalf("erro deveria ser indisponibilidade: %T", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ValidateResponse: %v", err)
			}
			answer := response.Answers["q"]
			if answer.Type != test.question.Type {
				t.Fatalf("tipo = %s", answer.Type)
			}
			if answer.Confidence == nil || *answer.Confidence != 0.5 {
				t.Fatalf("confiança = %v", answer.Confidence)
			}
		})
	}
}
