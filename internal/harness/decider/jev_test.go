package decider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func jevRequest() Request {
	return Request{
		State:     map[string]any{"artifact": "dados"},
		Questions: map[string]Question{"ok": {Type: QuestionNoul, Instructions: "tudo certo?"}},
	}
}

func noSleep(context.Context, time.Duration) error { return nil }

func TestJevPostsKeyInHeaderAndValidates(t *testing.T) {
	var seen jevBody
	var rawQuery string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rawQuery = r.URL.RawQuery
		if got := r.Header.Get("Authorization"); got != "Bearer chave-secreta" {
			t.Errorf("authorization = %q", got)
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("content-type = %q", got)
		}
		if err := json.NewDecoder(r.Body).Decode(&seen); err != nil {
			t.Errorf("corpo inválido: %v", err)
		}
		_, _ = w.Write([]byte(`{"model":"jev-1.13.0","answers":{"ok":{"type":"noul","noul":0.7}}}`))
	}))
	defer server.Close()
	endpoint := server.URL + "/v1/systemone"
	response, err := Jev{}.Call(context.Background(), Connection{Model: "jev-latest", Key: "chave-secreta", Endpoint: &endpoint}, jevRequest())
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if response.Model != "jev-1.13.0" || response.Answers["ok"].Noul == nil || *response.Answers["ok"].Noul != 0.7 {
		t.Fatalf("resposta = %+v", response)
	}
	if rawQuery != "" {
		t.Fatalf("a chave vazou para a URL: %q", rawQuery)
	}
	if seen.Model != "jev-latest" || !strings.Contains(seen.State.Notice, "não instruções") {
		t.Fatalf("pedido = %+v", seen)
	}
	if seen.State.Artifacts["artifact"] != "dados" {
		t.Fatalf("artefatos = %#v", seen.State.Artifacts)
	}
}

func TestJevRetriesRateLimit(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) < 3 {
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":"calma"}`))
			return
		}
		_, _ = w.Write([]byte(`{"model":"m","answers":{"ok":{"type":"noul","noul":0.5}}}`))
	}))
	defer server.Close()
	response, err := Jev{Sleep: noSleep}.Call(context.Background(), Connection{Model: "m", Key: "k", Endpoint: &server.URL}, jevRequest())
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if calls.Load() != 3 || response.Model != "m" {
		t.Fatalf("chamadas = %d, resposta = %+v", calls.Load(), response)
	}
}

func TestJevDoesNotRetryServerError(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`falha interna`))
	}))
	defer server.Close()
	_, err := Jev{Sleep: noSleep}.Call(context.Background(), Connection{Model: "m", Key: "k", Endpoint: &server.URL}, jevRequest())
	if !IsUnavailable(err) || !strings.Contains(err.Error(), "Jev respondeu HTTP 500") || !strings.Contains(err.Error(), "falha interna") {
		t.Fatalf("erro = %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("chamadas = %d, quer 1", calls.Load())
	}
}

func TestJevTimeoutAndInvalidBody(t *testing.T) {
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		_, _ = w.Write([]byte(`{"model":"m","answers":{}}`))
	}))
	defer slow.Close()
	_, err := Jev{Timeout: 20 * time.Millisecond}.Call(context.Background(), Connection{Model: "m", Key: "k", Endpoint: &slow.URL}, jevRequest())
	if !IsUnavailable(err) || !strings.Contains(err.Error(), "chamada ao Jev falhou") {
		t.Fatalf("erro de timeout = %v", err)
	}

	invalid := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`não é json`))
	}))
	defer invalid.Close()
	_, err = Jev{Sleep: noSleep}.Call(context.Background(), Connection{Model: "m", Key: "k", Endpoint: &invalid.URL}, jevRequest())
	if !IsUnavailable(err) || !strings.Contains(err.Error(), "corpo que não é JSON") {
		t.Fatalf("erro = %v", err)
	}
}

func TestJevCancelledContext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Jev{}.Call(ctx, Connection{Model: "m", Key: "k", Endpoint: &server.URL}, jevRequest())
	if !IsUnavailable(err) {
		t.Fatalf("erro = %v", err)
	}
}
