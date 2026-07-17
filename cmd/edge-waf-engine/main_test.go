package main

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const testRulesYAML = `
rules:
  - id: sqli-001
    category: sql_injection
    pattern: "(?i)union.*select"
    targets: [query]
    severity: high
    description: "teste"
`

func writeTestRulesFile(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.yaml")
	if err := os.WriteFile(path, []byte(testRulesYAML), 0o644); err != nil {
		t.Fatalf("erro escrevendo rules.yaml de teste: %v", err)
	}
	return path
}

func TestParseFlags_RequiresBackend(t *testing.T) {
	_, err := parseFlags([]string{"--listen", ":9090"})
	if err == nil {
		t.Fatal("esperava erro por --backend ausente")
	}
}

func TestParseFlags_DefaultsAreApplied(t *testing.T) {
	cfg, err := parseFlags([]string{"--backend", "http://localhost:9000"})
	if err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}
	if cfg.listenAddr != ":8080" {
		t.Errorf("listenAddr default incorreto: %v", cfg.listenAddr)
	}
	if cfg.rulesPath != "config/rules.yaml" {
		t.Errorf("rulesPath default incorreto: %v", cfg.rulesPath)
	}
	if cfg.rateLimitCapacity != 100 {
		t.Errorf("rateLimitCapacity default incorreto: %v", cfg.rateLimitCapacity)
	}
	if cfg.failMode != "fail_open" {
		t.Errorf("failMode default incorreto: %v", cfg.failMode)
	}
	if cfg.dryRun {
		t.Errorf("dryRun default deveria ser false")
	}
}

func TestParseFlags_CustomValuesOverrideDefaults(t *testing.T) {
	cfg, err := parseFlags([]string{
		"--backend", "http://localhost:9000",
		"--listen", ":9090",
		"--rate-limit-capacity", "50",
		"--rate-limit-refill", "5",
		"--fail-mode", "fail_closed",
		"--dry-run",
	})
	if err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}
	if cfg.listenAddr != ":9090" || cfg.rateLimitCapacity != 50 || cfg.rateLimitRefill != 5 {
		t.Fatalf("valores customizados nao aplicados corretamente: %+v", cfg)
	}
	if cfg.failMode != "fail_closed" {
		t.Fatalf("fail-mode nao aplicado: %v", cfg.failMode)
	}
	if !cfg.dryRun {
		t.Fatalf("dry-run deveria ser true")
	}
}

func TestBuildHandler_InvalidBackendURLFails(t *testing.T) {
	cfg := config{backendURL: "http://[::1]:namedport", rulesPath: writeTestRulesFile(t), rateLimitCapacity: 10, rateLimitRefill: 1, rateLimitIdleTTL: time.Minute, failMode: "fail_open"}
	_, _, err := buildHandler(cfg, io.Discard)
	if err == nil {
		t.Fatal("esperava erro para backend URL invalida")
	}
}

func TestBuildHandler_MissingRulesFileFails(t *testing.T) {
	cfg := config{backendURL: "http://localhost:9000", rulesPath: "/nao/existe/rules.yaml", rateLimitCapacity: 10, rateLimitRefill: 1, rateLimitIdleTTL: time.Minute, failMode: "fail_open"}
	_, _, err := buildHandler(cfg, io.Discard)
	if err == nil {
		t.Fatal("esperava erro para arquivo de regras ausente")
	}
}

func TestBuildHandler_InvalidRateLimitConfigFails(t *testing.T) {
	cfg := config{backendURL: "http://localhost:9000", rulesPath: writeTestRulesFile(t), rateLimitCapacity: 0, rateLimitRefill: 1, rateLimitIdleTTL: time.Minute, failMode: "fail_open"}
	_, _, err := buildHandler(cfg, io.Discard)
	if err == nil {
		t.Fatal("esperava erro para rate limit capacity invalida")
	}
}

func TestBuildHandler_InvalidFailModeFails(t *testing.T) {
	cfg := config{backendURL: "http://localhost:9000", rulesPath: writeTestRulesFile(t), rateLimitCapacity: 10, rateLimitRefill: 1, rateLimitIdleTTL: time.Minute, failMode: "modo_que_nao_existe"}
	_, _, err := buildHandler(cfg, io.Discard)
	if err == nil {
		t.Fatal("esperava erro para fail-mode invalido")
	}
}

func TestBuildHandler_ValidConfigBuildsWorkingHandler(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok do backend"))
	}))
	defer backend.Close()

	cfg := config{
		backendURL: backend.URL, rulesPath: writeTestRulesFile(t),
		rateLimitCapacity: 100, rateLimitRefill: 10, rateLimitIdleTTL: time.Minute,
		failMode: "fail_open",
	}

	var logBuf bytes.Buffer
	handler, limiter, err := buildHandler(cfg, &logBuf)
	if err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}
	if limiter == nil {
		t.Fatal("limiter nao deveria ser nil")
	}

	// requisicao limpa: encaminhada
	req := httptest.NewRequest(http.MethodGet, "/search?q=hello", nil)
	req.RemoteAddr = "203.0.113.1:1234"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("esperava 200, veio %d", rec.Code)
	}

	// requisicao maliciosa: bloqueada + logada
	reqBad := httptest.NewRequest(http.MethodGet, "/search?q=1+UNION+SELECT+x", nil)
	reqBad.RemoteAddr = "203.0.113.1:1234"
	recBad := httptest.NewRecorder()
	handler.ServeHTTP(recBad, reqBad)
	if recBad.Code != http.StatusForbidden {
		t.Fatalf("esperava 403, veio %d", recBad.Code)
	}
	if logBuf.Len() == 0 {
		t.Fatal("esperava que a requisicao bloqueada gerasse log")
	}
}

func TestRun_ServesRequestsAndShutsDownGracefully(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := config{
		backendURL: backend.URL, rulesPath: writeTestRulesFile(t),
		rateLimitCapacity: 100, rateLimitRefill: 10, rateLimitIdleTTL: time.Minute,
		rateLimitCleanupEvery: 50 * time.Millisecond,
		failMode:              "fail_open",
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("erro criando listener de teste: %v", err)
	}
	addr := listener.Addr().String()

	ctx, cancel := context.WithCancel(context.Background())

	runErr := make(chan error, 1)
	go func() {
		runErr <- run(ctx, cfg, listener, io.Discard, io.Discard)
	}()

	// aguarda o servidor comecar a aceitar conexoes (com pequeno retry,
	// ja que a goroutine acima leva um instante para chamar Serve).
	var resp *http.Response
	for i := 0; i < 20; i++ {
		resp, err = http.Get("http://" + addr + "/search?q=hello")
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("servidor nao respondeu a tempo: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("esperava 200, veio %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	cancel() // dispara o shutdown gracioso

	select {
	case err := <-runErr:
		if err != nil {
			t.Fatalf("run() deveria retornar nil apos shutdown gracioso, veio: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("run() nao retornou a tempo apos cancelamento do context")
	}
}
