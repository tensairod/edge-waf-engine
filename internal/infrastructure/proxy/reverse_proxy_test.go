package proxy_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tensairod/edge-waf-engine/internal/application"
	"github.com/tensairod/edge-waf-engine/internal/domain"
	"github.com/tensairod/edge-waf-engine/internal/infrastructure/proxy"
)

type fakeRateLimiter func(string) bool

func (f fakeRateLimiter) Allow(sourceIP string) bool { return f(sourceIP) }

func alwaysAllow() fakeRateLimiter { return func(string) bool { return true } }
func alwaysBlock() fakeRateLimiter { return func(string) bool { return false } }

// fakeLogger registra quantas vezes LogIfBlocked foi chamado e com qual
// resultado — usado para provar que o proxy de fato aciona o logger no
// momento certo, sem precisar inspecionar JSON de verdade nestes testes
// (isso já é responsabilidade dos testes do próprio logging.BlockLogger).
type fakeLogger struct {
	calls []application.ProcessResult
}

func (f *fakeLogger) LogIfBlocked(_ domain.RequestContext, result application.ProcessResult) {
	f.calls = append(f.calls, result)
}

func sqliRuleSet(t *testing.T) domain.RuleSet {
	t.Helper()
	rule, err := domain.NewRule(
		"sqli-001", domain.CategorySQLInjection, `(?i)union.*select`,
		[]domain.Target{domain.TargetQuery}, domain.SeverityHigh, "",
	)
	require.NoError(t, err)
	ruleSet, err := domain.NewRuleSet([]domain.Rule{rule})
	require.NoError(t, err)
	return ruleSet
}

func emptyRuleSet(t *testing.T) domain.RuleSet {
	t.Helper()
	ruleSet, err := domain.NewRuleSet([]domain.Rule{})
	require.NoError(t, err)
	return ruleSet
}

// newTestBackend sobe um servidor HTTP real que ecoa o corpo recebido e
// registra se foi chamado — usado para provar que requisições
// bloqueadas NUNCA chegam ao backend.
func newTestBackend(t *testing.T) (*httptest.Server, *bool) {
	t.Helper()
	wasCalled := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wasCalled = true
		body, _ := io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("backend recebeu: " + string(body)))
	}))
	return server, &wasCalled
}

func TestWAFReverseProxy_ForwardsAllowedRequestToBackend(t *testing.T) {
	backend, wasCalled := newTestBackend(t)
	defer backend.Close()
	backendURL, err := url.Parse(backend.URL)
	require.NoError(t, err)

	engine := application.NewDetectionEngine(sqliRuleSet(t))
	waf, err := application.NewWAFEngine(engine, alwaysAllow(), false, application.FailOpen)
	require.NoError(t, err)

	log := &fakeLogger{}
	wafProxy := proxy.NewWAFReverseProxy(backendURL, waf, log)

	req := httptest.NewRequest(http.MethodGet, "/search?q=hello", nil)
	req.RemoteAddr = "203.0.113.1:54321"
	rec := httptest.NewRecorder()

	wafProxy.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.True(t, *wasCalled, "backend deveria ter sido chamado para requisição limpa")
	assert.Empty(t, log.calls, "requisição permitida não deveria acionar o logger")
}

func TestWAFReverseProxy_BlocksMaliciousRequestBeforeReachingBackend(t *testing.T) {
	backend, wasCalled := newTestBackend(t)
	defer backend.Close()
	backendURL, err := url.Parse(backend.URL)
	require.NoError(t, err)

	engine := application.NewDetectionEngine(sqliRuleSet(t))
	waf, err := application.NewWAFEngine(engine, alwaysAllow(), false, application.FailOpen)
	require.NoError(t, err)

	log := &fakeLogger{}
	wafProxy := proxy.NewWAFReverseProxy(backendURL, waf, log)

	req := httptest.NewRequest(http.MethodGet, "/search?q=1+UNION+SELECT+password+FROM+users", nil)
	req.RemoteAddr = "203.0.113.1:54321"
	rec := httptest.NewRecorder()

	wafProxy.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.False(t, *wasCalled, "backend NUNCA deveria ser chamado para requisição bloqueada")
	require.Len(t, log.calls, 1)
	assert.Equal(t, application.BlockReasonRuleViolation, log.calls[0].Reason)
}

func TestWAFReverseProxy_BlocksOnRateLimit(t *testing.T) {
	backend, wasCalled := newTestBackend(t)
	defer backend.Close()
	backendURL, err := url.Parse(backend.URL)
	require.NoError(t, err)

	engine := application.NewDetectionEngine(emptyRuleSet(t))
	waf, err := application.NewWAFEngine(engine, alwaysBlock(), false, application.FailOpen)
	require.NoError(t, err)

	log := &fakeLogger{}
	wafProxy := proxy.NewWAFReverseProxy(backendURL, waf, log)

	req := httptest.NewRequest(http.MethodGet, "/search?q=hello", nil)
	req.RemoteAddr = "203.0.113.1:54321"
	rec := httptest.NewRecorder()

	wafProxy.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.False(t, *wasCalled)
	require.Len(t, log.calls, 1)
	assert.Equal(t, application.BlockReasonRateLimit, log.calls[0].Reason)
}

func TestWAFReverseProxy_DryRunForwardsEvenMaliciousRequest(t *testing.T) {
	backend, wasCalled := newTestBackend(t)
	defer backend.Close()
	backendURL, err := url.Parse(backend.URL)
	require.NoError(t, err)

	engine := application.NewDetectionEngine(sqliRuleSet(t))
	waf, err := application.NewWAFEngine(engine, alwaysAllow(), true, application.FailOpen) // dry-run
	require.NoError(t, err)

	log := &fakeLogger{}
	wafProxy := proxy.NewWAFReverseProxy(backendURL, waf, log)

	req := httptest.NewRequest(http.MethodGet, "/search?q=1+UNION+SELECT+password+FROM+users", nil)
	req.RemoteAddr = "203.0.113.1:54321"
	rec := httptest.NewRecorder()

	wafProxy.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code, "dry-run deveria encaminhar mesmo um payload malicioso")
	assert.True(t, *wasCalled)
	require.Len(t, log.calls, 1, "dry-run ainda deveria acionar o logger, mesmo sem bloquear de fato")
	assert.False(t, log.calls[0].Blocked)
	assert.True(t, log.calls[0].DryRun)
}

func TestWAFReverseProxy_BodyIsPreservedWhenForwardedToBackend(t *testing.T) {
	backend, _ := newTestBackend(t)
	defer backend.Close()
	backendURL, err := url.Parse(backend.URL)
	require.NoError(t, err)

	engine := application.NewDetectionEngine(emptyRuleSet(t))
	waf, err := application.NewWAFEngine(engine, alwaysAllow(), false, application.FailOpen)
	require.NoError(t, err)

	log := &fakeLogger{}
	wafProxy := proxy.NewWAFReverseProxy(backendURL, waf, log)

	req := httptest.NewRequest(http.MethodPost, "/comments", strings.NewReader("hello from the real body"))
	req.RemoteAddr = "203.0.113.1:54321"
	rec := httptest.NewRecorder()

	wafProxy.ServeHTTP(rec, req)

	respBody, _ := io.ReadAll(rec.Result().Body)
	assert.Contains(
		t, string(respBody), "hello from the real body",
		"o corpo original deveria ter chegado intacto ao backend, apesar de ter sido lido pelo WAF para inspeção",
	)
}

func TestWAFReverseProxy_InvalidRemoteAddrReturnsBadRequest(t *testing.T) {
	backend, wasCalled := newTestBackend(t)
	defer backend.Close()
	backendURL, err := url.Parse(backend.URL)
	require.NoError(t, err)

	engine := application.NewDetectionEngine(emptyRuleSet(t))
	waf, err := application.NewWAFEngine(engine, alwaysAllow(), false, application.FailOpen)
	require.NoError(t, err)

	log := &fakeLogger{}
	wafProxy := proxy.NewWAFReverseProxy(backendURL, waf, log)

	req := httptest.NewRequest(http.MethodGet, "/search", nil)
	req.RemoteAddr = "isso-nao-e-um-ip-nem-tem-porta"
	rec := httptest.NewRecorder()

	wafProxy.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.False(t, *wasCalled)
	assert.Empty(t, log.calls, "logger não deveria ser acionado se a requisição nem chegou a ser processada")
}
