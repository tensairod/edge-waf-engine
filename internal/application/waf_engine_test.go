package application_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tensairod/edge-waf-engine/internal/application"
	"github.com/tensairod/edge-waf-engine/internal/domain"
)

// fakeRateLimiter converte uma função comum em uma implementação de
// application.RateLimiter — idiom comum em Go para fakes de interface
// de um único método, sem precisar de uma struct dedicada por cenário.
type fakeRateLimiter func(sourceIP string) bool

func (f fakeRateLimiter) Allow(sourceIP string) bool { return f(sourceIP) }

func alwaysAllow() fakeRateLimiter { return func(string) bool { return true } }
func alwaysBlock() fakeRateLimiter { return func(string) bool { return false } }
func panicking() fakeRateLimiter   { return func(string) bool { panic("boom: erro interno simulado") } }

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

func cleanRequest(t *testing.T) domain.RequestContext {
	t.Helper()
	ctx, err := domain.NewRequestContext(domain.RequestContextParams{
		Method: "GET", Path: "/search", SourceIP: "203.0.113.1",
		Query: map[string][]string{"q": {"hello"}},
	})
	require.NoError(t, err)
	return ctx
}

func maliciousRequest(t *testing.T) domain.RequestContext {
	t.Helper()
	ctx, err := domain.NewRequestContext(domain.RequestContextParams{
		Method: "GET", Path: "/search", SourceIP: "203.0.113.1",
		Query: map[string][]string{"q": {"1 UNION SELECT password FROM users"}},
	})
	require.NoError(t, err)
	return ctx
}

func TestNewWAFEngine_InvalidFailModeFails(t *testing.T) {
	engine := application.NewDetectionEngine(emptyRuleSet(t))

	_, err := application.NewWAFEngine(engine, alwaysAllow(), false, application.FailMode("nao_existe"))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "fail mode inválido")
}

func TestWAFEngine_AllowsCleanRequest(t *testing.T) {
	engine := application.NewDetectionEngine(sqliRuleSet(t))
	waf, err := application.NewWAFEngine(engine, alwaysAllow(), false, application.FailOpen)
	require.NoError(t, err)

	result := waf.Process(cleanRequest(t))

	assert.False(t, result.Blocked)
	assert.Equal(t, application.BlockReasonNone, result.Reason)
}

func TestWAFEngine_BlocksOnRuleViolation(t *testing.T) {
	engine := application.NewDetectionEngine(sqliRuleSet(t))
	waf, err := application.NewWAFEngine(engine, alwaysAllow(), false, application.FailOpen)
	require.NoError(t, err)

	result := waf.Process(maliciousRequest(t))

	assert.True(t, result.Blocked)
	assert.Equal(t, application.BlockReasonRuleViolation, result.Reason)
	assert.True(t, result.Verdict.IsBlocked())
}

func TestWAFEngine_DryRunNeverBlocksButReportsViolation(t *testing.T) {
	engine := application.NewDetectionEngine(sqliRuleSet(t))
	waf, err := application.NewWAFEngine(engine, alwaysAllow(), true, application.FailOpen)
	require.NoError(t, err)

	result := waf.Process(maliciousRequest(t))

	assert.False(t, result.Blocked, "dry-run nunca deveria bloquear de fato")
	assert.Equal(t, application.BlockReasonRuleViolation, result.Reason, "mas deveria reportar o motivo")
	assert.True(t, result.DryRun)
}

func TestWAFEngine_BlocksOnRateLimit(t *testing.T) {
	engine := application.NewDetectionEngine(emptyRuleSet(t))
	waf, err := application.NewWAFEngine(engine, alwaysBlock(), false, application.FailOpen)
	require.NoError(t, err)

	result := waf.Process(cleanRequest(t))

	assert.True(t, result.Blocked)
	assert.Equal(t, application.BlockReasonRateLimit, result.Reason)
}

func TestWAFEngine_RateLimitIsCheckedBeforeDetection(t *testing.T) {
	// Requisição maliciosa E rate-limitada ao mesmo tempo: o motivo
	// reportado deve ser rate limit, não violação de regra — prova que
	// a checagem de rate limit acontece primeiro (RNF01: rejeitar cedo
	// evita gastar CPU avaliando regex numa requisição já descartada).
	engine := application.NewDetectionEngine(sqliRuleSet(t))
	waf, err := application.NewWAFEngine(engine, alwaysBlock(), false, application.FailOpen)
	require.NoError(t, err)

	result := waf.Process(maliciousRequest(t))

	assert.Equal(t, application.BlockReasonRateLimit, result.Reason)
}

func TestWAFEngine_DryRunAppliesToRateLimitToo(t *testing.T) {
	engine := application.NewDetectionEngine(emptyRuleSet(t))
	waf, err := application.NewWAFEngine(engine, alwaysBlock(), true, application.FailOpen)
	require.NoError(t, err)

	result := waf.Process(cleanRequest(t))

	assert.False(t, result.Blocked)
	assert.Equal(t, application.BlockReasonRateLimit, result.Reason)
	assert.True(t, result.DryRun)
}

func TestWAFEngine_PanicRecoveredWithFailOpenAllowsRequest(t *testing.T) {
	engine := application.NewDetectionEngine(emptyRuleSet(t))
	waf, err := application.NewWAFEngine(engine, panicking(), false, application.FailOpen)
	require.NoError(t, err)

	result := waf.Process(cleanRequest(t))

	assert.False(t, result.Blocked, "fail-open deveria permitir a requisição mesmo após panic")
	assert.Equal(t, application.BlockReasonInternalError, result.Reason)
}

func TestWAFEngine_PanicRecoveredWithFailClosedBlocksRequest(t *testing.T) {
	engine := application.NewDetectionEngine(emptyRuleSet(t))
	waf, err := application.NewWAFEngine(engine, panicking(), false, application.FailClosed)
	require.NoError(t, err)

	result := waf.Process(cleanRequest(t))

	assert.True(t, result.Blocked, "fail-closed deveria bloquear a requisição após panic")
	assert.Equal(t, application.BlockReasonInternalError, result.Reason)
}

func TestWAFEngine_DryRunOverridesFailClosedOnPanic(t *testing.T) {
	// Mesmo em fail-closed, dry-run nunca deve bloquear de fato — essa é
	// a garantia central do modo dry-run (RF09): nunca impactar tráfego
	// real, independentemente de qualquer outra configuração.
	engine := application.NewDetectionEngine(emptyRuleSet(t))
	waf, err := application.NewWAFEngine(engine, panicking(), true, application.FailClosed)
	require.NoError(t, err)

	result := waf.Process(cleanRequest(t))

	assert.False(t, result.Blocked)
	assert.Equal(t, application.BlockReasonInternalError, result.Reason)
	assert.True(t, result.DryRun)
}

func TestWAFEngine_DoesNotPanicItself(t *testing.T) {
	// O teste em si não deveria falhar por panic não recuperado — se
	// Process não recuperar corretamente, o teste inteiro quebra aqui.
	engine := application.NewDetectionEngine(emptyRuleSet(t))
	waf, err := application.NewWAFEngine(engine, panicking(), false, application.FailOpen)
	require.NoError(t, err)

	assert.NotPanics(t, func() {
		waf.Process(cleanRequest(t))
	})
}
