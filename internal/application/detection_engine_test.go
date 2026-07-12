package application_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tensairod/edge-waf-engine/internal/application"
	"github.com/tensairod/edge-waf-engine/internal/domain"
)

func mustRule(t *testing.T, id string, category domain.Category, pattern string, targets []domain.Target) domain.Rule {
	t.Helper()
	rule, err := domain.NewRule(id, category, pattern, targets, domain.SeverityHigh, "")
	require.NoError(t, err)
	return rule
}

func mustRequestContext(t *testing.T, params domain.RequestContextParams) domain.RequestContext {
	t.Helper()
	ctx, err := domain.NewRequestContext(params)
	require.NoError(t, err)
	return ctx
}

func baseParams() domain.RequestContextParams {
	return domain.RequestContextParams{
		Method:   "GET",
		Path:     "/search",
		SourceIP: "203.0.113.42",
	}
}

func TestDetectionEngine_AllowsCleanRequest(t *testing.T) {
	sqliRule := mustRule(t, "sqli-001", domain.CategorySQLInjection, `(?i)union.*select`, []domain.Target{domain.TargetQuery})
	ruleSet, err := domain.NewRuleSet([]domain.Rule{sqliRule})
	require.NoError(t, err)

	params := baseParams()
	params.Query = map[string][]string{"q": {"hello world"}}
	ctx := mustRequestContext(t, params)

	verdict := application.NewDetectionEngine(ruleSet).Evaluate(ctx)

	assert.False(t, verdict.IsBlocked())
	assert.Empty(t, verdict.Violations())
}

func TestDetectionEngine_BlocksOnSingleViolation(t *testing.T) {
	sqliRule := mustRule(t, "sqli-001", domain.CategorySQLInjection, `(?i)union.*select`, []domain.Target{domain.TargetQuery})
	ruleSet, err := domain.NewRuleSet([]domain.Rule{sqliRule})
	require.NoError(t, err)

	params := baseParams()
	params.Query = map[string][]string{"q": {"1 UNION SELECT password FROM users"}}
	ctx := mustRequestContext(t, params)

	verdict := application.NewDetectionEngine(ruleSet).Evaluate(ctx)

	require.True(t, verdict.IsBlocked())
	require.Len(t, verdict.Violations(), 1)
	assert.Equal(t, "sqli-001", verdict.Violations()[0].RuleID)
	assert.Equal(t, domain.TargetQuery, verdict.Violations()[0].Target)
}

func TestDetectionEngine_AggregatesMultipleViolatedRules(t *testing.T) {
	sqliRule := mustRule(t, "sqli-001", domain.CategorySQLInjection, `(?i)union.*select`, []domain.Target{domain.TargetQuery})
	xssRule := mustRule(t, "xss-001", domain.CategoryXSS, `(?i)<script`, []domain.Target{domain.TargetBody})
	ruleSet, err := domain.NewRuleSet([]domain.Rule{sqliRule, xssRule})
	require.NoError(t, err)

	params := baseParams()
	params.Query = map[string][]string{"q": {"1 UNION SELECT password FROM users"}}
	params.Body = "<script>alert(1)</script>"
	ctx := mustRequestContext(t, params)

	verdict := application.NewDetectionEngine(ruleSet).Evaluate(ctx)

	require.True(t, verdict.IsBlocked())
	assert.Len(t, verdict.Violations(), 2)
}

func TestDetectionEngine_SameRuleMatchingMultipleValuesProducesMultipleViolations(t *testing.T) {
	sqliRule := mustRule(t, "sqli-001", domain.CategorySQLInjection, `(?i)union.*select`, []domain.Target{domain.TargetQuery})
	ruleSet, err := domain.NewRuleSet([]domain.Rule{sqliRule})
	require.NoError(t, err)

	params := baseParams()
	params.Query = map[string][]string{
		"a": {"1 UNION SELECT x"},
		"b": {"2 UNION SELECT y"},
	}
	ctx := mustRequestContext(t, params)

	verdict := application.NewDetectionEngine(ruleSet).Evaluate(ctx)

	require.True(t, verdict.IsBlocked())
	assert.Len(t, verdict.Violations(), 2)
}

func TestDetectionEngine_RuleOnlyChecksItsDeclaredTargets(t *testing.T) {
	// Regra só declara TargetQuery — um payload malicioso no Body não
	// deve disparar essa regra específica.
	sqliRule := mustRule(t, "sqli-001", domain.CategorySQLInjection, `(?i)union.*select`, []domain.Target{domain.TargetQuery})
	ruleSet, err := domain.NewRuleSet([]domain.Rule{sqliRule})
	require.NoError(t, err)

	params := baseParams()
	params.Body = "1 UNION SELECT password FROM users"
	ctx := mustRequestContext(t, params)

	verdict := application.NewDetectionEngine(ruleSet).Evaluate(ctx)

	assert.False(t, verdict.IsBlocked())
}

func TestDetectionEngine_EmptyRuleSetAlwaysAllows(t *testing.T) {
	ruleSet, err := domain.NewRuleSet([]domain.Rule{})
	require.NoError(t, err)

	params := baseParams()
	params.Body = "<script>alert(1)</script>"
	ctx := mustRequestContext(t, params)

	verdict := application.NewDetectionEngine(ruleSet).Evaluate(ctx)

	assert.False(t, verdict.IsBlocked())
}

func TestDetectionEngine_RuleWithMultipleTargetsChecksAll(t *testing.T) {
	rule := mustRule(
		t, "sqli-001", domain.CategorySQLInjection, `(?i)union.*select`,
		[]domain.Target{domain.TargetQuery, domain.TargetBody, domain.TargetHeaders},
	)
	ruleSet, err := domain.NewRuleSet([]domain.Rule{rule})
	require.NoError(t, err)

	params := baseParams()
	params.Headers = map[string][]string{"X-Custom": {"1 UNION SELECT x"}}
	ctx := mustRequestContext(t, params)

	verdict := application.NewDetectionEngine(ruleSet).Evaluate(ctx)

	require.True(t, verdict.IsBlocked())
	assert.Equal(t, domain.TargetHeaders, verdict.Violations()[0].Target)
}
