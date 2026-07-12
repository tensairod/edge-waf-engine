package domain_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/SEU_USUARIO/edge-waf-engine/internal/domain"
)

func TestNewRule_HappyPath(t *testing.T) {
	rule, err := domain.NewRule(
		"sqli-001",
		domain.CategorySQLInjection,
		`(?i)(\bunion\b.*\bselect\b)`,
		[]domain.Target{domain.TargetQuery, domain.TargetBody},
		domain.SeverityHigh,
		"Detecta UNION SELECT clássico de SQL Injection.",
	)

	require.NoError(t, err)
	assert.Equal(t, "sqli-001", rule.ID())
	assert.Equal(t, domain.CategorySQLInjection, rule.Category())
	assert.Equal(t, domain.SeverityHigh, rule.Severity())
	assert.Equal(t, "Detecta UNION SELECT clássico de SQL Injection.", rule.Description())
}

func TestNewRule_MatchesText(t *testing.T) {
	rule, err := domain.NewRule(
		"sqli-001",
		domain.CategorySQLInjection,
		`(?i)(\bunion\b.*\bselect\b)`,
		[]domain.Target{domain.TargetQuery},
		domain.SeverityHigh,
		"",
	)
	require.NoError(t, err)

	assert.True(t, rule.Matches("id=1 UNION SELECT username, password FROM users"))
	assert.False(t, rule.Matches("id=42"))
}

func TestNewRule_HasTarget(t *testing.T) {
	rule, err := domain.NewRule(
		"sqli-001",
		domain.CategorySQLInjection,
		`test`,
		[]domain.Target{domain.TargetQuery, domain.TargetBody},
		domain.SeverityHigh,
		"",
	)
	require.NoError(t, err)

	assert.True(t, rule.HasTarget(domain.TargetQuery))
	assert.True(t, rule.HasTarget(domain.TargetBody))
	assert.False(t, rule.HasTarget(domain.TargetHeaders))
}

func TestNewRule_EmptyID(t *testing.T) {
	_, err := domain.NewRule(
		"",
		domain.CategorySQLInjection,
		"test",
		[]domain.Target{domain.TargetQuery},
		domain.SeverityHigh,
		"",
	)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "id não pode ser vazio")
}

func TestNewRule_InvalidCategory(t *testing.T) {
	_, err := domain.NewRule(
		"rule-1",
		domain.Category("nao_existe"),
		"test",
		[]domain.Target{domain.TargetQuery},
		domain.SeverityHigh,
		"",
	)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "categoria inválida")
}

func TestNewRule_NoTargets(t *testing.T) {
	_, err := domain.NewRule(
		"rule-1",
		domain.CategorySQLInjection,
		"test",
		[]domain.Target{},
		domain.SeverityHigh,
		"",
	)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "ao menos um target")
}

func TestNewRule_InvalidTarget(t *testing.T) {
	_, err := domain.NewRule(
		"rule-1",
		domain.CategorySQLInjection,
		"test",
		[]domain.Target{domain.Target("cookie")},
		domain.SeverityHigh,
		"",
	)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "target inválido")
}

func TestNewRule_InvalidSeverity(t *testing.T) {
	_, err := domain.NewRule(
		"rule-1",
		domain.CategorySQLInjection,
		"test",
		[]domain.Target{domain.TargetQuery},
		domain.Severity("catastrofica"),
		"",
	)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "severidade inválida")
}

func TestNewRule_InvalidRegexPattern(t *testing.T) {
	_, err := domain.NewRule(
		"rule-1",
		domain.CategorySQLInjection,
		`(unclosed group`,
		[]domain.Target{domain.TargetQuery},
		domain.SeverityHigh,
		"",
	)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "padrão regex inválido")
}

func TestNewRule_TargetsSliceIsCopiedNotAliased(t *testing.T) {
	// Garante que mutar o slice original depois de criar a Rule não afeta
	// a Rule já construída — mesma preocupação de isolamento que já
	// aplicamos no ConfigBuilder do config-validator.
	targets := []domain.Target{domain.TargetQuery}
	rule, err := domain.NewRule(
		"rule-1", domain.CategorySQLInjection, "test", targets, domain.SeverityHigh, "",
	)
	require.NoError(t, err)

	targets[0] = domain.TargetHeaders

	assert.True(t, rule.HasTarget(domain.TargetQuery))
	assert.False(t, rule.HasTarget(domain.TargetHeaders))
}
