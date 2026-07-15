package rules_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tensairod/edge-waf-engine/internal/domain"
	"github.com/tensairod/edge-waf-engine/internal/infrastructure/rules"
)

const validYAML = `
rules:
  - id: sqli-001-union-select
    category: sql_injection
    pattern: "(?i)\\bunion\\b.*\\bselect\\b"
    targets:
      - query
      - body
    severity: high
    description: "Detecta UNION SELECT."
  - id: xss-001-script-tag
    category: xss
    pattern: "(?i)<script"
    targets:
      - body
    severity: medium
    description: "Detecta tags de script."
`

func TestParseRuleSet_HappyPath(t *testing.T) {
	ruleSet, err := rules.ParseRuleSet([]byte(validYAML))

	require.NoError(t, err)
	assert.Equal(t, 2, ruleSet.Len())

	loaded := ruleSet.Rules()
	assert.Equal(t, "sqli-001-union-select", loaded[0].ID())
	assert.Equal(t, domain.CategorySQLInjection, loaded[0].Category())
	assert.Equal(t, domain.SeverityHigh, loaded[0].Severity())
	assert.True(t, loaded[0].HasTarget(domain.TargetQuery))
	assert.True(t, loaded[0].HasTarget(domain.TargetBody))
	assert.True(t, loaded[0].Matches("1 UNION SELECT password FROM users"))

	assert.Equal(t, "xss-001-script-tag", loaded[1].ID())
	assert.Equal(t, domain.CategoryXSS, loaded[1].Category())
}

func TestParseRuleSet_EmptyRulesListIsValid(t *testing.T) {
	ruleSet, err := rules.ParseRuleSet([]byte(`rules: []`))

	require.NoError(t, err)
	assert.Equal(t, 0, ruleSet.Len())
}

func TestParseRuleSet_MissingRulesKeyIsValid(t *testing.T) {
	ruleSet, err := rules.ParseRuleSet([]byte(``))

	require.NoError(t, err)
	assert.Equal(t, 0, ruleSet.Len())
}

func TestParseRuleSet_MalformedYAMLSyntaxFails(t *testing.T) {
	malformed := "rules:\n  - id: [this is not valid yaml structure"

	_, err := rules.ParseRuleSet([]byte(malformed))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "erro fazendo parse do YAML")
}

func TestParseRuleSet_UnknownCategoryFails(t *testing.T) {
	yamlContent := `
rules:
  - id: rule-1
    category: categoria_que_nao_existe
    pattern: "test"
    targets: [query]
    severity: high
`
	_, err := rules.ParseRuleSet([]byte(yamlContent))

	require.Error(t, err)
	assert.Contains(t, err.Error(), `regra #1 (id="rule-1")`)
	assert.Contains(t, err.Error(), "categoria inválida")
}

func TestParseRuleSet_UnknownSeverityFails(t *testing.T) {
	yamlContent := `
rules:
  - id: rule-1
    category: sql_injection
    pattern: "test"
    targets: [query]
    severity: catastrofica
`
	_, err := rules.ParseRuleSet([]byte(yamlContent))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "severidade inválida")
}

func TestParseRuleSet_UnknownTargetFails(t *testing.T) {
	yamlContent := `
rules:
  - id: rule-1
    category: sql_injection
    pattern: "test"
    targets: [cookie]
    severity: high
`
	_, err := rules.ParseRuleSet([]byte(yamlContent))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "target inválido")
}

func TestParseRuleSet_InvalidRegexPatternFails(t *testing.T) {
	yamlContent := `
rules:
  - id: rule-1
    category: sql_injection
    pattern: "(unclosed"
    targets: [query]
    severity: high
`
	_, err := rules.ParseRuleSet([]byte(yamlContent))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "padrão regex inválido")
}

func TestParseRuleSet_DuplicateRuleIDFails(t *testing.T) {
	yamlContent := `
rules:
  - id: rule-1
    category: sql_injection
    pattern: "test1"
    targets: [query]
    severity: high
  - id: rule-1
    category: xss
    pattern: "test2"
    targets: [body]
    severity: medium
`
	_, err := rules.ParseRuleSet([]byte(yamlContent))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "regra duplicada")
}

func TestParseRuleSet_NoTargetsFails(t *testing.T) {
	yamlContent := `
rules:
  - id: rule-1
    category: sql_injection
    pattern: "test"
    severity: high
`
	_, err := rules.ParseRuleSet([]byte(yamlContent))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "ao menos um target")
}

func TestLoadRuleSet_ReadsRealFileFromDisk(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.yaml")
	require.NoError(t, os.WriteFile(path, []byte(validYAML), 0o644))

	ruleSet, err := rules.LoadRuleSet(path)

	require.NoError(t, err)
	assert.Equal(t, 2, ruleSet.Len())
}

func TestLoadRuleSet_MissingFileFails(t *testing.T) {
	_, err := rules.LoadRuleSet("/caminho/que/nao/existe/rules.yaml")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "erro lendo arquivo")
}
