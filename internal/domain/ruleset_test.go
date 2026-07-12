package domain_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/SEU_USUARIO/edge-waf-engine/internal/domain"
)

func newTestRule(t *testing.T, id string) domain.Rule {
	t.Helper()
	rule, err := domain.NewRule(
		id, domain.CategorySQLInjection, "test", []domain.Target{domain.TargetQuery},
		domain.SeverityHigh, "",
	)
	require.NoError(t, err)
	return rule
}

func TestNewRuleSet_HappyPath(t *testing.T) {
	rules := []domain.Rule{newTestRule(t, "rule-1"), newTestRule(t, "rule-2")}

	ruleSet, err := domain.NewRuleSet(rules)

	require.NoError(t, err)
	assert.Equal(t, 2, ruleSet.Len())
	assert.Len(t, ruleSet.Rules(), 2)
}

func TestNewRuleSet_DuplicateIDFails(t *testing.T) {
	rules := []domain.Rule{newTestRule(t, "rule-1"), newTestRule(t, "rule-1")}

	_, err := domain.NewRuleSet(rules)

	require.Error(t, err)
	assert.Contains(t, err.Error(), `regra duplicada com id "rule-1"`)
}

func TestNewRuleSet_EmptyIsAllowed(t *testing.T) {
	ruleSet, err := domain.NewRuleSet([]domain.Rule{})

	require.NoError(t, err)
	assert.Equal(t, 0, ruleSet.Len())
}

func TestRuleSet_RulesPreservesOrder(t *testing.T) {
	rules := []domain.Rule{newTestRule(t, "a"), newTestRule(t, "b"), newTestRule(t, "c")}

	ruleSet, err := domain.NewRuleSet(rules)
	require.NoError(t, err)

	got := ruleSet.Rules()
	assert.Equal(t, "a", got[0].ID())
	assert.Equal(t, "b", got[1].ID())
	assert.Equal(t, "c", got[2].ID())
}

func TestRuleSet_RulesReturnsCopyNotInternalSlice(t *testing.T) {
	rules := []domain.Rule{newTestRule(t, "a")}
	ruleSet, err := domain.NewRuleSet(rules)
	require.NoError(t, err)

	got := ruleSet.Rules()
	got[0] = newTestRule(t, "mutated")

	assert.Equal(t, "a", ruleSet.Rules()[0].ID())
}
