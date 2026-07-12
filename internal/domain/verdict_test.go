package domain_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/SEU_USUARIO/edge-waf-engine/internal/domain"
)

func TestNewAllowVerdict(t *testing.T) {
	verdict := domain.NewAllowVerdict()

	assert.Equal(t, domain.DecisionAllow, verdict.Decision())
	assert.False(t, verdict.IsBlocked())
	assert.Empty(t, verdict.Violations())
}

func TestNewBlockVerdict_HappyPath(t *testing.T) {
	violations := []domain.Violation{
		{RuleID: "sqli-001", Category: domain.CategorySQLInjection, Severity: domain.SeverityHigh, Target: domain.TargetQuery, MatchedText: "UNION SELECT"},
		{RuleID: "xss-001", Category: domain.CategoryXSS, Severity: domain.SeverityMedium, Target: domain.TargetBody, MatchedText: "<script>"},
	}

	verdict, err := domain.NewBlockVerdict(violations)

	require.NoError(t, err)
	assert.Equal(t, domain.DecisionBlock, verdict.Decision())
	assert.True(t, verdict.IsBlocked())
	assert.Len(t, verdict.Violations(), 2)
}

func TestNewBlockVerdict_EmptyViolationsFails(t *testing.T) {
	_, err := domain.NewBlockVerdict([]domain.Violation{})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "ao menos uma violação")
}

func TestNewBlockVerdict_ViolationsSliceIsCopiedNotAliased(t *testing.T) {
	violations := []domain.Violation{
		{RuleID: "rule-1", Category: domain.CategorySQLInjection, Severity: domain.SeverityHigh, Target: domain.TargetQuery, MatchedText: "x"},
	}

	verdict, err := domain.NewBlockVerdict(violations)
	require.NoError(t, err)

	violations[0].RuleID = "mutated"

	assert.Equal(t, "rule-1", verdict.Violations()[0].RuleID)
}

func TestVerdict_ViolationsReturnsCopyNotInternalSlice(t *testing.T) {
	violations := []domain.Violation{
		{RuleID: "rule-1", Category: domain.CategorySQLInjection, Severity: domain.SeverityHigh, Target: domain.TargetQuery, MatchedText: "x"},
	}
	verdict, err := domain.NewBlockVerdict(violations)
	require.NoError(t, err)

	got := verdict.Violations()
	got[0].RuleID = "mutated_externally"

	assert.Equal(t, "rule-1", verdict.Violations()[0].RuleID)
}
