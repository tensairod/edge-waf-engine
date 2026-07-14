package logging_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tensairod/edge-waf-engine/internal/application"
	"github.com/tensairod/edge-waf-engine/internal/domain"
	"github.com/tensairod/edge-waf-engine/internal/infrastructure/logging"
)

func fixedClock() func() time.Time {
	fixed := time.Date(2026, 1, 15, 10, 30, 0, 0, time.UTC)
	return func() time.Time { return fixed }
}

func requestCtx(t *testing.T) domain.RequestContext {
	t.Helper()
	ctx, err := domain.NewRequestContext(domain.RequestContextParams{
		Method: "GET", Path: "/search", SourceIP: "203.0.113.42",
	})
	require.NoError(t, err)
	return ctx
}

func blockVerdict(t *testing.T) domain.Verdict {
	t.Helper()
	verdict, err := domain.NewBlockVerdict([]domain.Violation{
		{
			RuleID:      "sqli-001",
			Category:    domain.CategorySQLInjection,
			Severity:    domain.SeverityHigh,
			Target:      domain.TargetQuery,
			MatchedText: "1 UNION SELECT password FROM users",
		},
	})
	require.NoError(t, err)
	return verdict
}

func parseLogLine(t *testing.T, buf *bytes.Buffer) map[string]any {
	t.Helper()
	var entry map[string]any
	err := json.Unmarshal(buf.Bytes(), &entry)
	require.NoError(t, err, "log deveria ser JSON válido: %s", buf.String())
	return entry
}

func TestBlockLogger_DoesNotLogAllowedRequests(t *testing.T) {
	var buf bytes.Buffer
	logger := logging.NewBlockLogger(&buf, logging.WithClock(fixedClock()))

	logger.LogIfBlocked(requestCtx(t), application.ProcessResult{
		Blocked: false,
		Reason:  application.BlockReasonNone,
	})

	assert.Empty(t, buf.String(), "requisição permitida não deveria gerar nenhum log")
}

func TestBlockLogger_LogsRuleViolation(t *testing.T) {
	var buf bytes.Buffer
	logger := logging.NewBlockLogger(&buf, logging.WithClock(fixedClock()))

	logger.LogIfBlocked(requestCtx(t), application.ProcessResult{
		Blocked: true,
		Reason:  application.BlockReasonRuleViolation,
		Verdict: blockVerdict(t),
		DryRun:  false,
	})

	entry := parseLogLine(t, &buf)
	assert.Equal(t, "203.0.113.42", entry["source_ip"])
	assert.Equal(t, "GET", entry["method"])
	assert.Equal(t, "/search", entry["path"])
	assert.Equal(t, "rule_violation", entry["reason"])
	assert.Equal(t, true, entry["blocked"])
	assert.Equal(t, false, entry["dry_run"])
	assert.Equal(t, "2026-01-15T10:30:00Z", entry["timestamp"])

	violations, ok := entry["violations"].([]any)
	require.True(t, ok, "violations deveria ser uma lista")
	require.Len(t, violations, 1)
	violation := violations[0].(map[string]any)
	assert.Equal(t, "sqli-001", violation["rule_id"])
	assert.Equal(t, "sql_injection", violation["category"])
	assert.Equal(t, "high", violation["severity"])
	assert.Equal(t, "query", violation["target"])
	assert.Equal(t, "1 UNION SELECT password FROM users", violation["matched_text"])
}

func TestBlockLogger_LogsRateLimitWithoutViolationsField(t *testing.T) {
	var buf bytes.Buffer
	logger := logging.NewBlockLogger(&buf, logging.WithClock(fixedClock()))

	logger.LogIfBlocked(requestCtx(t), application.ProcessResult{
		Blocked: true,
		Reason:  application.BlockReasonRateLimit,
	})

	entry := parseLogLine(t, &buf)
	assert.Equal(t, "rate_limit", entry["reason"])
	_, hasViolations := entry["violations"]
	assert.False(t, hasViolations, "bloqueio por rate limit não deveria ter campo 'violations'")
}

func TestBlockLogger_LogsInternalError(t *testing.T) {
	var buf bytes.Buffer
	logger := logging.NewBlockLogger(&buf, logging.WithClock(fixedClock()))

	logger.LogIfBlocked(requestCtx(t), application.ProcessResult{
		Blocked: true,
		Reason:  application.BlockReasonInternalError,
	})

	entry := parseLogLine(t, &buf)
	assert.Equal(t, "internal_error", entry["reason"])
}

func TestBlockLogger_DryRunMessageDiffersFromRealBlock(t *testing.T) {
	var buf bytes.Buffer
	logger := logging.NewBlockLogger(&buf, logging.WithClock(fixedClock()))

	logger.LogIfBlocked(requestCtx(t), application.ProcessResult{
		Blocked: false,
		Reason:  application.BlockReasonRuleViolation,
		Verdict: blockVerdict(t),
		DryRun:  true,
	})

	entry := parseLogLine(t, &buf)
	assert.Equal(t, false, entry["blocked"])
	assert.Equal(t, true, entry["dry_run"])
	assert.Contains(t, entry["msg"], "dry-run")
}

func TestBlockLogger_TruncatesLongMatchedText(t *testing.T) {
	var buf bytes.Buffer
	logger := logging.NewBlockLogger(&buf, logging.WithClock(fixedClock()))

	longPayload := strings.Repeat("A", 500)
	verdict, err := domain.NewBlockVerdict([]domain.Violation{
		{RuleID: "sqli-001", Category: domain.CategorySQLInjection, Severity: domain.SeverityHigh, Target: domain.TargetQuery, MatchedText: longPayload},
	})
	require.NoError(t, err)

	logger.LogIfBlocked(requestCtx(t), application.ProcessResult{
		Blocked: true, Reason: application.BlockReasonRuleViolation, Verdict: verdict,
	})

	entry := parseLogLine(t, &buf)
	violations := entry["violations"].([]any)
	matchedText := violations[0].(map[string]any)["matched_text"].(string)

	assert.LessOrEqual(t, len(matchedText), 220)
	assert.Contains(t, matchedText, "truncado")
	assert.NotContains(t, matchedText, strings.Repeat("A", 500), "não deveria conter o payload inteiro")
}

func TestBlockLogger_ShortMatchedTextIsNotTruncated(t *testing.T) {
	var buf bytes.Buffer
	logger := logging.NewBlockLogger(&buf, logging.WithClock(fixedClock()))

	logger.LogIfBlocked(requestCtx(t), application.ProcessResult{
		Blocked: true, Reason: application.BlockReasonRuleViolation, Verdict: blockVerdict(t),
	})

	entry := parseLogLine(t, &buf)
	violations := entry["violations"].([]any)
	matchedText := violations[0].(map[string]any)["matched_text"].(string)

	assert.Equal(t, "1 UNION SELECT password FROM users", matchedText)
	assert.NotContains(t, matchedText, "truncado")
}
