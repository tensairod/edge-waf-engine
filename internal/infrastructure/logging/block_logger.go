// Package logging implementa o registro estruturado de requisições
// bloqueadas pelo WAF (RF08), usando log/slog (stdlib) para saída JSON.
package logging

import (
	"io"
	"log/slog"
	"time"

	"github.com/tensairod/edge-waf-engine/internal/application"
	"github.com/tensairod/edge-waf-engine/internal/domain"
)

// maxMatchedTextLength limita o tamanho do texto que disparou uma regra
// antes de logá-lo — evita que uma única requisição maliciosa com um
// payload gigante infle o volume de log descontroladamente.
const maxMatchedTextLength = 200

// BlockLogger registra estruturadamente toda requisição bloqueada (ou
// que teria sido bloqueada, em dry-run) — nunca requisições permitidas
// normalmente, para não gerar volume de log desnecessário sobre tráfego
// legítimo.
type BlockLogger struct {
	logger *slog.Logger
	now    func() time.Time
}

// Option customiza a construção de um BlockLogger.
type Option func(*BlockLogger)

// WithClock substitui a fonte de tempo usada internamente — existe
// para permitir testes determinísticos, mesmo padrão já usado em
// internal/infrastructure/ratelimiter.
func WithClock(now func() time.Time) Option {
	return func(l *BlockLogger) { l.now = now }
}

// NewBlockLogger constrói um BlockLogger que escreve JSON estruturado
// em w (tipicamente os.Stdout em produção, ou um bytes.Buffer em testes).
func NewBlockLogger(w io.Writer, opts ...Option) *BlockLogger {
	l := &BlockLogger{
		logger: slog.New(slog.NewJSONHandler(w, nil)),
		now:    time.Now,
	}
	for _, opt := range opts {
		opt(l)
	}
	return l
}

// LogIfBlocked registra a requisição se, e somente se, ela tiver sido
// bloqueada de fato OU seria bloqueada não fosse o modo dry-run.
//
// A decisão principal de "vale a pena chamar isso" já é filtrada por
// quem chama (WAFReverseProxy só invoca este método quando
// result.Reason != BlockReasonNone) — o guard abaixo é defesa em
// profundidade, não a única linha de proteção: qualquer chamador futuro
// que invoque LogIfBlocked diretamente, sem passar pelo filtro do
// proxy, ainda assim não gera log espúrio para requisições permitidas.
//
// IMPORTANTE (privacidade/segurança): o campo `matched_text` do log
// contém um trecho literal do conteúdo da requisição que disparou uma
// regra — isso pode incluir dados pessoais caso uma regra dispare como
// falso positivo sobre um valor legítimo sensível (ex: um nome de
// usuário). Isto é uma característica inerente a qualquer WAF baseado
// em log de payload (ModSecurity, WAFs comerciais, todos fazem o
// mesmo), mas relevante o suficiente para operadores de sistemas com
// requisitos de compliance (GDPR, LGPD) considerarem antes de habilitar
// retenção de log de longo prazo sem uma política de expurgo.
func (l *BlockLogger) LogIfBlocked(ctx domain.RequestContext, result application.ProcessResult) {
	if result.Reason == application.BlockReasonNone {
		return
	}

	attrs := []any{
		slog.String("timestamp", l.now().UTC().Format(time.RFC3339)),
		slog.String("source_ip", ctx.SourceIP()),
		slog.String("method", ctx.Method()),
		slog.String("path", ctx.Path()),
		slog.String("reason", string(result.Reason)),
		slog.Bool("blocked", result.Blocked),
		slog.Bool("dry_run", result.DryRun),
	}

	if result.Reason == application.BlockReasonRuleViolation {
		attrs = append(attrs, slog.Any("violations", violationLogEntries(result.Verdict)))
	}

	message := "requisição bloqueada"
	if result.DryRun {
		message = "requisição seria bloqueada (dry-run)"
	}
	l.logger.Warn(message, attrs...)
}

// violationEntry é a representação serializável de uma domain.Violation
// no log — um tipo próprio em vez de expor domain.Violation diretamente
// mantém o formato do log estável mesmo que o tipo de domínio mude.
type violationEntry struct {
	RuleID      string `json:"rule_id"`
	Category    string `json:"category"`
	Severity    string `json:"severity"`
	Target      string `json:"target"`
	MatchedText string `json:"matched_text"`
}

func violationLogEntries(verdict domain.Verdict) []violationEntry {
	violations := verdict.Violations()
	entries := make([]violationEntry, 0, len(violations))
	for _, v := range violations {
		entries = append(entries, violationEntry{
			RuleID:      v.RuleID,
			Category:    string(v.Category),
			Severity:    string(v.Severity),
			Target:      string(v.Target),
			MatchedText: truncate(v.MatchedText, maxMatchedTextLength),
		})
	}
	return entries
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "...(truncado)"
}
