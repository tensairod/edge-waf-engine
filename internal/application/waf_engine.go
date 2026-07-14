package application

import (
	"fmt"

	"github.com/tensairod/edge-waf-engine/internal/domain"
)

// BlockReason identifica POR QUE o WAFEngine decidiu (ou decidiria, em
// dry-run) bloquear uma requisição.
//
// Deliberadamente NÃO reaproveitamos domain.Category para isso — rate
// limiting e erro interno não são categorias de ataque (SQLi, XSS,
// etc.), são motivos de bloqueio de natureza diferente. Estender
// domain.Category para caber esses casos misturaria dois conceitos que
// o domínio mantém propositalmente separados (ver ADR do Verdict).
type BlockReason string

const (
	BlockReasonNone          BlockReason = ""
	BlockReasonRuleViolation BlockReason = "rule_violation"
	BlockReasonRateLimit     BlockReason = "rate_limit"
	BlockReasonInternalError BlockReason = "internal_error"
)

// FailMode define o comportamento do WAFEngine quando ocorre um erro
// interno inesperado (ex: um panic recuperado vindo do RateLimiter ou
// do DetectionEngine) — não deve ser confundido com uma violação de
// regra normal, que é um funcionamento correto do sistema, não uma
// falha dele.
type FailMode string

const (
	FailOpen   FailMode = "fail_open"
	FailClosed FailMode = "fail_closed"
)

func (f FailMode) isValid() bool {
	return f == FailOpen || f == FailClosed
}

// ProcessResult é o resultado completo do processamento de uma
// requisição pelo WAFEngine.
type ProcessResult struct {
	// Blocked é a decisão EFETIVA final — já considera o modo dry-run.
	// Em dry-run, Blocked é sempre false, mesmo que Reason indique que a
	// requisição teria sido bloqueada — isso permite logar "isto teria
	// sido bloqueado por X" (Issue 9) sem impactar tráfego real, que é
	// o propósito inteiro do modo dry-run (RF09).
	Blocked bool

	// Reason identifica por que a requisição seria (ou foi) bloqueada.
	// BlockReasonNone se nada foi violado.
	Reason BlockReason

	// Verdict é o resultado da avaliação de regras de detecção. Só é
	// relevante quando o processamento chega a rodar o DetectionEngine
	// (ou seja, quando Reason não é BlockReasonRateLimit nem
	// BlockReasonInternalError — nesses dois casos o processamento para
	// antes de avaliar regras).
	Verdict domain.Verdict

	// DryRun indica se o WAFEngine está configurado em modo dry-run.
	DryRun bool
}

// WAFEngine orquestra RateLimiter e DetectionEngine para decidir o
// destino final de uma requisição.
type WAFEngine struct {
	detectionEngine DetectionEngine
	rateLimiter     RateLimiter
	dryRun          bool
	failMode        FailMode
}

// NewWAFEngine constrói um WAFEngine.
//
// Args:
//   - dryRun: se true, o motor nunca bloqueia de fato — só calcula e
//     reporta o que teria sido bloqueado (RF09).
//   - failMode: o que fazer se ocorrer um erro interno inesperado
//     (panic recuperado) durante o processamento.
func NewWAFEngine(
	detectionEngine DetectionEngine,
	rateLimiter RateLimiter,
	dryRun bool,
	failMode FailMode,
) (WAFEngine, error) {
	if !failMode.isValid() {
		return WAFEngine{}, fmt.Errorf("waf engine: fail mode inválido: %q", failMode)
	}
	return WAFEngine{
		detectionEngine: detectionEngine,
		rateLimiter:     rateLimiter,
		dryRun:          dryRun,
		failMode:        failMode,
	}, nil
}

// Process avalia uma requisição contra rate limiting e regras de
// detecção, devolvendo o resultado completo do processamento.
//
// Rate limiting é checado ANTES da detecção de regras: é uma
// verificação muito mais barata (um lookup em mapa) do que rodar
// dezenas de regex contra query/body/headers inteiros — rejeitar cedo
// por excesso de tráfego evita gastar CPU analisando uma requisição que
// já seria descartada de qualquer forma (RNF01).
//
// Qualquer panic vindo do RateLimiter ou do DetectionEngine é
// recuperado aqui — defesa em profundidade: mesmo que ambos os
// componentes sejam projetados para nunca entrar em pânico em uso
// normal, um WAF nunca deveria derrubar o processo do proxy inteiro por
// causa de um bug em uma única regra ou verificação.
func (e WAFEngine) Process(ctx domain.RequestContext) (result ProcessResult) {
	defer func() {
		if recovered := recover(); recovered != nil {
			result = e.buildPanicResult()
		}
	}()

	if !e.rateLimiter.Allow(ctx.SourceIP()) {
		return ProcessResult{
			Blocked: !e.dryRun,
			Reason:  BlockReasonRateLimit,
			DryRun:  e.dryRun,
		}
	}

	verdict := e.detectionEngine.Evaluate(ctx)
	if verdict.IsBlocked() {
		return ProcessResult{
			Blocked: !e.dryRun,
			Reason:  BlockReasonRuleViolation,
			Verdict: verdict,
			DryRun:  e.dryRun,
		}
	}

	return ProcessResult{
		Blocked: false,
		Reason:  BlockReasonNone,
		Verdict: verdict,
		DryRun:  e.dryRun,
	}
}

func (e WAFEngine) buildPanicResult() ProcessResult {
	shouldBlock := e.failMode == FailClosed
	return ProcessResult{
		Blocked: shouldBlock && !e.dryRun,
		Reason:  BlockReasonInternalError,
		DryRun:  e.dryRun,
	}
}
