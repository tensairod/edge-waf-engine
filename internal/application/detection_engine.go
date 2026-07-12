// Package application orquestra os tipos puros do domínio para produzir
// comportamento real do WAF — sem, ainda, tocar rede ou filesystem
// diretamente (isso é responsabilidade da camada de Infrastructure).
package application

import (
	"fmt"

	"github.com/tensairod/edge-waf-engine/internal/domain"
)

// DetectionEngine avalia uma RequestContext contra um RuleSet.
//
// Agrega TODAS as regras violadas em um único Verdict — nunca para na
// primeira violação encontrada. Isso é o mesmo princípio de agregação
// de erros já usado no config-validator (ADR-004 daquele projeto):
// um bloqueio pode ter sido causado por múltiplas regras ao mesmo
// tempo, e essa informação completa é o que permite investigar um
// falso positivo depois — só saber "algo bateu" é informação
// insuficiente para depurar um WAF em produção.
type DetectionEngine struct {
	ruleSet domain.RuleSet
}

// NewDetectionEngine constrói um DetectionEngine para o RuleSet informado.
func NewDetectionEngine(ruleSet domain.RuleSet) DetectionEngine {
	return DetectionEngine{ruleSet: ruleSet}
}

// Evaluate avalia a requisição contra todas as regras do RuleSet e
// devolve o Verdict agregado.
func (e DetectionEngine) Evaluate(ctx domain.RequestContext) domain.Verdict {
	var violations []domain.Violation

	for _, rule := range e.ruleSet.Rules() {
		for _, target := range rule.Targets() {
			for _, text := range ctx.ValuesFor(target) {
				if rule.Matches(text) {
					violations = append(violations, domain.Violation{
						RuleID:      rule.ID(),
						Category:    rule.Category(),
						Severity:    rule.Severity(),
						Target:      target,
						MatchedText: text,
					})
				}
			}
		}
	}

	if len(violations) == 0 {
		return domain.NewAllowVerdict()
	}

	verdict, err := domain.NewBlockVerdict(violations)
	if err != nil {
		// Inalcançável em uso normal: violations é garantido não-vazio
		// pelo `if` acima, e NewBlockVerdict só falha com lista vazia.
		// Se isso disparar mesmo assim, é um bug interno grave — panic
		// é apropriado aqui, ao contrário dos erros de configuração
		// esperados do resto do domínio (ver docs/adr para a distinção).
		panic(fmt.Sprintf("edge-waf-engine: invariante violado ao construir Verdict: %v", err))
	}
	return verdict
}
