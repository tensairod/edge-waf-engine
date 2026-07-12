package domain

// Decision indica o resultado final da avaliação de uma requisição:
// permitir ou bloquear.
type Decision string

const (
	DecisionAllow Decision = "allow"
	DecisionBlock Decision = "block"
)

// Violation representa uma única regra violada por uma requisição —
// usado tanto para a decisão final quanto para logging estruturado
// (RF08, Issue 9).
type Violation struct {
	RuleID      string
	Category    Category
	Severity    Severity
	Target      Target
	MatchedText string
}

// Verdict é o resultado da avaliação de uma RequestContext contra um
// RuleSet: uma decisão (Allow/Block) e a lista de TODAS as violações
// encontradas — nunca só a primeira.
//
// Agregar todas as violações (em vez de parar na primeira regra
// violada) é o mesmo princípio de design usado no config-validator para
// erros de validação: um único bloqueio pode ter sido causado por
// múltiplas regras ao mesmo tempo, e isso é informação valiosa para
// quem for investigar um falso positivo depois.
type Verdict struct {
	decision   Decision
	violations []Violation
}

// NewAllowVerdict constrói um Verdict de permissão, sem violações.
func NewAllowVerdict() Verdict {
	return Verdict{decision: DecisionAllow}
}

// NewBlockVerdict constrói um Verdict de bloqueio a partir de uma lista
// de violações. Requer ao menos uma violação — um bloqueio sem motivo
// nenhum é um bug de quem está construindo o Verdict, não um estado
// válido do domínio.
func NewBlockVerdict(violations []Violation) (Verdict, error) {
	if len(violations) == 0 {
		return Verdict{}, errEmptyViolations
	}
	violationsCopy := make([]Violation, len(violations))
	copy(violationsCopy, violations)
	return Verdict{decision: DecisionBlock, violations: violationsCopy}, nil
}

// Decision retorna a decisão final (Allow ou Block).
func (v Verdict) Decision() Decision { return v.decision }

// IsBlocked retorna true se a decisão final foi bloquear a requisição.
func (v Verdict) IsBlocked() bool { return v.decision == DecisionBlock }

// Violations retorna todas as violações que levaram ao bloqueio (vazio
// se a decisão foi Allow).
func (v Verdict) Violations() []Violation {
	result := make([]Violation, len(v.violations))
	copy(result, v.violations)
	return result
}
