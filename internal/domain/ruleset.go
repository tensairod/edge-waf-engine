package domain

import "fmt"

// RuleSet é uma coleção de Rules avaliadas em conjunto contra uma
// RequestContext.
//
// Assim como Rule e RequestContext, um RuleSet só é construído via
// NewRuleSet — isso garante que todo RuleSet em memória já teve seus
// IDs de regra validados como únicos, sem exceção.
type RuleSet struct {
	rules []Rule
}

// NewRuleSet constrói um RuleSet a partir de uma lista de Rules,
// validando que não há IDs duplicados.
func NewRuleSet(rules []Rule) (RuleSet, error) {
	seen := make(map[string]struct{}, len(rules))
	for _, r := range rules {
		if _, ok := seen[r.ID()]; ok {
			return RuleSet{}, fmt.Errorf("ruleset: regra duplicada com id %q", r.ID())
		}
		seen[r.ID()] = struct{}{}
	}

	rulesCopy := make([]Rule, len(rules))
	copy(rulesCopy, rules)
	return RuleSet{rules: rulesCopy}, nil
}

// Rules retorna todas as regras do conjunto, em ordem estável (a mesma
// ordem em que foram passadas para NewRuleSet).
func (rs RuleSet) Rules() []Rule {
	result := make([]Rule, len(rs.rules))
	copy(result, rs.rules)
	return result
}

// Len retorna o número de regras no conjunto.
func (rs RuleSet) Len() int { return len(rs.rules) }
