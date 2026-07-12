// Package domain contém o núcleo puro do edge-waf-engine: os tipos que
// descrevem regras de detecção, requisições normalizadas e veredictos.
//
// Este pacote não importa net/http nem faz nenhum tipo de I/O — isso é
// o que permite testar toda a lógica de negócio (o que é uma regra
// válida, o que constitui uma violação) sem precisar subir um servidor
// HTTP real ou capturar tráfego de verdade.
package domain

import (
	"fmt"
	"regexp"
)

// Category identifica a classe de ataque que uma Rule detecta.
type Category string

const (
	CategorySQLInjection     Category = "sql_injection"
	CategoryXSS              Category = "xss"
	CategoryPathTraversal    Category = "path_traversal"
	CategoryCommandInjection Category = "command_injection"
)

func (c Category) isValid() bool {
	switch c {
	case CategorySQLInjection, CategoryXSS, CategoryPathTraversal, CategoryCommandInjection:
		return true
	default:
		return false
	}
}

// Target identifica qual parte da requisição HTTP uma Rule deve inspecionar.
type Target string

const (
	TargetQuery   Target = "query"
	TargetBody    Target = "body"
	TargetHeaders Target = "headers"
)

func (t Target) isValid() bool {
	switch t {
	case TargetQuery, TargetBody, TargetHeaders:
		return true
	default:
		return false
	}
}

// Severity indica a gravidade de uma violação — usada para logging e
// observabilidade, não para a decisão de bloquear ou não (isso é binário:
// qualquer regra violada gera um Verdict de bloqueio, ver Verdict).
type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

func (s Severity) isValid() bool {
	switch s {
	case SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
		return true
	default:
		return false
	}
}

// Rule representa uma assinatura de detecção de ataque.
//
// Uma Rule descreve O QUE detectar (padrão, categoria, alvo) — não COMO a
// requisição é obtida nem O QUE fazer com o resultado. Isso é o que
// mantém o domínio testável isoladamente (ver ADR-002 em docs/adr/).
//
// Instâncias só devem ser criadas via NewRule, nunca via struct literal
// direto — isso garante que toda Rule em memória já passou pela
// validação fail-fast (regex compilado, categoria/target/severidade
// válidos), sem exceção.
type Rule struct {
	id          string
	category    Category
	pattern     *regexp.Regexp
	targets     []Target
	severity    Severity
	description string
}

// NewRule constrói uma Rule validando todos os invariantes na criação.
//
// Retorna um erro (não panic) porque regras normalmente vêm de um
// arquivo de configuração externo (rules.yaml, ver Issue 10) — uma regra
// malformada é um erro de configuração esperado, não uma condição
// excepcional do programa.
func NewRule(
	id string,
	category Category,
	pattern string,
	targets []Target,
	severity Severity,
	description string,
) (Rule, error) {
	if id == "" {
		return Rule{}, fmt.Errorf("rule: id não pode ser vazio")
	}
	if !category.isValid() {
		return Rule{}, fmt.Errorf("rule %q: categoria inválida %q", id, category)
	}
	if len(targets) == 0 {
		return Rule{}, fmt.Errorf("rule %q: precisa de ao menos um target de inspeção", id)
	}
	for _, t := range targets {
		if !t.isValid() {
			return Rule{}, fmt.Errorf("rule %q: target inválido %q", id, t)
		}
	}
	if !severity.isValid() {
		return Rule{}, fmt.Errorf("rule %q: severidade inválida %q", id, severity)
	}

	compiled, err := regexp.Compile(pattern)
	if err != nil {
		return Rule{}, fmt.Errorf("rule %q: padrão regex inválido: %w", id, err)
	}

	targetsCopy := make([]Target, len(targets))
	copy(targetsCopy, targets)

	return Rule{
		id:          id,
		category:    category,
		pattern:     compiled,
		targets:     targetsCopy,
		severity:    severity,
		description: description,
	}, nil
}

// ID retorna o identificador único da regra.
func (r Rule) ID() string { return r.id }

// Category retorna a categoria de ataque que esta regra detecta.
func (r Rule) Category() Category { return r.category }

// Severity retorna a severidade configurada para esta regra.
func (r Rule) Severity() Severity { return r.severity }

// Description retorna a descrição legível da regra.
func (r Rule) Description() string { return r.description }

// HasTarget retorna true se a regra deve inspecionar o Target informado.
func (r Rule) HasTarget(target Target) bool {
	for _, t := range r.targets {
		if t == target {
			return true
		}
	}
	return false
}

// Targets retorna todos os Targets que esta regra deve inspecionar.
func (r Rule) Targets() []Target {
	result := make([]Target, len(r.targets))
	copy(result, r.targets)
	return result
}

// Matches retorna true se o texto fornecido bate com o padrão da regra.
func (r Rule) Matches(text string) bool {
	return r.pattern.MatchString(text)
}
