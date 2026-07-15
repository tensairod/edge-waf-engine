// Package rules carrega o conjunto de regras de detecção a partir de um
// arquivo rules.yaml externo (RF07, ADR-003) — em vez de hardcoded no
// binário, permitindo ajustar regras sem recompilar.
package rules

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/tensairod/edge-waf-engine/internal/domain"
)

// yamlRule é a representação intermediária de uma regra tal como
// aparece no arquivo rules.yaml.
//
// Deliberadamente separada de domain.Rule: o formato de um arquivo de
// configuração externo (strings livres vindas de YAML) não deveria
// ditar a forma do tipo de domínio, e vice-versa — essa camada de
// tradução é o único lugar que precisa mudar se o formato do arquivo
// evoluir (ex: adicionar um campo novo) sem tocar no domínio.
type yamlRule struct {
	ID          string   `yaml:"id"`
	Category    string   `yaml:"category"`
	Pattern     string   `yaml:"pattern"`
	Targets     []string `yaml:"targets"`
	Severity    string   `yaml:"severity"`
	Description string   `yaml:"description"`
}

// yamlRulesFile é a raiz do documento rules.yaml: uma lista de regras
// sob a chave "rules".
type yamlRulesFile struct {
	Rules []yamlRule `yaml:"rules"`
}

// LoadRuleSet lê e faz parse de um arquivo rules.yaml no caminho
// informado, devolvendo um domain.RuleSet totalmente validado.
func LoadRuleSet(path string) (domain.RuleSet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return domain.RuleSet{}, fmt.Errorf("rules: erro lendo arquivo %q: %w", path, err)
	}
	return ParseRuleSet(data)
}

// ParseRuleSet faz parse do conteúdo YAML já em memória (útil para
// testes que não precisam tocar o filesystem, e reutilizado por
// LoadRuleSet).
//
// Cada regra malformada — categoria/severidade/target desconhecidos,
// regex inválido, id duplicado — é reportada com uma mensagem que
// identifica QUAL regra falhou (posição no arquivo + id, quando
// disponível), não apenas "erro genérico de configuração".
func ParseRuleSet(data []byte) (domain.RuleSet, error) {
	var file yamlRulesFile
	if err := yaml.Unmarshal(data, &file); err != nil {
		return domain.RuleSet{}, fmt.Errorf("rules: erro fazendo parse do YAML: %w", err)
	}

	rules := make([]domain.Rule, 0, len(file.Rules))
	for i, yr := range file.Rules {
		rule, err := toDomainRule(yr)
		if err != nil {
			return domain.RuleSet{}, fmt.Errorf("rules: regra #%d (id=%q): %w", i+1, yr.ID, err)
		}
		rules = append(rules, rule)
	}

	ruleSet, err := domain.NewRuleSet(rules)
	if err != nil {
		return domain.RuleSet{}, fmt.Errorf("rules: %w", err)
	}
	return ruleSet, nil
}

// toDomainRule converte uma yamlRule (strings livres) em um domain.Rule
// validado.
//
// Note que NÃO validamos categoria/severidade/target aqui antes de
// passar adiante — domain.NewRule já faz exatamente essa validação, com
// mensagens de erro claras. Duplicar essa validação aqui só criaria dois
// lugares para manter sincronizados se a lista de categorias/severidades
// válidas mudar no futuro.
func toDomainRule(yr yamlRule) (domain.Rule, error) {
	targets := make([]domain.Target, 0, len(yr.Targets))
	for _, t := range yr.Targets {
		targets = append(targets, domain.Target(t))
	}

	return domain.NewRule(
		yr.ID,
		domain.Category(yr.Category),
		yr.Pattern,
		targets,
		domain.Severity(yr.Severity),
		yr.Description,
	)
}
