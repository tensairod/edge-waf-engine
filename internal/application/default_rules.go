package application

import "github.com/tensairod/edge-waf-engine/internal/domain"

// NewDefaultRuleSet constrói o conjunto inicial de regras de detecção,
// cobrindo os quatro tipos de ataque do escopo da v1 (RF02-RF05): SQL
// Injection, XSS, Path Traversal e Command Injection.
//
// Este é um ponto de partida com curadoria manual — não pretende ser tão
// abrangente quanto o OWASP Core Rule Set (que tem centenas de regras
// refinadas ao longo de anos de produção real). A partir da Issue 10,
// este conjunto passa a ser carregado de um arquivo rules.yaml externo,
// e este função deixa de ser o único ponto de definição de regras — mas
// serve bem como padrão sensato ("secure by default") caso nenhum
// arquivo de regras customizado seja fornecido.
//
// Cada regra foi testada contra payloads reais do OWASP Testing Guide
// (verdadeiro positivo, RNF03) e contra tráfego legítimo comum
// (verdadeiro negativo, RNF04) — ver default_rules_test.go.
func NewDefaultRuleSet() (domain.RuleSet, error) {
	rules := []ruleDefinition{
		// --- SQL Injection ---
		{
			id:          "sqli-001-union-select",
			category:    domain.CategorySQLInjection,
			pattern:     `(?i)\bunion\b(?:\s+all)?\s+select\b`,
			targets:     []domain.Target{domain.TargetQuery, domain.TargetBody},
			severity:    domain.SeverityHigh,
			description: "Detecta UNION SELECT, usado para extrair dados de outras tabelas.",
		},
		{
			id:          "sqli-002-tautology",
			category:    domain.CategorySQLInjection,
			pattern:     `(?i)\b(or|and)\b\s*['"]?\w+['"]?\s*=\s*['"]?\w+['"]?`,
			targets:     []domain.Target{domain.TargetQuery, domain.TargetBody},
			severity:    domain.SeverityHigh,
			description: `Detecta condições tautológicas clássicas (ex: ' OR '1'='1), usadas para burlar autenticação.`,
		},
		{
			id:          "sqli-003-quote-comment-breakout",
			category:    domain.CategorySQLInjection,
			pattern:     `(?i)['"]\s*(--|#)`,
			targets:     []domain.Target{domain.TargetQuery, domain.TargetBody},
			severity:    domain.SeverityHigh,
			description: `Detecta fechamento de aspas seguido de comentário SQL (ex: admin'--), usado para ignorar o resto da query.`,
		},
		{
			id:          "sqli-004-stacked-query",
			category:    domain.CategorySQLInjection,
			pattern:     `(?i);\s*(drop|delete|truncate|update|insert)\s+`,
			targets:     []domain.Target{domain.TargetQuery, domain.TargetBody},
			severity:    domain.SeverityCritical,
			description: "Detecta stacked queries com comandos destrutivos (ex: '; DROP TABLE users).",
		},

		// --- XSS ---
		{
			id:          "xss-001-script-tag",
			category:    domain.CategoryXSS,
			pattern:     `(?i)<script[\s>]`,
			targets:     []domain.Target{domain.TargetQuery, domain.TargetBody},
			severity:    domain.SeverityHigh,
			description: "Detecta tags <script>, o vetor mais comum de XSS refletido/armazenado.",
		},
		{
			id:          "xss-002-event-handler",
			category:    domain.CategoryXSS,
			pattern:     `(?i)\bon(error|load|click|mouseover|focus)\s*=`,
			targets:     []domain.Target{domain.TargetQuery, domain.TargetBody},
			severity:    domain.SeverityHigh,
			description: `Detecta handlers de evento inline (ex: onerror=, onload=) usados para executar JS sem <script>.`,
		},
		{
			id:          "xss-003-javascript-uri",
			category:    domain.CategoryXSS,
			pattern:     `(?i)javascript:\s*\S`,
			targets:     []domain.Target{domain.TargetQuery, domain.TargetBody},
			severity:    domain.SeverityMedium,
			description: `Detecta URIs "javascript:" usadas em atributos href/src para executar código.`,
		},

		// --- Path Traversal ---
		{
			id:          "pathtrav-001-dot-dot-slash",
			category:    domain.CategoryPathTraversal,
			pattern:     `\.\.[/\\]`,
			targets:     []domain.Target{domain.TargetQuery},
			severity:    domain.SeverityHigh,
			description: `Detecta sequências "../" ou "..\\" usadas para sair do diretório esperado.`,
		},
		{
			id:          "pathtrav-002-encoded-dot-dot-slash",
			category:    domain.CategoryPathTraversal,
			pattern:     `(?i)%2e%2e(%2f|%5c|/)`,
			targets:     []domain.Target{domain.TargetQuery},
			severity:    domain.SeverityHigh,
			description: `Detecta a mesma sequência de path traversal, mas URL-encoded (ex: %2e%2e%2f).`,
		},
		{
			id:          "pathtrav-003-sensitive-file",
			category:    domain.CategoryPathTraversal,
			pattern:     `(?i)(etc/passwd|boot\.ini|win\.ini)`,
			targets:     []domain.Target{domain.TargetQuery},
			severity:    domain.SeverityCritical,
			description: "Detecta referência direta a arquivos sensíveis clássicos de Linux/Windows.",
		},

		// --- Command Injection ---
		{
			id:          "cmdi-001-chained-shell-command",
			category:    domain.CategoryCommandInjection,
			pattern:     `(?i)[;&|]\s*(ls|cat|whoami|id|uname|wget|curl|nc|bash|sh|ping|nslookup)\b`,
			targets:     []domain.Target{domain.TargetQuery, domain.TargetBody},
			severity:    domain.SeverityCritical,
			description: `Detecta encadeamento de shell (;, |, &&) seguido de comando comum usado por atacantes.`,
		},
		{
			id:          "cmdi-002-dollar-subshell",
			category:    domain.CategoryCommandInjection,
			pattern:     `\$\([^)]+\)`,
			targets:     []domain.Target{domain.TargetQuery, domain.TargetBody},
			severity:    domain.SeverityCritical,
			description: `Detecta substituição de comando via $(...) (subshell).`,
		},
		{
			id:          "cmdi-003-backtick-subshell",
			category:    domain.CategoryCommandInjection,
			pattern:     "`[^`]+`",
			targets:     []domain.Target{domain.TargetQuery, domain.TargetBody},
			severity:    domain.SeverityCritical,
			description: "Detecta substituição de comando via crases (subshell estilo legado).",
		},
	}

	return buildRuleSet(rules)
}

// ruleDefinition é um helper interno só para deixar a lista de regras
// acima legível como dados — não expõe API pública nenhuma.
type ruleDefinition struct {
	id          string
	category    domain.Category
	pattern     string
	targets     []domain.Target
	severity    domain.Severity
	description string
}

func buildRuleSet(defs []ruleDefinition) (domain.RuleSet, error) {
	rules := make([]domain.Rule, 0, len(defs))
	for _, def := range defs {
		rule, err := domain.NewRule(def.id, def.category, def.pattern, def.targets, def.severity, def.description)
		if err != nil {
			return domain.RuleSet{}, err
		}
		rules = append(rules, rule)
	}
	return domain.NewRuleSet(rules)
}
