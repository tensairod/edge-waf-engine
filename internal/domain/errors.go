package domain

import "errors"

// Erros sentinela do domínio. Usar errors.New + variável exportada (em
// vez de fmt.Errorf inline em cada função) permite que código chamador
// distinga o tipo de erro via errors.Is, não apenas via string matching
// frágil na mensagem.
var (
	// errEmptyViolations é retornado por NewBlockVerdict quando chamado
	// sem nenhuma violação — um bloqueio sem motivo é um bug de quem
	// constrói o Verdict, não um estado válido do domínio.
	errEmptyViolations = errors.New("verdict: bloqueio requer ao menos uma violação")
)
