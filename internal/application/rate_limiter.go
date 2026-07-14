package application

// RateLimiter decide se uma requisição vinda de um IP de origem deve
// prosseguir ou ser bloqueada por excesso de tráfego (RF06).
//
// Definida aqui, na camada de Application — não em Infrastructure —
// pelo mesmo motivo que ConfigSource vive na camada de Application no
// projeto config-validator: é o WAFEngine (Issue 7) que depende desta
// abstração; a implementação concreta (ex: token bucket em memória, ou
// futuramente Redis) vive em Infrastructure e a implementa. Isso é
// Dependency Inversion: o orquestrador de alto nível não depende de
// detalhes de baixo nível sobre COMO o rate limiting é implementado.
type RateLimiter interface {
	// Allow retorna true se a requisição do IP informado pode prosseguir
	// agora, e false se o limite de taxa configurado foi excedido.
	Allow(sourceIP string) bool
}
