// Package ratelimiter implementa RateLimiter em memória, usando o
// algoritmo de token bucket — um contador (balde) por IP de origem, que
// reabastece tokens continuamente a uma taxa fixa e é consumido a cada
// requisição permitida.
package ratelimiter

import (
	"fmt"
	"sync"
	"time"
)

// bucket é o estado interno de rate limiting de um único IP.
type bucket struct {
	tokens     float64
	lastRefill time.Time
	lastAccess time.Time
}

// TokenBucketRateLimiter implementa application.RateLimiter em memória.
//
// Trade-off consciente (ver docs/architecture.md, ADR-004): este rate
// limiter mantém estado só na instância local do processo — se o
// edge-waf-engine rodar em múltiplas instâncias atrás de um load
// balancer, cada uma tem sua própria contagem, o que pode permitir um
// atacante distribuir requisições entre instâncias para efetivamente
// multiplicar o limite real. Redis é a evolução natural se/quando isso
// virar um requisito real de escala horizontal.
type TokenBucketRateLimiter struct {
	mu              sync.Mutex
	buckets         map[string]*bucket
	capacity        float64
	refillPerSecond float64
	idleTTL         time.Duration
	now             func() time.Time
}

// Option customiza a construção de um TokenBucketRateLimiter.
type Option func(*TokenBucketRateLimiter)

// WithClock substitui a fonte de tempo usada internamente — existe
// exclusivamente para permitir testes determinísticos (avançar o tempo
// manualmente em vez de usar time.Sleep real, que tornaria os testes
// lentos e potencialmente instáveis sob carga de CI).
func WithClock(now func() time.Time) Option {
	return func(r *TokenBucketRateLimiter) { r.now = now }
}

// NewTokenBucketRateLimiter constrói um TokenBucketRateLimiter.
//
// Args:
//   - capacity: número máximo de tokens (requisições em rajada) que um
//     IP pode acumular.
//   - refillPerSecond: quantos tokens são reabastecidos por segundo.
//   - idleTTL: por quanto tempo o estado de um IP é mantido em memória
//     sem receber nenhuma requisição nova, antes de ser elegível para
//     remoção via Cleanup().
func NewTokenBucketRateLimiter(
	capacity float64, refillPerSecond float64, idleTTL time.Duration, opts ...Option,
) (*TokenBucketRateLimiter, error) {
	if capacity <= 0 {
		return nil, fmt.Errorf("rate limiter: capacity deve ser maior que zero, recebeu %v", capacity)
	}
	if refillPerSecond <= 0 {
		return nil, fmt.Errorf(
			"rate limiter: refillPerSecond deve ser maior que zero, recebeu %v", refillPerSecond,
		)
	}
	if idleTTL <= 0 {
		return nil, fmt.Errorf("rate limiter: idleTTL deve ser maior que zero, recebeu %v", idleTTL)
	}

	r := &TokenBucketRateLimiter{
		buckets:         make(map[string]*bucket),
		capacity:        capacity,
		refillPerSecond: refillPerSecond,
		idleTTL:         idleTTL,
		now:             time.Now,
	}
	for _, opt := range opts {
		opt(r)
	}
	return r, nil
}

// Allow implementa application.RateLimiter.
func (r *TokenBucketRateLimiter) Allow(sourceIP string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := r.now()
	b, exists := r.buckets[sourceIP]
	if !exists {
		// Primeira requisição deste IP: balde começa cheio, menos o
		// token que esta própria requisição consome.
		r.buckets[sourceIP] = &bucket{
			tokens:     r.capacity - 1,
			lastRefill: now,
			lastAccess: now,
		}
		return true
	}

	elapsed := now.Sub(b.lastRefill).Seconds()
	b.tokens = min(r.capacity, b.tokens+elapsed*r.refillPerSecond)
	b.lastRefill = now
	b.lastAccess = now

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// Cleanup remove do mapa interno todo IP sem atividade há mais tempo
// que idleTTL, e retorna quantas entradas foram removidas.
//
// Não é chamado automaticamente — quem sobe o processo (cmd/edge-waf-engine,
// Issue 11) é responsável por chamar isto periodicamente (ex: via
// time.Ticker em uma goroutine), já que o ritmo ideal de limpeza depende
// do volume de tráfego real, algo que este pacote não deveria decidir
// sozinho.
func (r *TokenBucketRateLimiter) Cleanup() int {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := r.now()
	removed := 0
	for ip, b := range r.buckets {
		if now.Sub(b.lastAccess) > r.idleTTL {
			delete(r.buckets, ip)
			removed++
		}
	}
	return removed
}

// Len retorna quantos IPs têm estado de rate limiting atualmente em
// memória — útil para observabilidade e para os próprios testes deste
// pacote.
func (r *TokenBucketRateLimiter) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.buckets)
}
