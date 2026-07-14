package ratelimiter_test

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tensairod/edge-waf-engine/internal/infrastructure/ratelimiter"
)

// fakeClock permite controlar o tempo manualmente nos testes, evitando
// time.Sleep real (que tornaria os testes lentos e potencialmente
// instáveis sob carga de CI).
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock(start time.Time) *fakeClock {
	return &fakeClock{now: start}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func TestNewTokenBucketRateLimiter_ValidationErrors(t *testing.T) {
	_, err := ratelimiter.NewTokenBucketRateLimiter(0, 1, time.Minute)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "capacity deve ser maior que zero")

	_, err = ratelimiter.NewTokenBucketRateLimiter(10, 0, time.Minute)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "refillPerSecond deve ser maior que zero")

	_, err = ratelimiter.NewTokenBucketRateLimiter(10, 1, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "idleTTL deve ser maior que zero")
}

func TestTokenBucketRateLimiter_AllowsUpToCapacityThenBlocks(t *testing.T) {
	clock := newFakeClock(time.Now())
	limiter, err := ratelimiter.NewTokenBucketRateLimiter(
		3, 1, time.Minute, ratelimiter.WithClock(clock.Now),
	)
	require.NoError(t, err)

	assert.True(t, limiter.Allow("203.0.113.1"))
	assert.True(t, limiter.Allow("203.0.113.1"))
	assert.True(t, limiter.Allow("203.0.113.1"))
	assert.False(t, limiter.Allow("203.0.113.1"), "4ª requisição deveria exceder a capacidade de 3")
}

func TestTokenBucketRateLimiter_RefillsOverTime(t *testing.T) {
	clock := newFakeClock(time.Now())
	limiter, err := ratelimiter.NewTokenBucketRateLimiter(
		2, 1, time.Minute, ratelimiter.WithClock(clock.Now),
	)
	require.NoError(t, err)

	assert.True(t, limiter.Allow("203.0.113.1"))
	assert.True(t, limiter.Allow("203.0.113.1"))
	assert.False(t, limiter.Allow("203.0.113.1"), "capacidade de 2 já deveria estar esgotada")

	clock.Advance(1 * time.Second) // refillPerSecond=1 -> reabastece 1 token

	assert.True(t, limiter.Allow("203.0.113.1"), "deveria ter 1 token novo após 1s")
	assert.False(t, limiter.Allow("203.0.113.1"), "token novo já foi consumido")
}

func TestTokenBucketRateLimiter_DoesNotExceedCapacityOnLongIdlePeriod(t *testing.T) {
	clock := newFakeClock(time.Now())
	limiter, err := ratelimiter.NewTokenBucketRateLimiter(
		2, 1, time.Minute, ratelimiter.WithClock(clock.Now),
	)
	require.NoError(t, err)

	require.True(t, limiter.Allow("203.0.113.1"))

	// Avança 1 hora — mesmo com refillPerSecond=1, o balde não deveria
	// acumular 3600 tokens; deve ficar travado no teto de `capacity`.
	clock.Advance(1 * time.Hour)

	assert.True(t, limiter.Allow("203.0.113.1"))
	assert.True(t, limiter.Allow("203.0.113.1"))
	assert.False(t, limiter.Allow("203.0.113.1"), "nao deveria exceder a capacidade mesmo apos ficar ocioso")
}

func TestTokenBucketRateLimiter_DifferentIPsHaveIndependentBuckets(t *testing.T) {
	clock := newFakeClock(time.Now())
	limiter, err := ratelimiter.NewTokenBucketRateLimiter(
		1, 1, time.Minute, ratelimiter.WithClock(clock.Now),
	)
	require.NoError(t, err)

	assert.True(t, limiter.Allow("203.0.113.1"))
	assert.False(t, limiter.Allow("203.0.113.1"), "IP 1 já deveria estar sem tokens")

	assert.True(t, limiter.Allow("203.0.113.2"), "IP 2 deveria ter seu próprio balde, independente do IP 1")
}

func TestTokenBucketRateLimiter_Len(t *testing.T) {
	clock := newFakeClock(time.Now())
	limiter, err := ratelimiter.NewTokenBucketRateLimiter(
		5, 1, time.Minute, ratelimiter.WithClock(clock.Now),
	)
	require.NoError(t, err)

	assert.Equal(t, 0, limiter.Len())

	limiter.Allow("203.0.113.1")
	limiter.Allow("203.0.113.2")
	limiter.Allow("203.0.113.1") // mesmo IP de novo, não deveria criar entrada nova

	assert.Equal(t, 2, limiter.Len())
}

func TestTokenBucketRateLimiter_CleanupRemovesOnlyIdleEntries(t *testing.T) {
	clock := newFakeClock(time.Now())
	limiter, err := ratelimiter.NewTokenBucketRateLimiter(
		5, 1, 10*time.Second, ratelimiter.WithClock(clock.Now),
	)
	require.NoError(t, err)

	limiter.Allow("203.0.113.1") // vai ficar ocioso
	clock.Advance(5 * time.Second)
	limiter.Allow("203.0.113.2") // mais recente, não deveria ser removido ainda

	clock.Advance(6 * time.Second) // IP 1 está ocioso há 11s (> idleTTL de 10s); IP 2 há 6s

	removed := limiter.Cleanup()

	assert.Equal(t, 1, removed)
	assert.Equal(t, 1, limiter.Len())
}

func TestTokenBucketRateLimiter_CleanupRemovesNothingWhenAllActive(t *testing.T) {
	clock := newFakeClock(time.Now())
	limiter, err := ratelimiter.NewTokenBucketRateLimiter(
		5, 1, time.Minute, ratelimiter.WithClock(clock.Now),
	)
	require.NoError(t, err)

	limiter.Allow("203.0.113.1")
	limiter.Allow("203.0.113.2")

	removed := limiter.Cleanup()

	assert.Equal(t, 0, removed)
	assert.Equal(t, 2, limiter.Len())
}

func TestTokenBucketRateLimiter_ConcurrentAccessIsSafe(t *testing.T) {
	// Roda com `go test -race` para validar de verdade a ausência de
	// data races no acesso concorrente ao mapa interno de buckets.
	limiter, err := ratelimiter.NewTokenBucketRateLimiter(1000, 100, time.Minute)
	require.NoError(t, err)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				limiter.Allow("203.0.113.1")
			}
		}(i)
	}
	wg.Wait()

	assert.Equal(t, 1, limiter.Len())
}
