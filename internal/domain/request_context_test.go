package domain_test

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/SEU_USUARIO/edge-waf-engine/internal/domain"
)

func validParams() domain.RequestContextParams {
	return domain.RequestContextParams{
		Method:   "GET",
		Path:     "/search",
		SourceIP: "203.0.113.42",
		Query:    url.Values{"q": {"hello"}},
		Headers:  map[string][]string{"User-Agent": {"curl/8.0"}},
		Body:     "",
	}
}

func TestNewRequestContext_HappyPath(t *testing.T) {
	ctx, err := domain.NewRequestContext(validParams())

	require.NoError(t, err)
	assert.Equal(t, "GET", ctx.Method())
	assert.Equal(t, "/search", ctx.Path())
	assert.Equal(t, "203.0.113.42", ctx.SourceIP())
}

func TestNewRequestContext_EmptyMethod(t *testing.T) {
	params := validParams()
	params.Method = ""

	_, err := domain.NewRequestContext(params)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "method não pode ser vazio")
}

func TestNewRequestContext_EmptyPath(t *testing.T) {
	params := validParams()
	params.Path = ""

	_, err := domain.NewRequestContext(params)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "path não pode ser vazio")
}

func TestNewRequestContext_PathWithoutLeadingSlash(t *testing.T) {
	params := validParams()
	params.Path = "search"

	_, err := domain.NewRequestContext(params)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "precisa começar com '/'")
}

func TestNewRequestContext_EmptySourceIP(t *testing.T) {
	params := validParams()
	params.SourceIP = ""

	_, err := domain.NewRequestContext(params)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "sourceIP não pode ser vazio")
}

func TestNewRequestContext_InvalidSourceIP(t *testing.T) {
	params := validParams()
	params.SourceIP = "not-an-ip"

	_, err := domain.NewRequestContext(params)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "não é um endereço IP válido")
}

func TestNewRequestContext_IPv6SourceIPIsValid(t *testing.T) {
	params := validParams()
	params.SourceIP = "2001:db8::1"

	_, err := domain.NewRequestContext(params)

	require.NoError(t, err)
}

func TestRequestContext_ValuesForQuery(t *testing.T) {
	params := validParams()
	params.Query = url.Values{"q": {"1' OR '1'='1"}, "page": {"2"}}

	ctx, err := domain.NewRequestContext(params)
	require.NoError(t, err)

	values := ctx.ValuesFor(domain.TargetQuery)
	assert.ElementsMatch(t, []string{"1' OR '1'='1", "2"}, values)
}

func TestRequestContext_ValuesForBody(t *testing.T) {
	params := validParams()
	params.Body = "<script>alert(1)</script>"

	ctx, err := domain.NewRequestContext(params)
	require.NoError(t, err)

	assert.Equal(t, []string{"<script>alert(1)</script>"}, ctx.ValuesFor(domain.TargetBody))
}

func TestRequestContext_ValuesForHeaders(t *testing.T) {
	params := validParams()
	params.Headers = map[string][]string{
		"X-Forwarded-For": {"1.2.3.4"},
		"Cookie":          {"session=abc"},
	}

	ctx, err := domain.NewRequestContext(params)
	require.NoError(t, err)

	values := ctx.ValuesFor(domain.TargetHeaders)
	assert.ElementsMatch(t, []string{"1.2.3.4", "session=abc"}, values)
}

func TestRequestContext_ValuesForUnknownTargetReturnsNil(t *testing.T) {
	ctx, err := domain.NewRequestContext(validParams())
	require.NoError(t, err)

	assert.Nil(t, ctx.ValuesFor(domain.Target("nao_existe")))
}

func TestNewRequestContext_QueryIsCopiedNotAliased(t *testing.T) {
	query := url.Values{"q": {"original"}}
	params := validParams()
	params.Query = query

	ctx, err := domain.NewRequestContext(params)
	require.NoError(t, err)

	query["q"][0] = "mutated"

	assert.Equal(t, []string{"original"}, ctx.ValuesFor(domain.TargetQuery))
}

func TestNewRequestContext_HeadersAreCopiedNotAliased(t *testing.T) {
	headers := map[string][]string{"X-Test": {"original"}}
	params := validParams()
	params.Headers = headers

	ctx, err := domain.NewRequestContext(params)
	require.NoError(t, err)

	headers["X-Test"][0] = "mutated"

	assert.Equal(t, []string{"original"}, ctx.ValuesFor(domain.TargetHeaders))
}

func TestNewRequestContext_NilQueryAndHeadersAreHandled(t *testing.T) {
	params := validParams()
	params.Query = nil
	params.Headers = nil

	ctx, err := domain.NewRequestContext(params)

	require.NoError(t, err)
	assert.Empty(t, ctx.ValuesFor(domain.TargetQuery))
	assert.Empty(t, ctx.ValuesFor(domain.TargetHeaders))
}
