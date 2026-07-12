package domain

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// RequestContext é uma representação normalizada de uma requisição HTTP,
// desacoplada de net/http.
//
// O DetectionEngine (Issue 4) opera inteiramente sobre este tipo — isso
// permite testar regras de detecção contra requisições construídas à
// mão, sem precisar subir um servidor HTTP real. A tradução de uma
// *http.Request real para um RequestContext é responsabilidade da
// camada de Infrastructure (ver internal/infrastructure/proxy, Issue 8),
// não deste pacote.
type RequestContext struct {
	method   string
	path     string
	sourceIP string
	query    url.Values
	headers  map[string][]string
	body     string
}

// RequestContextParams agrupa os argumentos de NewRequestContext.
//
// Usar uma struct de parâmetros (em vez de vários argumentos posicionais)
// evita erros de troca de ordem entre campos do mesmo tipo (ex: Method e
// Path, ambos string) e deixa o call site autoexplicativo pelos nomes
// dos campos.
type RequestContextParams struct {
	Method   string
	Path     string
	SourceIP string
	Query    url.Values
	Headers  map[string][]string
	Body     string
}

// NewRequestContext constrói um RequestContext validando os invariantes
// mínimos necessários para o motor de detecção funcionar corretamente.
func NewRequestContext(params RequestContextParams) (RequestContext, error) {
	if params.Method == "" {
		return RequestContext{}, fmt.Errorf("request context: method não pode ser vazio")
	}
	if params.Path == "" {
		return RequestContext{}, fmt.Errorf("request context: path não pode ser vazio")
	}
	if !strings.HasPrefix(params.Path, "/") {
		return RequestContext{}, fmt.Errorf(
			"request context: path %q precisa começar com '/'", params.Path,
		)
	}
	if params.SourceIP == "" {
		return RequestContext{}, fmt.Errorf("request context: sourceIP não pode ser vazio")
	}
	if net.ParseIP(params.SourceIP) == nil {
		return RequestContext{}, fmt.Errorf(
			"request context: sourceIP %q não é um endereço IP válido", params.SourceIP,
		)
	}

	// Copia query e headers para não reter referências aos mappings do
	// chamador — mesma preocupação de isolamento já aplicada a
	// Rule.targets (ver internal/domain/rule.go).
	query := url.Values{}
	for key, values := range params.Query {
		query[key] = append([]string{}, values...)
	}

	headers := make(map[string][]string, len(params.Headers))
	for key, values := range params.Headers {
		headers[key] = append([]string{}, values...)
	}

	return RequestContext{
		method:   params.Method,
		path:     params.Path,
		sourceIP: params.SourceIP,
		query:    query,
		headers:  headers,
		body:     params.Body,
	}, nil
}

// Method retorna o método HTTP da requisição (GET, POST, etc.).
func (r RequestContext) Method() string { return r.method }

// Path retorna o caminho da requisição (sem query string).
func (r RequestContext) Path() string { return r.path }

// SourceIP retorna o endereço IP de origem da requisição.
func (r RequestContext) SourceIP() string { return r.sourceIP }

// Body retorna o corpo bruto da requisição.
func (r RequestContext) Body() string { return r.body }

// ValuesFor retorna todos os valores textuais associados a um Target
// específico da requisição — é isso que o DetectionEngine varre contra
// cada Rule.
//
// A ordem dos valores retornados para TargetQuery e TargetHeaders NÃO é
// determinística (percorre um map internamente); isso é irrelevante
// para detecção (basta UM valor bater com a regra), mas testes que
// comparam o resultado devem usar comparação "contém os mesmos
// elementos", não igualdade de slice ordenada.
func (r RequestContext) ValuesFor(target Target) []string {
	switch target {
	case TargetQuery:
		values := make([]string, 0, len(r.query))
		for _, vs := range r.query {
			values = append(values, vs...)
		}
		return values
	case TargetBody:
		return []string{r.body}
	case TargetHeaders:
		values := make([]string, 0, len(r.headers))
		for _, vs := range r.headers {
			values = append(values, vs...)
		}
		return values
	default:
		return nil
	}
}
