// Package proxy contém o reverse proxy HTTP real que fica na borda,
// inspecionando cada requisição através do WAFEngine antes de decidir
// se ela deve chegar ao backend.
package proxy

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/tensairod/edge-waf-engine/internal/application"
	"github.com/tensairod/edge-waf-engine/internal/domain"
)

// WAFReverseProxy é um http.Handler que inspeciona cada requisição
// através de um WAFEngine antes de encaminhá-la (ou não) ao backend real.
type WAFReverseProxy struct {
	engine       application.WAFEngine
	reverseProxy *httputil.ReverseProxy
}

// NewWAFReverseProxy constrói um WAFReverseProxy que encaminha
// requisições permitidas para backendURL.
func NewWAFReverseProxy(backendURL *url.URL, engine application.WAFEngine) *WAFReverseProxy {
	return &WAFReverseProxy{
		engine:       engine,
		reverseProxy: httputil.NewSingleHostReverseProxy(backendURL),
	}
}

// ServeHTTP implementa http.Handler.
//
// Se a tradução da requisição real para RequestContext falhar (caso
// extremamente raro — ex: RemoteAddr em formato inesperado), a
// requisição é rejeitada com 400: um WAF que não conseguiu nem entender
// a requisição não deveria arriscar encaminhá-la ao backend sem
// inspeção nenhuma.
func (p *WAFReverseProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx, err := buildRequestContext(r)
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	result := p.engine.Process(ctx)
	if result.Blocked {
		// Mensagem deliberadamente genérica: não expõe qual regra foi
		// violada nem por quê — essa informação vai para o log
		// estruturado (Issue 9), não para a resposta HTTP, para não dar
		// a quem está atacando um retorno útil sobre qual payload testar
		// em seguida.
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	p.reverseProxy.ServeHTTP(w, r)
}

// buildRequestContext traduz um *http.Request real em um
// domain.RequestContext, a fronteira entre o mundo de rede real
// (net/http) e o domínio puro do WAF.
func buildRequestContext(r *http.Request) (domain.RequestContext, error) {
	sourceIP, err := extractSourceIP(r)
	if err != nil {
		return domain.RequestContext{}, err
	}

	body, err := readAndRestoreBody(r)
	if err != nil {
		return domain.RequestContext{}, err
	}

	return domain.NewRequestContext(domain.RequestContextParams{
		Method:   r.Method,
		Path:     r.URL.Path,
		SourceIP: sourceIP,
		Query:    r.URL.Query(),
		Headers:  r.Header,
		Body:     body,
	})
}

// extractSourceIP extrai o endereço IP de origem de r.RemoteAddr, que
// normalmente vem no formato "IP:porta".
//
// Deliberadamente NÃO confia em headers como X-Forwarded-For — esses
// headers são fornecidos pelo próprio cliente e podem ser forjados
// livremente; usá-los sem uma lista de proxies confiáveis configurada
// abriria uma forma trivial de burlar o rate limiting (bastaria mandar
// um X-Forwarded-For diferente a cada requisição). Suporte a proxies
// confiáveis fica como evolução futura documentada, não implementada
// às cegas aqui.
func extractSourceIP(r *http.Request) (string, error) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		if net.ParseIP(r.RemoteAddr) != nil {
			return r.RemoteAddr, nil
		}
		return "", fmt.Errorf(
			"proxy: não foi possível extrair IP de origem de %q: %w", r.RemoteAddr, err,
		)
	}
	return host, nil
}

// readAndRestoreBody lê o corpo da requisição para inspeção do WAF, e
// em seguida RESTAURA r.Body — se isso não fosse feito, o
// httputil.ReverseProxy encaminharia um corpo vazio ao backend, já que
// io.Reader só pode ser lido uma vez.
func readAndRestoreBody(r *http.Request) (string, error) {
	if r.Body == nil {
		return "", nil
	}
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		return "", fmt.Errorf("proxy: erro lendo corpo da requisição: %w", err)
	}
	r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	return string(bodyBytes), nil
}
