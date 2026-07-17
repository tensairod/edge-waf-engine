// Command edge-waf-engine sobe o reverse proxy WAF configurável via
// flags de linha de comando.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/tensairod/edge-waf-engine/internal/application"
	"github.com/tensairod/edge-waf-engine/internal/infrastructure/logging"
	"github.com/tensairod/edge-waf-engine/internal/infrastructure/proxy"
	"github.com/tensairod/edge-waf-engine/internal/infrastructure/ratelimiter"
	"github.com/tensairod/edge-waf-engine/internal/infrastructure/rules"
)

// config agrupa toda a configuração vinda das flags de linha de comando.
type config struct {
	backendURL            string
	listenAddr            string
	rulesPath             string
	rateLimitCapacity     float64
	rateLimitRefill       float64
	rateLimitIdleTTL      time.Duration
	rateLimitCleanupEvery time.Duration
	failMode              string
	dryRun                bool
}

// parseFlags interpreta os argumentos de linha de comando.
//
// Recebe args explicitamente (em vez de ler os.Args direto) para ser
// testável sem precisar manipular variáveis globais do processo.
func parseFlags(args []string) (config, error) {
	fs := flag.NewFlagSet("edge-waf-engine", flag.ContinueOnError)

	cfg := config{}
	fs.StringVar(&cfg.backendURL, "backend", "",
		"URL do backend para onde encaminhar requisições permitidas (obrigatório)")
	fs.StringVar(&cfg.listenAddr, "listen", ":8080", "Endereço em que o proxy deve escutar")
	fs.StringVar(&cfg.rulesPath, "rules", "config/rules.yaml",
		"Caminho do arquivo de regras de detecção")
	fs.Float64Var(&cfg.rateLimitCapacity, "rate-limit-capacity", 100,
		"Capacidade (burst) do rate limiter, por IP")
	fs.Float64Var(&cfg.rateLimitRefill, "rate-limit-refill", 10,
		"Tokens reabastecidos por segundo, por IP")
	fs.DurationVar(&cfg.rateLimitIdleTTL, "rate-limit-idle-ttl", 5*time.Minute,
		"Tempo ocioso até um IP ser elegível para limpeza de memória")
	fs.DurationVar(&cfg.rateLimitCleanupEvery, "rate-limit-cleanup-interval", time.Minute,
		"Intervalo entre execuções de limpeza do rate limiter")
	fs.StringVar(&cfg.failMode, "fail-mode", string(application.FailOpen),
		"Comportamento em erro interno: fail_open ou fail_closed")
	fs.BoolVar(&cfg.dryRun, "dry-run", false,
		"Se true, nunca bloqueia de fato — só reporta o que seria bloqueado (RF09)")

	if err := fs.Parse(args); err != nil {
		return config{}, err
	}

	if cfg.backendURL == "" {
		return config{}, errors.New("--backend é obrigatório")
	}

	return cfg, nil
}

// buildHandler monta o http.Handler completo (WAFReverseProxy já
// configurado com detecção, rate limiting e logging) a partir de uma
// config já validada.
//
// Separado de run() deliberadamente: isso permite testar toda a
// composição de dependências (parse do backend, carregamento de
// regras, construção do rate limiter/engine/proxy) via httptest, sem
// precisar abrir uma porta TCP de verdade.
func buildHandler(cfg config, logOutput io.Writer) (http.Handler, *ratelimiter.TokenBucketRateLimiter, error) {
	backendURL, err := url.Parse(cfg.backendURL)
	if err != nil {
		return nil, nil, fmt.Errorf("--backend inválido: %w", err)
	}

	ruleSet, err := rules.LoadRuleSet(cfg.rulesPath)
	if err != nil {
		return nil, nil, fmt.Errorf("erro carregando regras: %w", err)
	}

	limiter, err := ratelimiter.NewTokenBucketRateLimiter(
		cfg.rateLimitCapacity, cfg.rateLimitRefill, cfg.rateLimitIdleTTL,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("erro configurando rate limiter: %w", err)
	}

	detectionEngine := application.NewDetectionEngine(ruleSet)

	wafEngine, err := application.NewWAFEngine(
		detectionEngine, limiter, cfg.dryRun, application.FailMode(cfg.failMode),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("erro configurando WAF engine: %w", err)
	}

	blockLogger := logging.NewBlockLogger(logOutput)
	handler := proxy.NewWAFReverseProxy(backendURL, wafEngine, blockLogger)

	return handler, limiter, nil
}

// run sobe o servidor HTTP num listener já aberto, até que ctx seja
// cancelado (ex: SIGINT/SIGTERM recebido por main), e então encerra
// graciosamente.
//
// Recebe ctx e listener como parâmetros (em vez de criar o listener
// internamente e escutar sinais de OS direto aqui) exatamente para
// viabilizar testes de ponta a ponta: um teste pode criar seu próprio
// listener em uma porta aleatória (":0"), cancelar via context.Cancel
// normal em vez de precisar enviar um sinal de verdade ao processo.
func run(ctx context.Context, cfg config, listener net.Listener, stdout, stderr io.Writer) error {
	handler, limiter, err := buildHandler(cfg, stdout)
	if err != nil {
		return err
	}

	server := &http.Server{Handler: handler}

	cleanupDone := make(chan struct{})
	go func() {
		defer close(cleanupDone)
		ticker := time.NewTicker(cfg.rateLimitCleanupEvery)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				limiter.Cleanup()
			}
		}
	}()

	serveErr := make(chan error, 1)
	go func() {
		fmt.Fprintf(
			stdout, "edge-waf-engine ouvindo em %s, encaminhando para %s (dry-run=%v, fail-mode=%s)\n",
			listener.Addr().String(), cfg.backendURL, cfg.dryRun, cfg.failMode,
		)
		serveErr <- server.Serve(listener)
	}()

	select {
	case err := <-serveErr:
		<-cleanupDone
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	case <-ctx.Done():
		fmt.Fprintln(stdout, "encerrando graciosamente...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		err := server.Shutdown(shutdownCtx)
		<-cleanupDone
		return err
	}
}

func main() {
	cfg, err := parseFlags(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	listener, err := net.Listen("tcp", cfg.listenAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "erro escutando em %q: %v\n", cfg.listenAddr, err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, cfg, listener, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
