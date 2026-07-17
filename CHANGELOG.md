# Changelog

Todas as mudanças notáveis deste projeto serão documentadas neste arquivo.

O formato segue [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/),
e este projeto segue [Semantic Versioning](https://semver.org/lang/pt-BR/).

## [1.0.0] - Unreleased

### Adicionado

**Domain Core**
- `Rule`: assinatura de detecção de ataque — id, categoria (SQLi, XSS,
  Path Traversal, Command Injection), padrão regex compilado, alvos de
  inspeção (query/body/headers), severidade. Construída via `NewRule`,
  com validação fail-fast de todos os invariantes.
- `RequestContext`: representação normalizada de uma requisição HTTP,
  desacoplada de `net/http` — permite testar regras sem servidor real.
- `Verdict` / `RuleSet`: resultado agregado da avaliação (permitir ou
  bloquear, com todas as violações — nunca só a primeira) e coleção de
  regras com IDs únicos.

**Detection Engine**
- `DetectionEngine`: avalia uma `RequestContext` contra um `RuleSet`,
  agregando todas as violações de todas as regras/alvos/valores.
- Conjunto padrão de 13 regras (SQLi, XSS, Path Traversal, Command
  Injection), testadas contra payloads reais do OWASP Testing Guide
  (verdadeiro positivo) e tráfego legítimo comum (verdadeiro negativo).

**Rate Limiting**
- `RateLimiter` (interface) + `TokenBucketRateLimiter`: rate limiting
  em memória, por IP, algoritmo de token bucket, com relógio injetável
  para testes determinísticos e limpeza periódica de entradas ociosas.

**WAF Engine & Proxy**
- `WAFEngine`: orquestra rate limiting + detecção de regras numa
  decisão final, com modo dry-run (RF09) e fail-open/fail-closed
  configurável para erros internos (com recuperação de panic).
- `WAFReverseProxy`: reverse proxy HTTP real (`net/http/httputil`),
  bloqueando com 403 genérico ou encaminhando ao backend, preservando
  corpo/headers da requisição original.
- `BlockLogger`: log estruturado (JSON, `log/slog`) de toda requisição
  bloqueada (ou que seria bloqueada em dry-run), com IP, regra, motivo e
  o texto que disparou a violação (truncado a 200 caracteres).

**Configuração e CLI**
- Carregador de `rules.yaml`: regras de detecção carregadas de arquivo
  externo, não hardcoded — `config/rules.yaml` espelha o conjunto
  padrão como ponto de partida editável.
- `cmd/edge-waf-engine`: binário configurável via flags (`--backend`,
  `--listen`, `--rules`, parâmetros de rate limit, `--fail-mode`,
  `--dry-run`), com shutdown gracioso em SIGINT/SIGTERM.

**Infraestrutura do projeto**
- Suíte de testes cobrindo domínio, aplicação e infraestrutura, usando
  `httptest` para requisições HTTP reais de ponta a ponta (não mocks) e
  relógios/listeners injetáveis para determinismo.
- Ambiente de desenvolvimento documentado (Go 1.22+, golangci-lint,
  VS Code + WSL).

### Notas de arquitetura

Ver [`docs/architecture.md`](docs/architecture.md) para decisões
arquiteturais (ADRs), diagrama de componentes e limitações conhecidas
documentadas conscientemente (regra de tautologia SQLi com falso
positivo conhecido, rate limiter não distribuído, conteúdo sensível em
log de payload).
