# edge-waf-engine

![Go](https://img.shields.io/badge/go-1.22%2B-00ADD8)
![License](https://img.shields.io/badge/license-MIT-blue)

> Um Web Application Firewall simplificado, rodando na borda: reverse
> proxy em Go que inspeciona cada requisição HTTP contra assinaturas de
> ataque (SQLi, XSS, Path Traversal, Command Injection) e rate limiting
> por IP, antes de decidir se ela chega ao seu backend.

## O problema

APIs e aplicações web expostas na internet sofrem ataques constantes.
Soluções comerciais (Cloudflare, AWS WAF) resolvem isso, mas são caixas-
-pretas; ModSecurity resolve, mas com uma curva de configuração íngreme.
`edge-waf-engine` é um WAF **explicável**: cada regra é um padrão regex
legível, cada bloqueio gera um log estruturado dizendo exatamente qual
regra disparou e por quê — pensado para ser entendido, auditado e
ajustado por quem o opera, não uma caixa-preta.

## Instalação

```bash
git clone https://github.com/tensairod/edge-waf-engine.git
cd edge-waf-engine
go mod tidy
go build -o bin/edge-waf-engine ./cmd/edge-waf-engine
```

## Uso

```bash
./bin/edge-waf-engine --backend http://localhost:9000
```

```
edge-waf-engine ouvindo em [::]:8080, encaminhando para http://localhost:9000 (dry-run=false, fail-mode=fail_open)
```

Testando com `curl`:

```bash
# Requisição limpa — encaminhada ao backend (200, ou o que o backend responder)
curl -i "http://localhost:8080/search?q=hello"

# Payload de SQL Injection — bloqueado direto pelo WAF (403), backend nunca é chamado
curl -i "http://localhost:8080/search?q=1+UNION+SELECT+password+FROM+users"
```

O segundo comando gera um log estruturado assim no stdout do processo:

```json
{
  "time": "2026-07-16T15:37:40-03:00",
  "level": "WARN",
  "msg": "requisição bloqueada",
  "source_ip": "::1",
  "method": "GET",
  "path": "/search",
  "reason": "rule_violation",
  "blocked": true,
  "dry_run": false,
  "violations": [
    {
      "rule_id": "sqli-001-union-select",
      "category": "sql_injection",
      "severity": "high",
      "target": "query",
      "matched_text": "1 UNION SELECT password FROM users"
    }
  ]
}
```

### Flags disponíveis

| Flag | Default | Descrição |
|---|---|---|
| `--backend` | *(obrigatório)* | URL do backend para onde encaminhar requisições permitidas |
| `--listen` | `:8080` | Endereço em que o proxy escuta |
| `--rules` | `config/rules.yaml` | Caminho do arquivo de regras de detecção |
| `--rate-limit-capacity` | `100` | Capacidade (burst) do rate limiter, por IP |
| `--rate-limit-refill` | `10` | Tokens reabastecidos por segundo, por IP |
| `--rate-limit-idle-ttl` | `5m` | Tempo ocioso até um IP ser elegível para limpeza |
| `--rate-limit-cleanup-interval` | `1m` | Intervalo entre limpezas do rate limiter |
| `--fail-mode` | `fail_open` | Comportamento em erro interno: `fail_open` ou `fail_closed` |
| `--dry-run` | `false` | Nunca bloqueia de fato — só reporta o que seria bloqueado |

## Regras de detecção

As regras vivem em [`config/rules.yaml`](config/rules.yaml) — edite,
adicione ou remova regras sem recompilar o binário. Cada regra:

```yaml
- id: sqli-001-union-select
  category: sql_injection
  pattern: "(?i)\\bunion\\b(?:\\s+all)?\\s+select\\b"
  targets: [query, body]
  severity: high
  description: "Detecta UNION SELECT, usado para extrair dados de outras tabelas."
```

O conjunto padrão cobre 4 categorias (SQL Injection, XSS, Path
Traversal, Command Injection) com 13 regras, testadas contra payloads
reais do OWASP Testing Guide e contra tráfego legítimo comum — ver
`internal/application/default_rules_test.go`.

## Features

- ✅ Reverse proxy real (`net/http/httputil.ReverseProxy`) — encaminha
  requisições permitidas preservando corpo, headers e método.
- ✅ Detecção por assinaturas regex: SQL Injection, XSS, Path Traversal,
  Command Injection.
- ✅ Rate limiting por IP (token bucket em memória).
- ✅ Modo dry-run (RF09): teste regras novas em produção sem risco de
  bloquear tráfego real.
- ✅ Fail-open / fail-closed configurável para erros internos.
- ✅ Log estruturado (JSON) de toda requisição bloqueada.
- ✅ Regras carregadas de `rules.yaml` externo — sem recompilar.
- ✅ Shutdown gracioso (SIGINT/SIGTERM).
- ✅ 100% type-safe, testado com `httptest` de ponta a ponta (requisições
  HTTP reais, não mocks).

## Arquitetura

O projeto segue uma arquitetura em camadas (Domain → Application →
Infrastructure), com as dependências sempre apontando para dentro.
Diagrama completo, ADRs e limitações conhecidas em
[`docs/architecture.md`](docs/architecture.md).

## Desenvolvimento

```bash
go test ./... -v -cover -race
gofmt -l .
golangci-lint run ./...
```

## Roadmap

- [ ] Rate limiting por ASN (requer integração com base GeoIP/MaxMind —
  avaliado e cortado da v1 para manter o escopo enxuto).
- [ ] Rate limiter distribuído via Redis, para múltiplas instâncias
  atrás de um load balancer (débito técnico documentado desde a Issue 6).
- [ ] Hot-reload de `rules.yaml` sem reiniciar o processo.
- [ ] Suporte a proxies confiáveis para `X-Forwarded-For` (hoje
  deliberadamente ignorado — ver `docs/architecture.md`).

## Licença

MIT — veja [`LICENSE`](LICENSE).
