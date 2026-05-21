# ⚡ Olimpo Engine — V2
### Business Intelligence Automation Backend — IDS de Nível de Aplicação

> Evolução do [Olimpo Engine V1](https://github.com/proteumetamorfo-blip/oleoduto-de-seguranca).
> Desenvolvido inteiramente via dispositivo móvel (Android + Termux),
> Esse é o Dashboard do Olimpo Engine: https://proteumetamorfo-blip.github.io/olimpo-engine-V2/
> O dashborard mostra registro de um ataque simulado. (Foram simulado um total de 97 tentativas de usuários malioso e usuários legítimos misturados. O código conseguiu captar todos os anômalos que implementei.

---

## O Problema

Firewalls tradicionais protegem portas e protocolos.
Eles não enxergam **comportamento**.

Um atacante que tenta 50 logins errados pela porta 443 passa pelo firewall
de rede sem ser detectado — porque a porta está aberta e o protocolo é válido.

O Olimpo Engine resolve isso na camada de aplicação: analisa o **padrão**
das requisições, não apenas se elas chegaram.

---

## O que o sistema faz

```
EVENTOS BRUTOS
     │
     ▼
┌─────────────┐
│     ETL     │  Limpa, valida IPs, normaliza eventos, rejeita dados corrompidos
└──────┬──────┘
       │
       ▼
┌─────────────┐
│  RATE LIMIT │  Sliding window: detecta força bruta e spam por volume
└──────┬──────┘
       │
       ▼
┌─────────────┐
│  IDS RULES  │  4 regras: Path Traversal, Route Scan, Malicious UA, Method Abuse
└──────┬──────┘
       │
       ▼
┌─────────────┐
│   SQLite    │  Persiste eventos, blacklist, quarentena e ameaças detectadas
└──────┬──────┘
       │
       ▼
  DASHBOARD + RELATÓRIO HTML
```

---

## Resultados reais da simulação

```
Total eventos processados:   92
Alertas CRITICAL:            29
Alertas WARNING:              9
Ameaças IDS detectadas:      38
IPs na blacklist:             2
Eventos em quarentena:        8

BLACKLIST GERADA:
  45.33.32.156 → 14x login_failed em 5min  (limite: 5)
  198.51.100.8 → 9x contact_submit em 5min (limite: 5)

AMEAÇAS IDS:
  [HIGH]   104.21.45.33   → MALICIOUS_UA  (sqlmap detectado)
  [MEDIUM] 89.248.172.16  → ROUTE_SCAN    (/wp-admin, /.env, /phpmyadmin)
```

---

## Estrutura do projeto

```
olimpo-engine-V2/
├── pipeline.py            ← orquestrador principal (modo batch)
├── daemon.py              ← modo daemon (tempo real)
├── dashboard.py           ← painel CLI ao vivo
│
├── core/
│   ├── transformer.py     ← ETL: limpeza, validação, normalização
│   ├── loader.py          ← persistência SQLite com 4 tabelas indexadas
│   └── watcher.py         ← leitura contínua de log
│
├── security/
│   ├── rate_limit.py      ← algoritmo sliding window
│   └── ids_rules.py       ← motor de regras IDS com regex compiladas
│
└── tools/
    ├── log_generator.py   ← gerador de tráfego simulado com ataques reais
    └── report_exporter.py ← exportação de relatório em HTML
```

---

## Tecnologias

| Tecnologia | Uso |
|------------|-----|
| Python 3.10+ | Lógica principal |
| SQLite nativo | Persistência sem servidor de banco |
| Regex compilada | Performance nas regras IDS |
| ANSI escape codes | Dashboard sem dependências externas |
| Termux (Android) | Ambiente de desenvolvimento |

**Dependências externas: zero.**

---

## Como rodar

```bash
# Pré-requisito no Termux
pkg install python

# 1. Gerar logs simulados
timeout 15 python tools/log_generator.py --speed slow

# 2. Processar e detectar
python pipeline.py

# 3. Ver painel de resultados
python dashboard.py --once
```

### Modo tempo real (duas sessões)
```bash
# Sessão 1
python daemon.py

# Sessão 2
python tools/log_generator.py --speed normal
```

---

## Regras IDS implementadas

| Regra | O que detecta | Severidade |
|-------|---------------|------------|
| `RATE_LIMIT` | Mesmo IP acima do limite na janela de tempo | CRITICAL |
| `PATH_TRAVERSAL` | `/../`, `/etc/passwd`, `/.git/config` | HIGH |
| `ROUTE_SCAN` | `/wp-admin`, `/.env`, `/phpmyadmin` | MEDIUM |
| `MALICIOUS_UA` | sqlmap, nikto, masscan, gobuster | HIGH |
| `METHOD_ABUSE` | DELETE, TRACE em rotas comuns | MEDIUM |

---

## Evolução em relação ao V1

| V1 | V2 |
|----|----|
| Arquivos na raiz | Pastas separadas por responsabilidade |
| Modo batch apenas | Modo daemon em tempo real |
| Rate limit simples | Rate limit + 4 regras IDS |
| Relatório no terminal | Dashboard CLI + relatório HTML |
| Sem gerador de logs | Gerador de tráfego com ataques simulados |

---

## O que falta para produção

- VPS Linux com Nginx em formato JSON
- Daemon systemd para processo ativo 24/7
- Integração com iptables/ufw para bloqueio na rede
- Alertas via webhook (Telegram, email)

A lógica de detecção não muda. Só o ambiente de execução.

---

## Contexto de desenvolvimento

Desenvolvido inteiramente via **Android + Termux**, sem computador,
sem IDE profissional, sem infraestrutura dedicada.

O objetivo foi provar que é possível projetar arquitetura de segurança
em camadas com as ferramentas disponíveis — não com as ideais.

---

**Vinícios Silva** — Técnico em Redes de Computadores
Goiana, Pernambuco · vinicios098silva@gmail.com
