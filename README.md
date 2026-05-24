# ⚡ Olimpo Engine - Business Intelligence Automation Backend.

Olimpo Engine é um sistema de monitoramento e detecção de comportamento suspeito em aplicações web.

Enquanto firewalls tradicionais analisam portas e protocolos de rede, o Olimpo Engine observa o comportamento dos usuários dentro da aplicação, identificando padrões que podem indicar ataques, abuso de recursos ou tentativas de invasão.

Durante a simulação apresentada no dashboard, o sistema processou dezenas de eventos legítimos e maliciosos, identificando automaticamente atividades suspeitas como força bruta, varredura de rotas administrativas, uso de ferramentas de pentest automatizadas e métodos HTTP incomuns.

O projeto foi desenvolvido integralmente em Python, utilizando SQLite para persistência dos eventos e um mecanismo próprio de regras para análise de tráfego em tempo real.

> Seu objetivo é demonstrar conceitos de:

• ETL aplicado a logs
• Monitoramento de eventos
• Rate limiting
• Intrusion Detection Systems (IDS)
• Processamento contínuo de dados
• Arquitetura modular de segurança


# O Olimpo Engine trabalha assim:

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
*Para melhorar o entendendo do dashboard acesse o link: https://proteumetamorfo-blip.github.io/olimpo-engine/*
```
# Estrutura do projeto


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




# Tecnologia utilizadas.

| Tecnologia | Uso |
|------------|-----|
| Python 3.10+ | Lógica principal |
| SQLite nativo | Persistência sem servidor de banco |
| Regex compilada | Performance nas regras IDS |
| ANSI escape codes | Dashboard sem dependências externas |
| Termux (Android) | Ambiente de desenvolvimento |





# Como rodar o Olimpo Engine.
```
```bash
# Pré-requisito no Termux

pkg install python

# 1. Gerar logs simulados

timeout 15 python tools/log_generator.py --speed slow

# 2. Processar e detectar

python pipeline.py

# 3. Ver painel de resultados

python dashboard.py --once


# Modo tempo real (duas sessões)

```bash
# Sessão 1

python daemon.py

# Sessão 2

python tools/log_generator.py --speed normal
```


## Regras IDS implementadas.

| Regra | O que detecta | Severidade |

| `RATE_LIMIT` | Mesmo IP acima do limite na janela de tempo | CRITICAL |
| `PATH_TRAVERSAL` | `/../`, `/etc/passwd`, `/.git/config` | HIGH |
| `ROUTE_SCAN` | `/wp-admin`, `/.env`, `/phpmyadmin` | MEDIUM |
| `MALICIOUS_UA` | sqlmap, nikto, masscan, gobuster | HIGH |
| `METHOD_ABUSE` | DELETE, TRACE em rotas comuns | MEDIUM |


# Essas são as complementações que podem deixar o Olimpo Engine mais forte.

- VPS Linux com Nginx em formato JSON
- Daemon systemd para processo ativo 24/7
- Integração com iptables/ufw para bloqueio na rede
- Alertas via webhook (Telegram, email)

> Esse projeto foi totalmente desenvolvido inteiramente via (Android + Termux),

O meu objetivo foi provar que é possível projetar arquitetura de segurança
em camadas com as ferramentas disponíveis.


**Vinícios Silva** — Técnico em Redes de Computadores
