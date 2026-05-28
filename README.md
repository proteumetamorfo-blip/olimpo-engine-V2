# ⚡ Olimpo Engine - Business Intelligence Automation Backend.

Olimpo Engine é um sistema de monitoramento e detecção de comportamento suspeito em aplicações web.

Enquanto firewalls tradicionais analisam portas e protocolos de rede, o Olimpo Engine observa o comportamento dos usuários dentro da aplicação, identificando padrões que podem indicar ataques, abuso de recursos ou tentativas de invasão.

Durante a simulação apresentada no dashboard, o sistema processou dezenas de eventos legítimos e maliciosos, identificando automaticamente atividades suspeitas como força bruta, varredura de rotas administrativas, uso de ferramentas de pentest automatizadas e métodos HTTP incomuns.

O projeto foi desenvolvido integralmente em Python, utilizando SQLite para persistência dos eventos e um mecanismo próprio de regras para análise de tráfego em tempo real.


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
```

> Para acessar o dashboard que é gerado no final de todo esse processo acesse o link: https://proteumetamorfo-blip.github.io/olimpo-engine/

# Tecnologia Utilizadas.

```
| Tecnologia | Uso |
|------------|-----|
| Python 3.10+ | Lógica principal |
| SQLite nativo | Persistência sem servidor de banco |
| Regex compilada | Performance nas regras IDS |
| ANSI escape codes | Dashboard sem dependências externas |
| Termux (Android) | Ambiente de desenvolvimento |
```

# Essas são as complementações que podem deixar o Olimpo Engine mais forte
```
- VPS Linux com Nginx em formato JSON
- Daemon systemd para processo ativo 24/7
- Integração com iptables/ufw para bloqueio na rede
- Alertas via webhook (Telegram, email)
```
# Desenvolvidor

> Vinícios Silva — Técnico em Redes de Computadores:
Goiana, Pernambuco · vinicios098silva@gmail.com
Esse projeto foi totalmente desenvolvido inteiramente via (Android + Termux).

O meu objetivo foi aprender a estruturar um ecossistema digital seguro do zero e entender os conceitos de um firewall inteligente na prática.
