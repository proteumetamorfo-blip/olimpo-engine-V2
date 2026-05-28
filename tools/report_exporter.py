[#!/usr/bin/env python3
import os, sys, argparse
from datetime import datetime, timezone
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from core.loader import init_db, live_stats

OUT_DEFAULT = os.path.join(os.path.dirname(__file__), "..", "logs", "relatorio_seguranca.html")

def _badge(level):
    styles = {
        "CRITICAL": "background:#8b1a1a;color:#f0ece4",
        "WARNING":  "background:#7a6000;color:#f0ece4",
        "OK":       "background:#1a4a1a;color:#c8f0c8",
        "HIGH":     "background:#8b1a1a;color:#f0ece4",
        "MEDIUM":   "background:#7a6000;color:#f0ece4",
    }
    s = styles.get(level, "background:#333;color:#ccc")
    return f'<span style="padding:2px 6px;border-radius:3px;font-size:0.7rem;font-family:monospace;white-space:nowrap;{s}">{level}</span>'

def _row(*cells, header=False):
    tag = "th" if header else "td"
    inner = "".join(f"<{tag}>{c}</{tag}>" for c in cells)
    return f"<tr>{inner}</tr>"

def build_html(stats):
    now   = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    total = stats["total"] or 1
    ok_n  = stats["total"] - stats["warning"] - stats["critical"]
    ok_pct   = round((ok_n              / total) * 100)
    warn_pct = round((stats["warning"]  / total) * 100)
    crit_pct = round((stats["critical"] / total) * 100)

    events_rows = "\n".join(
        _row(
            f'<span style="font-family:monospace;font-size:0.75rem">{ev["ip"]}</span>',
            f'<span style="font-size:0.8rem">{ev["event"]}</span>',
            f'<span style="font-size:0.75rem;color:#888;word-break:break-all">{ev["route"]}</span>',
            _badge(ev["alert_level"]),
            f'<span style="color:#c9a84c;font-size:0.7rem">{ev["ids_tags"] or "—"}</span>',
            f'<span style="color:#555;font-size:0.7rem;white-space:nowrap">{ev["timestamp"]}</span>',
        )
        for ev in stats["recent_events"]
    ) or "<tr><td colspan='6' style='color:#555;text-align:center;padding:1rem'>Sem eventos</td></tr>"

    bl_rows = "\n".join(
        _row(
            f'<strong style="color:#ff6b6b;font-family:monospace;font-size:0.8rem">{bl["ip"]}</strong>',
            f'<span style="font-size:0.8rem">{bl["event_type"]}</span>',
            f'<span style="color:#c9a84c;font-weight:700">{bl["count"]}x</span>',
            f'<span style="font-size:0.75rem;color:#ccc">{bl["reason"]}</span>',
            f'<span style="color:#555;font-size:0.7rem;white-space:nowrap">{bl["detected_at"]}</span>',
        )
        for bl in stats["blacklist"]
    ) or "<tr><td colspan='5' style='color:#555;text-align:center;padding:1rem'>Nenhum IP bloqueado</td></tr>"

    thr_rows = "\n".join(
        _row(
            f'<strong style="color:#ff6b6b;font-family:monospace;font-size:0.8rem">{t["ip"]}</strong>',
            f'<span style="color:#c9a84c;font-family:monospace;font-size:0.75rem">{t["rule"]}</span>',
            _badge(t["severity"]),
            f'<span style="font-size:0.75rem;color:#ccc;word-break:break-all">{t["detail"]}</span>',
            f'<span style="color:#555;font-size:0.7rem;white-space:nowrap">{t["detected_at"]}</span>',
        )
        for t in stats["recent_threats"]
    ) or "<tr><td colspan='5' style='color:#555;text-align:center;padding:1rem'>Nenhuma ameaça IDS detectada</td></tr>"

    return f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1.0"/>
  <title>Olimpo Engine — Relatório de Segurança</title>
  <style>
    :root{{--obsidian:#0a0908;--gold:#c9a84c;--mid:#1a1714;--marble:#f0ece4;}}
    *{{box-sizing:border-box;margin:0;padding:0;}}
    body{{background:var(--obsidian);color:var(--marble);font-family:'Segoe UI',system-ui,sans-serif;font-size:14px;line-height:1.6;padding:clamp(0.75rem,4vw,1.5rem);}}
    h1{{font-family:Georgia,serif;color:var(--gold);font-size:clamp(1.2rem,5vw,2rem);letter-spacing:0.05em;}}
    h2{{font-family:Georgia,serif;color:var(--gold);font-size:clamp(0.9rem,3vw,1.1rem);margin-bottom:1rem;}}
    .subtitle{{color:rgba(240,236,228,0.45);font-size:clamp(0.7rem,2.5vw,0.85rem);margin-top:0.35rem;font-style:italic;}}
    header{{border-bottom:1px solid rgba(201,168,76,0.25);padding-bottom:1.25rem;margin-bottom:1.75rem;}}
    .meta{{font-family:monospace;font-size:clamp(0.6rem,2vw,0.7rem);color:rgba(201,168,76,0.5);margin-top:0.5rem;}}

    .stats-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(100px,1fr));gap:0.6rem;margin-bottom:2rem;}}
    .stat-card{{background:var(--mid);border:1px solid rgba(201,168,76,0.2);border-radius:4px;padding:0.75rem;text-align:center;}}
    .stat-num{{font-size:clamp(1.4rem,5vw,2rem);font-weight:700;color:var(--gold);line-height:1;}}
    .stat-num.red{{color:#ff6b6b;}} .stat-num.yellow{{color:#ffd166;}}
    .stat-num.purple{{color:#c084fc;}} .stat-num.green{{color:#4caf50;}}
    .stat-label{{font-size:clamp(0.55rem,1.8vw,0.65rem);letter-spacing:0.1em;color:rgba(240,236,228,0.4);margin-top:0.3rem;text-transform:uppercase;}}

    .dist-section{{margin-bottom:2rem;}}
    .dist-row{{display:flex;align-items:center;gap:0.5rem;margin-bottom:0.6rem;}}
    .dist-label{{width:65px;font-size:0.7rem;font-family:monospace;color:rgba(240,236,228,0.5);flex-shrink:0;}}
    .bar-track{{flex:1;height:8px;background:rgba(255,255,255,0.06);border-radius:4px;overflow:hidden;min-width:0;}}
    .bar-fill{{height:100%;border-radius:4px;}}
    .bar-ok{{background:linear-gradient(90deg,#1a6b1a,#4caf50);}}
    .bar-warn{{background:linear-gradient(90deg,#7a6000,#ffd166);}}
    .bar-crit{{background:linear-gradient(90deg,#6b1a1a,#ff6b6b);}}
    .dist-val{{width:38px;text-align:right;font-family:monospace;font-size:0.7rem;color:rgba(240,236,228,0.5);flex-shrink:0;}}

    .card{{background:var(--mid);border:1px solid rgba(201,168,76,0.18);border-radius:4px;padding:clamp(0.75rem,3vw,1.25rem);margin-bottom:1rem;}}
    .table-wrap{{overflow-x:auto;-webkit-overflow-scrolling:touch;}}
    table{{width:100%;border-collapse:collapse;font-size:clamp(0.7rem,2.2vw,0.82rem);min-width:400px;}}
    th{{background:rgba(201,168,76,0.12);color:var(--gold);font-family:monospace;font-size:clamp(0.6rem,1.8vw,0.65rem);letter-spacing:0.08em;text-transform:uppercase;padding:0.5rem 0.6rem;text-align:left;border-bottom:1px solid rgba(201,168,76,0.2);white-space:nowrap;}}
    td{{padding:0.45rem 0.6rem;border-bottom:1px solid rgba(255,255,255,0.04);vertical-align:top;}}
    tr:hover td{{background:rgba(201,168,76,0.04);}}
    footer{{margin-top:2rem;padding-top:1rem;border-top:1px solid rgba(201,168,76,0.15);text-align:center;font-family:monospace;font-size:0.62rem;color:rgba(201,168,76,0.3);}}
  </style>
</head>
<body>

<header>
  <h1>⚡ OLIMPO ENGINE</h1>
  <p class="subtitle">Relatório de Auditoria de Segurança — Business Intelligence Automation Backend</p>
  <p class="meta">Gerado em: {now} | Por: Vinícios Silva</p>
</header>

<section class="stats-grid">
  <div class="stat-card"><div class="stat-num">{stats['total']}</div><div class="stat-label">Total</div></div>
  <div class="stat-card"><div class="stat-num green">{ok_n}</div><div class="stat-label">OK</div></div>
  <div class="stat-card"><div class="stat-num yellow">{stats['warning']}</div><div class="stat-label">Warning</div></div>
  <div class="stat-card"><div class="stat-num red">{stats['critical']}</div><div class="stat-label">Critical</div></div>
  <div class="stat-card"><div class="stat-num purple">{stats['threats']}</div><div class="stat-label">Ameaças IDS</div></div>
  <div class="stat-card"><div class="stat-num red">{stats['blacklisted']}</div><div class="stat-label">Blacklist</div></div>
  <div class="stat-card"><div class="stat-num yellow">{stats['quarantined']}</div><div class="stat-label">Quarentena</div></div>
</section>

<section class="dist-section card">
  <h2>DISTRIBUIÇÃO DE ALERTAS</h2>
  <div class="dist-row"><span class="dist-label">OK</span><div class="bar-track"><div class="bar-fill bar-ok" style="width:{ok_pct}%"></div></div><span class="dist-val">{ok_pct}%</span></div>
  <div class="dist-row"><span class="dist-label">WARNING</span><div class="bar-track"><div class="bar-fill bar-warn" style="width:{warn_pct}%"></div></div><span class="dist-val">{warn_pct}%</span></div>
  <div class="dist-row"><span class="dist-label">CRITICAL</span><div class="bar-track"><div class="bar-fill bar-crit" style="width:{crit_pct}%"></div></div><span class="dist-val">{crit_pct}%</span></div>
</section>

<section class="card">
  <h2>🚫 BLACKLIST — IPs BLOQUEADOS</h2>
  <div class="table-wrap"><table>
    <thead><tr>{''.join(f'<th>{h}</th>' for h in ['IP','Evento','Contagem','Motivo','Detectado'])}</tr></thead>
    <tbody>{bl_rows}</tbody>
  </table></div>
</section>

<section class="card">
  <h2>◉ AMEAÇAS IDS DETECTADAS</h2>
  <div class="table-wrap"><table>
    <thead><tr>{''.join(f'<th>{h}</th>' for h in ['IP','Regra','Severidade','Detalhe','Detectado'])}</tr></thead>
    <tbody>{thr_rows}</tbody>
  </table></div>
</section>

<section class="card">
  <h2>📋 ÚLTIMOS EVENTOS (todos os tipos)</h2>
  <div class="table-wrap"><table>
    <thead><tr>{''.join(f'<th>{h}</th>' for h in ['IP','Evento','Rota','Alerta','IDS Tags','Timestamp'])}</tr></thead>
    <tbody>{events_rows}</tbody>
  </table></div>
</section>

<footer>OLIMPO ENGINE V2 · Vinícios Silva · Goiana, PE</footer>
</body>
</html>"""

def export(output_path=OUT_DEFAULT):
    init_db()
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    stats = live_stats()
    html  = build_html(stats)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"\n  Relatorio gerado: {output_path}\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default=OUT_DEFAULT)
    args = parser.parse_args()
    export(args.output)]
