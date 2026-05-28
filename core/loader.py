["""
core/loader.py
──────────────
Camada L do ETL — Carga no banco SQLite.

Gerencia toda a interação com o arquivo .db:
  - Criação das tabelas na primeira execução (idempotente).
  - Inserção dos eventos limpos com seus alertas.
  - Inserção dos registros de blacklist.
  - Inserção dos eventos rejeitados (quarentena) para auditoria.
"""

import sqlite3
import os
from datetime import datetime


# Caminho do banco — relativo à raiz do projeto
DB_PATH = os.path.join(os.path.dirname(__file__), "..", "db", "olimpo_audit.db")


def _get_connection() -> sqlite3.Connection:
    """
    Abre conexão com o SQLite.
    WAL Mode ativado: permite leituras e escritas simultâneas sem travar
    o banco inteiro — essencial para o daemon processar centenas de
    eventos por segundo sem gargalo.
    """
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode = WAL")   # ← V2: Write-Ahead Logging
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA synchronous = NORMAL")  # ← V2: performance sem perder durabilidade
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """
    Cria as tabelas se ainda não existirem.
    Seguro para executar múltiplas vezes (IF NOT EXISTS).
    """
    schema = """
    CREATE TABLE IF NOT EXISTS events_log (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        ip          TEXT    NOT NULL,
        event       TEXT    NOT NULL,
        route       TEXT    NOT NULL,
        timestamp   TEXT    NOT NULL,
        alert_level TEXT    NOT NULL DEFAULT 'OK',
        ids_tags    TEXT    NOT NULL DEFAULT '',
        geo_country TEXT    NOT NULL DEFAULT '',
        geo_city    TEXT    NOT NULL DEFAULT '',
        geo_code    TEXT    NOT NULL DEFAULT '',
        processed_at TEXT   NOT NULL
    );

    CREATE TABLE IF NOT EXISTS blacklist (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        ip           TEXT NOT NULL UNIQUE,
        event_type   TEXT NOT NULL,
        count        INTEGER NOT NULL,
        window_start TEXT NOT NULL,
        window_end   TEXT NOT NULL,
        reason       TEXT NOT NULL,
        detected_at  TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS quarantine_log (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        raw_ip        TEXT,
        raw_event     TEXT,
        raw_route     TEXT,
        raw_timestamp TEXT,
        reject_reason TEXT NOT NULL,
        processed_at  TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS threats_log (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        ip          TEXT NOT NULL,
        rule        TEXT NOT NULL,
        detail      TEXT NOT NULL,
        severity    TEXT NOT NULL,
        detected_at TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_events_ip     ON events_log  (ip);
    CREATE INDEX IF NOT EXISTS idx_events_alert  ON events_log  (alert_level);
    CREATE INDEX IF NOT EXISTS idx_blacklist_ip  ON blacklist   (ip);
    CREATE INDEX IF NOT EXISTS idx_threats_ip    ON threats_log (ip);
    CREATE INDEX IF NOT EXISTS idx_threats_rule  ON threats_log (rule);
    """
    with _get_connection() as conn:
        conn.executescript(schema)


def load_events(flagged_events: list[dict]) -> int:
    """Insere eventos processados na tabela events_log."""
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    rows = [
        (ev["ip"], ev["event"], ev["route"], ev["timestamp"],
         ev.get("alert_level", "OK"), ev.get("ids_tags", ""),
         ev.get("geo_country", ""), ev.get("geo_city", ""),
         ev.get("geo_code", ""), now)
        for ev in flagged_events
    ]
    with _get_connection() as conn:
        conn.executemany(
            "INSERT INTO events_log "
            "(ip, event, route, timestamp, alert_level, ids_tags, "
            "geo_country, geo_city, geo_code, processed_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            rows,
        )
    return len(rows)


def load_threats(threat_entries: list[dict]) -> int:
    """Insere ameaças detectadas pelo IDS na tabela threats_log."""
    rows = [
        (t["ip"], t["rule"], t["detail"], t["severity"], t["detected_at"])
        for t in threat_entries
    ]
    with _get_connection() as conn:
        conn.executemany(
            "INSERT INTO threats_log (ip, rule, detail, severity, detected_at) "
            "VALUES (?, ?, ?, ?, ?)",
            rows,
        )
    return len(rows)


def load_blacklist(blacklist_entries: list[dict]) -> int:
    """
    Insere IPs abusivos na blacklist.
    Se o IP já existir, atualiza o registro (INSERT OR REPLACE).
    Retorna o número de registros processados.
    """
    rows = [
        (entry["ip"], entry["event_type"], entry["count"],
         entry["window_start"], entry["window_end"],
         entry["reason"], entry["detected_at"])
        for entry in blacklist_entries
    ]

    with _get_connection() as conn:
        conn.executemany(
            "INSERT OR REPLACE INTO blacklist "
            "(ip, event_type, count, window_start, window_end, reason, detected_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            rows,
        )
    return len(rows)


def load_quarantine(quarantined: list[dict]) -> int:
    """
    Insere registros inválidos na quarentena para auditoria futura.
    Retorna o número de registros inseridos.
    """
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    rows = [
        (str(ev.get("ip", "")), str(ev.get("event", "")),
         str(ev.get("route", "")), str(ev.get("timestamp", "")),
         ev.get("reject_reason", "desconhecido"), now)
        for ev in quarantined
    ]

    with _get_connection() as conn:
        conn.executemany(
            "INSERT INTO quarantine_log "
            "(raw_ip, raw_event, raw_route, raw_timestamp, reject_reason, processed_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            rows,
        )
    return len(rows)


def get_all_blacklisted_ips() -> list[str]:
    """Retorna todos os IPs da blacklist."""
    with _get_connection() as conn:
        rows = conn.execute("SELECT ip FROM blacklist").fetchall()
    return [row["ip"] for row in rows]


def live_stats() -> dict:
    """Snapshot atual do banco para o dashboard ao vivo."""
    with _get_connection() as conn:
        total   = conn.execute("SELECT COUNT(*) FROM events_log").fetchone()[0]
        crit    = conn.execute("SELECT COUNT(*) FROM events_log WHERE alert_level='CRITICAL'").fetchone()[0]
        warn    = conn.execute("SELECT COUNT(*) FROM events_log WHERE alert_level='WARNING'").fetchone()[0]
        bl_cnt  = conn.execute("SELECT COUNT(*) FROM blacklist").fetchone()[0]
        quar    = conn.execute("SELECT COUNT(*) FROM quarantine_log").fetchone()[0]
        thr_cnt = conn.execute("SELECT COUNT(*) FROM threats_log").fetchone()[0]

        recent  = conn.execute(
            "SELECT ip, event, route, alert_level, ids_tags, timestamp "
            "FROM events_log ORDER BY id DESC LIMIT 20"
        ).fetchall()

        bl_rows = conn.execute(
            "SELECT ip, event_type, count, reason, detected_at "
            "FROM blacklist ORDER BY detected_at DESC"
        ).fetchall()

        thr_rows = conn.execute(
            "SELECT ip, rule, severity, detail, detected_at "
            "FROM threats_log ORDER BY id DESC LIMIT 6"
        ).fetchall()

    return {
        "total": total, "critical": crit, "warning": warn,
        "blacklisted": bl_cnt, "quarantined": quar, "threats": thr_cnt,
        "recent_events":  [dict(r) for r in recent],
        "blacklist":      [dict(r) for r in bl_rows],
        "recent_threats": [dict(r) for r in thr_rows],
    }]
