import re
from datetime import datetime

_PATH_TRAVERSAL_PATTERNS = [
    re.compile(r"\.\./"),
    re.compile(r"%2e%2e", re.IGNORECASE),
    re.compile(r"etc/passwd", re.IGNORECASE),
    re.compile(r"etc/shadow", re.IGNORECASE),
    re.compile(r"\.(git|env|htaccess|htpasswd)(/|$)"),
]

_SCAN_ROUTES = {
    "/wp-admin","/wp-login.php","/.env","/phpmyadmin",
    "/admin","/config.php","/backup.zip","/.git/config",
    "/shell.php","/cgi-bin/test.cgi","/server-status",
    "/api/users","/api/admin","/actuator","/console",
}

_MALICIOUS_UA_PATTERNS = [
    re.compile(r"sqlmap",    re.IGNORECASE),
    re.compile(r"nikto",     re.IGNORECASE),
    re.compile(r"masscan",   re.IGNORECASE),
    re.compile(r"zgrab",     re.IGNORECASE),
    re.compile(r"nmap",      re.IGNORECASE),
    re.compile(r"gobuster",  re.IGNORECASE),
    re.compile(r"nuclei",    re.IGNORECASE),
    re.compile(r"hydra",     re.IGNORECASE),
    re.compile(r"python-requests/2\.\d+\.\d+$"),
    re.compile(r"^Go-http-client/"),
    re.compile(r"^-$"),
]

_ABUSIVE_METHODS = {"DELETE","PUT","PATCH","TRACE","OPTIONS"}

_XSS_PATTERNS = [
    re.compile(r"<script[\s>]",       re.IGNORECASE),
    re.compile(r"javascript\s*:",     re.IGNORECASE),
    re.compile(r"on\w+\s*=\s*[\"']", re.IGNORECASE),
    re.compile(r"<iframe[\s>]",       re.IGNORECASE),
    re.compile(r"%3Cscript",          re.IGNORECASE),
    re.compile(r"expression\s*\(",    re.IGNORECASE),
    re.compile(r"vbscript\s*:",       re.IGNORECASE),
]

_SQLI_PATTERNS = [
    re.compile(r"\bUNION\s+SELECT\b",       re.IGNORECASE),
    re.compile(r"\bOR\s+1\s*=\s*1\b",      re.IGNORECASE),
    re.compile(r"\bAND\s+1\s*=\s*1\b",     re.IGNORECASE),
    re.compile(r"'\s*OR\s*'",              re.IGNORECASE),
    re.compile(r"\bDROP\s+TABLE\b",         re.IGNORECASE),
    re.compile(r"\bSELECT\s+\*\s+FROM\b",  re.IGNORECASE),
    re.compile(r"\bDELETE\s+FROM\b",        re.IGNORECASE),
    re.compile(r";\s*(DROP|DELETE|INSERT)",  re.IGNORECASE),
    re.compile(r"%27",                      re.IGNORECASE),
]

def _make_threat(ip, rule, detail, severity):
    return {
        "ip":ip,"rule":rule,"detail":detail,"severity":severity,
        "detected_at":datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
    }

def _check_path_traversal(event):
    route = event.get("route","")
    for p in _PATH_TRAVERSAL_PATTERNS:
        if p.search(route):
            return _make_threat(event["ip"],"PATH_TRAVERSAL",f"Rota suspeita: '{route}'","HIGH")
    return None

def _check_route_scan(event):
    route = event.get("route","").split("?")[0].lower()
    if route in _SCAN_ROUTES:
        return _make_threat(event["ip"],"ROUTE_SCAN",f"Rota sensivel: '{route}'","MEDIUM")
    return None

def _check_malicious_ua(event):
    ua = event.get("user_agent","") or ""
    for p in _MALICIOUS_UA_PATTERNS:
        if p.search(ua):
            return _make_threat(event["ip"],"MALICIOUS_UA",f"UA suspeito: '{ua[:60]}'","HIGH")
    return None

def _check_method_abuse(event):
    method = str(event.get("method","")).upper()
    if method in _ABUSIVE_METHODS:
        return _make_threat(event["ip"],"METHOD_ABUSE",f"Metodo abusivo: {method}","MEDIUM")
    return None

def _check_xss(event):
    route = event.get("route","") + " " + str(event.get("user_agent",""))
    for p in _XSS_PATTERNS:
        if p.search(route):
            return _make_threat(event["ip"],"XSS_ATTEMPT",f"XSS detectado: '{route[:60]}'","HIGH")
    return None

def _check_sqli(event):
    route = event.get("route","")
    for p in _SQLI_PATTERNS:
        if p.search(route):
            return _make_threat(event["ip"],"SQL_INJECTION",f"SQLi detectado: '{route[:60]}'","HIGH")
    return None

_RULE_CHECKERS = [
    _check_path_traversal,
    _check_route_scan,
    _check_malicious_ua,
    _check_method_abuse,
    _check_xss,
    _check_sqli,
]

def scan(flagged_events):
    enriched = []
    threats  = []
    for ev in flagged_events:
        tags_hit = []
        for checker in _RULE_CHECKERS:
            threat = checker(ev)
            if threat:
                tags_hit.append(threat["rule"])
                threats.append(threat)
                if threat["severity"]=="HIGH" and ev.get("alert_level")!="CRITICAL":
                    ev = dict(ev)
                    ev["alert_level"] = "CRITICAL"
        enriched_ev = dict(ev)
        enriched_ev["ids_tags"] = ",".join(tags_hit) if tags_hit else ""
        enriched.append(enriched_ev)
    return enriched, threats
