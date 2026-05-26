import os, time, json
from datetime import datetime
from core.transformer    import transform
from core.loader         import init_db, load_events, load_blacklist, load_quarantine, load_threats
from core.geoip          import enrich_batch
from security.rate_limit import analyze
from security.ids_rules  import scan

LOG_PATH       = os.path.join(os.path.dirname(__file__), "..", "data", "raw", "access.json")
FLUSH_INTERVAL = 8
SLEEP_INTERVAL = 0.05

class C:
    RESET="\033[0m"; BOLD="\033[1m"; DIM="\033[2m"
    RED="\033[91m"; YELLOW="\033[93m"; GREEN="\033[92m"; CYAN="\033[96m"

def _get_inode(path):
    try: return os.stat(path).st_ino
    except: return None

def _wait_for_file(path, timeout=30):
    print(f"  {C.YELLOW}Aguardando:{C.RESET} {path}")
    for _ in range(timeout*10):
        if os.path.exists(path): return True
        time.sleep(0.1)
    return False

def _flush_buffer(buffer):
    if not buffer: return {}
    clean, quarantined = transform(buffer)
    clean              = enrich_batch(clean)
    flagged, blacklisted = analyze(clean)
    enriched, threats    = scan(flagged)
    load_events(enriched); load_blacklist(blacklisted)
    load_quarantine(quarantined); load_threats(threats)
    for entry in blacklisted:
        print(f"  {C.RED}[CRITICAL]{C.RESET} IP {C.BOLD}{entry['ip']}{C.RESET} — {entry['reason']}")
    for threat in threats:
        sc = C.RED if threat["severity"]=="HIGH" else C.YELLOW
        print(f"  {sc}[IDS {threat['severity']}]{C.RESET} {threat['ip']} | {threat['rule']}")
    return {"total":len(buffer),"clean":len(clean),"quarantined":len(quarantined),"blacklisted":len(blacklisted),"threats":len(threats)}

def watch():
    init_db()
    print(f"\n{C.CYAN}{C.BOLD}  OLIMPO ENGINE — DAEMON V2{C.RESET}")
    print(f"  {C.DIM}Rate Limit dinamico · XSS/SQLi · GeoIP · Log Rotation{C.RESET}\n")
    if not _wait_for_file(LOG_PATH):
        print(f"  {C.RED}Arquivo nao encontrado.{C.RESET}\n"); return
    print(f"  {C.GREEN}Monitorando:{C.RESET} {LOG_PATH}\n")
    buffer=[]; last_flush=time.time(); lines_read=0; batches=0
    current_inode = _get_inode(LOG_PATH)
    with open(LOG_PATH,"r") as f:
        f.seek(0,2)
        try:
            while True:
                new_inode = _get_inode(LOG_PATH)
                if new_inode and new_inode != current_inode:
                    print(f"\n  {C.YELLOW}[LOG ROTATION]{C.RESET} Reabrindo arquivo...")
                    if buffer: _flush_buffer(buffer); buffer.clear()
                    f.close(); f = open(LOG_PATH,"r")
                    current_inode = new_inode
                line = f.readline()
                if line:
                    line = line.strip()
                    if line:
                        try: buffer.append(json.loads(line)); lines_read+=1
                        except: pass
                now = time.time()
                if now-last_flush >= FLUSH_INTERVAL:
                    if buffer:
                        batches+=1
                        ts = datetime.utcnow().strftime("%H:%M:%S")
                        print(f"\n  {C.CYAN}[{ts}] Lote #{batches} ({len(buffer)} eventos){C.RESET}")
                        r = _flush_buffer(buffer); buffer.clear()
                        print(f"  {C.DIM}Limpos:{r['clean']} Quarentena:{r['quarantined']} Bloqueios:{r['blacklisted']} IDS:{r['threats']}{C.RESET}")
                    last_flush=now
                else: time.sleep(SLEEP_INTERVAL)
        except KeyboardInterrupt:
            if buffer: _flush_buffer(buffer)
            print(f"\n  {C.GREEN}Daemon encerrado.{C.RESET} {lines_read} linhas | {batches} lotes.\n")
