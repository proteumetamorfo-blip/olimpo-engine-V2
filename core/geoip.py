import os
from pathlib import Path

GEOIP_DB = os.path.join(os.path.dirname(__file__), "..", "db", "GeoLite2-City.mmdb")
_reader = None

def _get_reader():
    global _reader
    if _reader is not None: return _reader
    if not Path(GEOIP_DB).exists(): return None
    try:
        import geoip2.database
        _reader = geoip2.database.Reader(GEOIP_DB)
        return _reader
    except: return None

def _is_private(ip):
    if ip.startswith(("10.","127.","169.254.","192.168.","::1")):
        return True
    parts = ip.split(".")
    if len(parts)==4:
        try:
            if parts[0]=="172" and 16<=int(parts[1])<=31: return True
        except: pass
    return False

def lookup(ip):
    reader = _get_reader()
    if reader is None: return {}
    if _is_private(ip): return {"country":"Private","country_code":"LAN","city":"—"}
    try:
        r = reader.city(ip)
        return {"country":r.country.name or "—","country_code":r.country.iso_code or "—","city":r.city.name or "—","latitude":r.location.latitude,"longitude":r.location.longitude}
    except: return {}

def enrich_event(event):
    geo = lookup(event.get("ip",""))
    e = dict(event)
    e["geo_country"] = geo.get("country","")
    e["geo_city"]    = geo.get("city","")
    e["geo_code"]    = geo.get("country_code","")
    return e

def enrich_batch(events):
    return [enrich_event(ev) for ev in events]
