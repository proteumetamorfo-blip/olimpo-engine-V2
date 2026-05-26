from datetime import datetime, timedelta
from collections import defaultdict

EVENT_LIMITS = {
    "login_failed":   (3,  120),
    "contact_submit": (5,  300),
    "route_scan":     (4,   60),
    "page_view":      (60,  60),
    "method_abuse":   (2,  300),
    "path_traversal": (1,  600),
}
IGNORED_EVENTS = {"ping", "health_check", "favicon"}

def _make_entry(ip, event_type, count, window_start, window_end, max_allowed, window_secs):
    return {
        "ip": ip, "event_type": event_type, "count": count,
        "window_start": window_start.strftime("%Y-%m-%d %H:%M:%S"),
        "window_end":   window_end.strftime("%Y-%m-%d %H:%M:%S"),
        "reason": f"{count}x '{event_type}' em {window_secs}s (limite: {max_allowed})",
        "detected_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
    }

def analyze(clean_events):
    groups = defaultdict(list)
    for ev in clean_events:
        event_type = ev.get("event","")
        if event_type in EVENT_LIMITS and event_type not in IGNORED_EVENTS:
            groups[(ev["ip"], event_type)].append(ev["_parsed_ts"])

    abusive_ips = {}
    for (ip, event_type), timestamps in groups.items():
        max_allowed, window_secs = EVENT_LIMITS[event_type]
        for i in range(len(sorted(timestamps))):
            ts_sorted    = sorted(timestamps)
            window_start = ts_sorted[i]
            window_end   = window_start + timedelta(seconds=window_secs)
            in_window    = [t for t in ts_sorted[i:] if t <= window_end]
            if len(in_window) > max_allowed:
                if ip not in abusive_ips:
                    abusive_ips[ip] = _make_entry(
                        ip, event_type, len(in_window),
                        window_start, window_end, max_allowed, window_secs)
                break

    flagged_events = []
    abusive_ip_set = set(abusive_ips.keys())
    for ev in clean_events:
        flagged = dict(ev)
        flagged.pop("_parsed_ts", None)
        event_type = ev.get("event","")
        if ev["ip"] in abusive_ip_set:        flagged["alert_level"] = "CRITICAL"
        elif event_type in EVENT_LIMITS:       flagged["alert_level"] = "WARNING"
        else:                                  flagged["alert_level"] = "OK"
        flagged_events.append(flagged)

    return flagged_events, list(abusive_ips.values())
