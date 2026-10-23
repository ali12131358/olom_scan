import csv,io
from .constants import service_name

# Backwards compatible alias: legacy Persian label -> new wording.
CLASSIFICATION_LABELS = {
    "mikrotik_candidate": "دستگاه MikroTik",
    "نامزد MikroTik": "دستگاه MikroTik",
    "potential_non_mikrotik": "احتمالاً غیر MikroTik",
    "winbox_open_api_closed": "Winbox باز / API بسته",
    "no_ping": "بدون پاسخ پینگ",
}

def classification_label(value):
    """Persian display label, tolerating the legacy "نامزد MikroTik" wording."""
    return CLASSIFICATION_LABELS.get(value, value)

REPORT_KEYS=("ping_responders","mikrotik_candidates","potential_non_mikrotik","winbox_open_api_closed")
def records_for(report,key):
    tests={
        "ping_responders": lambda x: x.is_alive,
        "mikrotik_candidates": lambda x: x.classification == "mikrotik_candidate",
        "potential_non_mikrotik": lambda x: x.classification == "potential_non_mikrotik",
        "winbox_open_api_closed": lambda x: x.classification == "winbox_open_api_closed",
    }
    if key not in tests: raise KeyError(key)
    return [r for r in report.records if tests[key](r)]
def csv_bytes(report,key):
    out=io.StringIO(newline="");w=csv.writer(out);w.writerow(["IP","classification","open ports with service names","open numbers","8291 state","8728 state"])
    for r in records_for(report,key):w.writerow([r.ip,r.classification,"; ".join(f"{p} {service_name(p)}" for p in r.open_ports),",".join(map(str,r.open_ports)),r.ports.get(8291,"not_scanned"),r.ports.get(8728,"not_scanned")])
    return out.getvalue().encode("utf-8-sig")
