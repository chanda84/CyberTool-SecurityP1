# modules/osint.py
import os
import subprocess
import json
import shutil

def tool_exists(name):
    return shutil.which(name) is not None

def shodan_lookup(host):
    """
    Uses SHODAN_API_KEY (environment variable) and shodan python package if installed.
    """
    key = os.environ.get("SHODAN_API_KEY")  # <-- nombre de la variable, no la clave en sí
    if not key:
        return {"error": "SHODAN_API_KEY not set in environment. Export it before running."}
    try:
        import shodan
    except Exception as e:
        return {"error": "shodan package not installed (pip install shodan)", "detail": str(e)}
    try:
        api = shodan.Shodan(key)
        result = api.host(host)
        out = {
            "ip_str": result.get("ip_str"),
            "org": result.get("org"),
            "os": result.get("os"),
            "ports": result.get("ports"),
            "data_sample": result.get("data", [])[:5]
        }
        return out
    except Exception as e:
        return {"error": str(e)}

# modules/osint.py
def run(args):
    if getattr(args, "subdomains", None):
        print("[OSINT] subdomains target:", args.subdomains)
        return
    if getattr(args, "ip_info", None):
        print("[OSINT] ip-info target:", args.ip_info)
        return
    if getattr(args, "email_leaks", None):
        print("[OSINT] email-leaks:", args.email_leaks)
        return
    print("[OSINT] No action specified. Usa --subdomains/--ip-info/--email-leaks")
