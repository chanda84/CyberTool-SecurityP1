def list_guides():
    """
    Returns a small curated list of guides/resources referenced in the UI image.
    """
    guides = {
        "OWASP": "https://owasp.org/",
        "NIST CSF": "https://www.nist.gov/cyberframework",
        "MITRE CWE": "https://cwe.mitre.org/",
        "CVE": "https://cve.mitre.org/"
    }
    # local helpful notes or references can be added as files in a /guides folder later
    return guides

# modules/guides.py
def run(args):
    if getattr(args, "list", False):
        print("[GUIDES] Listado de guías disponibles (placeholder): OWASP, NIST CSF, MITRE CWE, CVE")
        return
    if getattr(args, "show", None):
        print(f"[GUIDES] Mostrar guía: {args.show} (placeholder)")
        return
    print("[GUIDES] No action specified. Usa --list o --show <name>")
