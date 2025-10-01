import shutil
import subprocess
import hashlib
import os

def tool_exists(name):
    return shutil.which(name) is not None

def scan_clam(path):
    """
    Wrapper for clamscan (ClamAV). Returns summary or error.
    """
    if not tool_exists("clamscan"):
        return {"error": "clamscan not found in PATH"}
    try:
        out = subprocess.run(["clamscan", "-r", path], capture_output=True, text=True, timeout=600)
        return {"returncode": out.returncode, "stdout": out.stdout, "stderr": out.stderr}
    except Exception as e:
        return {"error": str(e)}

def compute_hashes(path):
    """
    Compute md5, sha1, sha256 for a file.
    """
    if not os.path.isfile(path):
        return {"error": "file not found"}
    h = {"md5":"", "sha1":"", "sha256":""}
    b = open(path, "rb").read()
    import hashlib
    h["md5"] = hashlib.md5(b).hexdigest()
    h["sha1"] = hashlib.sha1(b).hexdigest()
    h["sha256"] = hashlib.sha256(b).hexdigest()
    return h

# modules/defend.py
def run(args):
    if getattr(args, "check_firewall", False) or getattr(args, "check-firewall", False):
        # argparse convierte --check-firewall a args.check_firewall
        print("[DEFEND] check-firewall -> OK (placeholder)")
        return
    if getattr(args, "vuln_scan", None) or getattr(args, "vuln-scan", None):
        ip = args.vuln_scan if getattr(args, "vuln_scan", None) else args.vuln_scan
        # better: use attribute name used in main: vuln_scan
        ip = getattr(args, "vuln_scan", None)
        print(f"[DEFEND] vuln-scan target={ip}")
        return
    if getattr(args, "check_processes", False):
        print("[DEFEND] check-processes -> listado (placeholder)")
        return
    print("[DEFEND] No action specified. Usa --check-firewall/--vuln-scan/--check-processes")
