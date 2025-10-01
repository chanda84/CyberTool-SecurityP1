import shutil
import subprocess
import json

def tool_exists(name):
    return shutil.which(name) is not None

def run_nmap(target, args="-sC -sV -oX -"):
    """
    Run nmap if available. Returns parsed output when possible.
    """
    if not tool_exists("nmap"):
        return {"error": "nmap not found in PATH"}
    cmd = ["nmap", *args.split(), "-oX", "-", target]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        return {"returncode": out.returncode, "stdout": out.stdout, "stderr": out.stderr}
    except Exception as e:
        return {"error": str(e)}

def run_hydra(target, service, userlist="/usr/share/wordlists/rockyou.txt", timeout=600):
    """
    Calls hydra if available. This is only a wrapper — ensure you have permission to test targets.
    """
    if not tool_exists("hydra"):
        return {"error": "hydra not found in PATH"}
    # note: this is a simple example - do not run against targets without authorization
    cmd = ["hydra", "-L", userlist, "-p", "password", f"{target}", service]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {"returncode": out.returncode, "stdout": out.stdout, "stderr": out.stderr}
    except Exception as e:
        return {"error": str(e)}

# modules/attack.py
def run(args):
    # args.scan_ports -> string or None
    if getattr(args, "scan_ports", None):
        print("[ATTACK] scan-ports:", args.scan_ports)
        # aquí llama la función real run_nmap(args.scan_ports)
        return
    if getattr(args, "bruteforce", None):
        proto, ip, userlist = args.bruteforce
        print(f"[ATTACK] bruteforce proto={proto} ip={ip} userlist={userlist}")
        return
    if getattr(args, "sqltest", None):
        print("[ATTACK] sqltest:", args.sqltest)
        return
    print("[ATTACK] No action specified. Usa --scan-ports/--bruteforce/--sqltest")
