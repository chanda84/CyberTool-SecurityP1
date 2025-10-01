#!/usr/bin/env python3
import argparse
import sys

# Import modules
from modules import attack, defend, forensics, guides, malware, osint

# --- Interfaz de arranque con Rich (con fallback) ------------------------
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.prompt import Prompt
    from rich.text import Text
    _RICH_AVAILABLE = True
    console = Console()
except Exception:
    _RICH_AVAILABLE = False
    console = None

def show_startup_banner():
    """Muestra banner / menú bonito al iniciar (si no se pasó módulo)."""
    title = "SECURITYP1"
    subtitle = "Herramienta modular de seguridad — arranque"
    modules = [
        ("attack", "Módulo ofensivo"),
        ("defend", "Módulo defensivo"),
        ("forensics", "Módulo forense"),
        ("guides", "Guías"),
        ("malware", "Análisis malware"),
        ("osint", "OSINT")
    ]

    if _RICH_AVAILABLE:
        txt = Text.assemble(
            (f"{title}\n", "bold magenta"),
            (f"{subtitle}\n\n", "italic"),
        )
        console.print(Panel(txt, expand=False, border_style="green"))
        t = Table(show_header=True, header_style="bold cyan")
        t.add_column("Comando")
        t.add_column("Descripción")
        for k, d in modules:
            t.add_row(k, d)
        console.print(t)
    else:
        print("="*40)
        print(title)
        print(subtitle)
        print("-"*40)
        for k, d in modules:
            print(f"{k:10s} - {d}")
        print("="*40)

def interactive_select_module():
    """Solicita al usuario elegir un módulo si no indicó ninguno."""
    if _RICH_AVAILABLE:
        choices = ["attack","defend","forensics","guides","malware","osint","exit"]
        choice = Prompt.ask("Selecciona módulo a ejecutar", choices=choices, default="malware")
        if choice == "exit":
            sys.exit(0)
        return choice
    else:
        print("Escribe el nombre del módulo a ejecutar o 'exit':")
        choice = input("> ").strip().lower()
        if choice == "exit":
            sys.exit(0)
        return choice

# -----------------------------------------------------------------------

def build_parser():
    parser = argparse.ArgumentParser(
        description="SECURITYP1 - Herramienta modular de seguridad"
    )
    parser.add_argument("--case", default="CASE-0001", help="Case ID para reports")
    parser.add_argument("--gui", action="store_true", help="Arrancar la interfaz web local (UI)")

    subparsers = parser.add_subparsers(dest="module", help="Módulo a ejecutar")

    # ATTACK
    attack_parser = subparsers.add_parser("attack", help="Módulo ofensivo")
    attack_parser.add_argument("--scan-ports", help="Escanear puertos de una IP")
    attack_parser.add_argument("--bruteforce", nargs=3, metavar=("PROTO","IP","USERLIST"),
                               help="Fuerza bruta: PROTO IP USERLIST")
    attack_parser.add_argument("--sqltest", help="Prueba SQLi en URL")

    # DEFEND
    defend_parser = subparsers.add_parser("defend", help="Módulo defensivo")
    defend_parser.add_argument("--check-firewall", action="store_true", help="Verificar firewall")
    defend_parser.add_argument("--vuln-scan", help="Escanear vulnerabilidades en IP")
    defend_parser.add_argument("--check-processes", action="store_true", help="Listar procesos sospechosos")

    # FORENSICS
    for_parser = subparsers.add_parser("forensics", help="Módulo forense")
    for_parser.add_argument("--analyze-logs", help="Analizar ruta de logs")
    for_parser.add_argument("--memory", help="Analizar memory dump")
    for_parser.add_argument("--file-hash", help="Calcular hashes de archivo")

    # GUIDES
    guides_parser = subparsers.add_parser("guides", help="Guías")
    guides_parser.add_argument("--list", action="store_true", help="Listar guías")
    guides_parser.add_argument("--show", help="Mostrar guía por nombre")

    # MALWARE
    mal_parser = subparsers.add_parser("malware", help="Módulo malware")
    mal_parser.add_argument("--report-format", choices=["console","json","both"],
                            default="both",
                            help="Formato de salida para resultados VT/FileScan: console/json/both (default both)")
    mal_parser.add_argument("--scan", dest="scan", help="(placeholder) antivirus scan alias")
    mal_parser.add_argument("--strings", help="Extraer strings de archivo")
    mal_parser.add_argument("--entropy", help="Analizar entropía archivo")
    mal_parser.add_argument("--vt-upload", dest="vt_upload", help="Upload file to VirusTotal (requires VT_API_KEY)")
    mal_parser.add_argument("--vt-hash", dest="vt_hash", help="Get VirusTotal report by file hash")
    mal_parser.add_argument("--filescan-upload", dest="filescan_upload", help="Upload file to FileScan.io")
    mal_parser.add_argument("--deep-scan", dest="deep_scan", help="Ejecutar batería de herramientas del sistema sobre archivo")
    mal_parser.add_argument("--tool", help="Ejecutar herramienta puntual (sysstrings, clamscan, objdump, etc.)")
    mal_parser.add_argument("--target", help="Target para --tool (archivo o IP)")

    # OSINT
    os_parser = subparsers.add_parser("osint", help="Módulo OSINT")
    os_parser.add_argument("--subdomains", help="Buscar subdominios")
    os_parser.add_argument("--ip-info", help="Reputación de IP")
    os_parser.add_argument("--email-leaks", help="Buscar filtraciones de email")

    return parser

def main():
    parser = build_parser()
    args = parser.parse_args()

    if not args.module and not getattr(args, "gui", False):
        show_startup_banner()
        args.module = interactive_select_module()

    if getattr(args, "gui", False):
        try:
            import ui_web
            ui_web.app.run(host="127.0.0.1", port=5000)
            return
        except Exception as e:
            if _RICH_AVAILABLE:
                console.print(f"[red]No se pudo iniciar la UI web local:[/red] {e}")
            else:
                print("[ERROR] No se pudo iniciar la UI web local:", e)

    if args.module == "attack":
        attack.run(args)
    elif args.module == "defend":
        defend.run(args)
    elif args.module == "forensics":
        forensics.run(args)
    elif args.module == "guides":
        guides.run(args)
    elif args.module == "malware":
        malware.run(args)
    elif args.module == "osint":
        osint.run(args)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
