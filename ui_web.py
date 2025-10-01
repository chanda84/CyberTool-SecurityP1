# ui_web.py
import subprocess
import os
import re
from datetime import datetime
from threading import Thread
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt
from rich.text import Text
from rich.align import Align

# FastAPI/uvicorn (se ejecuta en hilo separado)
from fastapi import FastAPI
import uvicorn

console = Console()

# -------------------------
# Helpers: sanitizar nombres
# -------------------------

INVALID_FILENAME_CHARS = r'[:<>"/\\|?*\n\r\t]'

def sanitize_filename_component(s: str, maxlen: int = 150) -> str:
    """Remueve caracteres inválidos y acorta la cadena."""
    if s is None:
        return ""
    s = str(s)
    # Reemplaza rutas por texto legible
    s = s.replace(os.path.sep, "_")
    # Quitar prefijos extraños (ej ".\C:\...")
    s = re.sub(r'^\.+', '', s)
    # Remover caracteres inválidos
    s = re.sub(INVALID_FILENAME_CHARS, "_", s)
    # acortar
    if len(s) > maxlen:
        s = s[:maxlen] + "_TRUNC"
    return s

def build_report_path(args_list):
    """Construye path seguro para el reporte en reports/"""
    safe_parts = [sanitize_filename_component(p) for p in args_list]
    name = "report_" + "_".join([p for p in safe_parts if p])
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = f"{name}_{timestamp}.txt"
    reports_dir = Path("reports")
    reports_dir.mkdir(parents=True, exist_ok=True)
    return str(reports_dir / fname)

def normalize_target_path(raw: str) -> str:
    """Normaliza entradas del usuario para rutas de archivo antes de pasarlas a main.py"""
    if not raw:
        return raw
    s = raw.strip()
    # Si el usuario puso algo como "./C:\..." o ".\C:\..." eliminar el punto inicial
    s = re.sub(r'^[.\\/]+(?=[A-Za-z]:)', '', s)
    # Quitar prefijos './' o '.\' si es relativo
    s = re.sub(r'^\./|^\\\.', '', s)
    s = os.path.expanduser(s)
    # No forzar absolute, pasar tal cual pero normalizado
    return s

# -------------------------
# Ejecución de comandos
# -------------------------

def run_cmd(args):
    """Ejecuta main.py con parametros, muestra salida y guarda en reports/"""
    # Normalizar cualquier argumento tipo path que contenga 'test_data' o sea claramente ruta
    norm_args = []
    for a in args:
        # si parece una opción (--foo) no tocar
        if a.startswith("-"):
            norm_args.append(a)
            continue
        # intentar detectar rutas con separadores o con drive letter
        if any(x in a for x in (os.path.sep, "/", "\\", ":")):
            na = normalize_target_path(a)
            norm_args.append(na)
        else:
            norm_args.append(a)

    # Ejecutar el comando
    proc = subprocess.run(["python", "main.py"] + norm_args, capture_output=True, text=True)
    output = proc.stdout
    if proc.stderr:
        output += "\n[STDERR]\n" + proc.stderr

    # Mostrar en pantalla (Rich)
    console.print(output)

    # Guardar automáticamente en reports/
    report_path = build_report_path(norm_args)
    try:
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(output)
        console.print(f"[green]✔ Reporte guardado en:[/green] {report_path}\n")
    except Exception as e:
        console.print(f"[red]Error guardando reporte:[/red] {e}")

# -------------------------
# API local (FastAPI)
# -------------------------

app = FastAPI()

@app.get("/run/{module}")
def run_module_api(module: str, tool: str = None, target: str = None):
    """Endpoint simple para ejecutar módulos remotamente. Devuelve stdout/stderr."""
    args = []
    if module == "forensics":
        t = normalize_target_path(target or "./test_data/notepad_sample.exe")
        args = ["forensics", "--file-hash", t]
    elif module == "malware":
        if tool in ("vt-upload", "filescan-upload", "deep-scan"):
            t = normalize_target_path(target or "./test_data/notepad_sample.exe")
            args = ["malware", f"--{tool}", t]
        else:
            t = normalize_target_path(target or "./test_data/notepad_sample.exe")
            args = ["malware", "--tool", tool or "strings", "--target", t]
    elif module == "osint":
        # nota: tu módulo osint actual usa --subdomains/--ip-info/--email-leaks, aquí simplificamos
        q = target or "example.com"
        args = ["osint", "--subdomains", q]
    else:
        return {"error": "module not supported"}

    proc = subprocess.run(["python", "main.py"] + args, capture_output=True, text=True)
    return {"stdout": proc.stdout, "stderr": proc.stderr}

def run_api():
    """
    Ejecuta uvicorn en hilo separado.
    Se fuerza log_level a 'critical' / access_log False para no saturar consola TUI.
    """
    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="critical", access_log=False)

# -------------------------
# Interfaz Rich (TUI)
# -------------------------

def show_logo():
# 🐱 Gato mediano y centrado
    cat_text = Text("""
                             .                                               .                                
                            *#*+:                                        .=#@@-                               
                            %@*#@#=.                                   :+##@@@+                               
                           .@@%#%@%%*-.        .+*****#***.         :==*#@@@@@*                               
                           -@@@%%@@%%@@#+-:..++*@#+@#*%*#@*++:::-==#++%%@@@@@@%                               
                           =@@%@@%@@@@@@@@@@@@%*##*#*=#+*%%%@@@#*#-*#%@@@@@@@@@                               
                           -@%#%%@@@@@@@%%#%%##=+*=*#*%%%%#%%##*+%#%@@@@@@@@@@@.                              
                           :@@#+@@%#@%%**#+#*=#++#+*%%%*#%%%%*###%%@@@@@@@%@@@#                                                            
                          =%*%*####*%%%%%%@@@@@@@@@@@%@@@@@@%%%%%%@@@@@@@@@@%@@*                              
                          +%##*#%%@@@######%%@@@@@@@@@@@@@@@%%%#####@@@@@@@@@@@*         .:+=%#@%#*+-         
                         -+++%#%@@@@@#++***#*#%@@@@@@@@@@@%####****#@@@@@@@@@@@%*.     .-+*%%@@@@@@@@%+.      
                        =+*##%@@@@@@@%=---==---%@@@@@@@@@*---=+----#@@@@@@@@@@@@@*    .=*%@@%#++*%@@@@@@=     
                       =##%@@@@@@@@@@@@*:----=*#######@#%#+------=%%%#%%#%@@@@@@@@=  .=#%@@=      =@@@@@@+    
                      .@%@@@@@@@@@@@@@@%*#+=***%%++*+*##%#*#*+++%**%+##*@@@@@@@@@@@. =*#@@=        =#%@@@@-   
                      -@@@@@@@@@@@@@@@@@%%%##%%%%#####%@@%%@%%@%%%@%@%%%@@@@%@@@@@@: +%#@@.           *@@@#   
                      .%@@@@@%%@@@@@@@@@%%%%%%%@@%%%%%@@@%@@@@%@@@@@@@@@@@@@@@@@@@%. +%%@@:           +@@@%   
                       .=%@@@@##@@@@@@@@@%%%%%%%%@@%%%@%%%%%%@@@@@@@@@@@@@@@@@@@@*.  -*%%@%.          #@@@#   
                  **  =: .=#@@@%*%@@@@@@@@@%@@%%%%@@@@%%%%%@@@@@@@@@@@@@@@@@@@#=.  := =#%@@%.        -@@@@=   
               .  -=  @@.   *@%#%*#@@@@@@@@@@@@%@@@@%@@@@@@@@@@@@@@@@@@%%@@@@%     %@. -#%%@%-       %@@@+    
              :@=     @@. %@@@%%%@%*#@@@@@@@@@@@@@@@%@@@@@@@@@@@@@@@@%%%@@@@@@%@@. #@. -@%%@@@+      -++:     
               .  +%=-@@#*##**%%%@%#%#%@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%%@@@@@@@@@@@*+%@.  :=#@@@@#.             
              .+-:+@%%@@%%#***%%%%@@@@%#@@@@@@@@@@@@@@@@@@@@@@@@@@%%@@@@@@@@@@@@@%%@@-.*% :%@@@@%-            
              =@@%%@%##*#*##**%%%%@@@@@@#@@@@@@@@@@@@@@@@@@@@@@@@#%@@@@@@@@@@%@#%%#%@@@@@+=:*@@@@@=           
       .::::::+@@+=%*##*%##%%%##%%@@@@@@@%%@@@@@@@@@@@@@@@@@@@@%#@@@@@@@@@@@%#%%%@@%%@%@@@@+=@@%@@@=          
       =%%%%@%*%##%%=#%%#+##++@@#*%%@@@@@@%@@@@@@@@@@@@@@@@@@@%%@@@@@@@%%@@@%%@%%@@%###%%%%#@@#%@@@@:         
           -@@#%#%%%+*#%%++#**@@%%%*#%%@@@@%@@@@@@@@@@@@@@@@@@%@@@@@@@@%%@@@@%@%@##%@%#%%%%#@@*#@@@@#         
       .%%%%@%%@%@%%#%@%%*#%#%##%##**%%@@@@@@@@@@@@@@@@@@@@@@%@@@@@@@@@%@@@@@@@@@%%@@@%@@@@@@@%%@@@@%         
    :%@@@@@@@**@@@@#*%#*@@@#+#%@%+#@@%%%#%@@@@@@@@@@@@@@@@@@@@@@%%@%@##@@@###*#%%@@%@@@@@@@#*%@@@@@@%@@=:    
    :---------------------------------------------------------------------------------------------------:  
    """, style="bold cyan")

    cat_text = Align.center(cat_text)

    logo_text = Text("""
'  MM'""""'YMM              dP                         MP""""""`MM                                         oo   dP               M""""""M                           dP'
'  M' .mmm. `M          88                         M  mmmmm..M                                          88               Mmmm  mmmM                   88'
'  M  MMMMMooM dP    dP 88d888b. .d8888b. 88d888b. M.      `YM .d8888b. .d8888b. dP    dP 88d888b. dP d8888P dP    dP    MMMM  MMMM .d8888b. .d8888b. 88'
'  M  MMMMMMMM 88    88 88'  `88 88ooood8 88'  `88 MMMMMMM.  M 88ooood8 88'  `"" 88    88 88'  `88 88   88   88    88    MMMM  MMMM 88'  `88 88'  `88 88'
'  M. `MMM' .M 88.  .88 88.  .88 88.  ... 88       M. .MMM'  M 88.  ... 88.  ... 88.  .88 88       88   88   88.  .88    MMMM  MMMM 88.  .88 88.  .88 88'
'  MM.     .dM `8888P88 88Y8888' `88888P' dP       Mb.     .dM `88888P' `88888P' `88888P' dP       dP   dP   `8888P88    MMMM  MMMM `88888P' `88888P' dP'
'  MMMMMMMMMMM      .88                            MMMMMMMMMMM                                                    .88    MMMMMMMMMM'
'               d8888P                                                                                        d8888P'                                                                                                         d8888P'
""", style="bold cyan")
    console.print(cat_text)
    console.print(logo_text)
    console.print(Panel("Bienvenido a SecurityP1 [bold yellow]Andres Valdivieso Version 1.0[/bold yellow]", style="bold green"))

def show_menu():
    table = Table(title="Menú Principal", style="bold magenta")
    table.add_column("ID", justify="center", style="white", no_wrap=True)
    table.add_column("Módulo", style="bold yellow")
    table.add_column("Descripción", style="white")

    table.add_row("1", "Forensics", "Generar hashes de archivos")
    table.add_row("2", "Malware - Strings", "Extraer cadenas de texto")
    table.add_row("3", "Malware - ClamAV", "Escaneo antivirus")
    table.add_row("4", "Malware - VT Upload", "Subir archivo a VirusTotal")
    table.add_row("5", "OSINT", "Consultar dominio o IP")
    table.add_row("6", "Salir", "Cerrar la aplicación")

    console.print(table)

# -------------------------
# Loop principal
# -------------------------

def main():
    # Levantar API en background (silenciosa)
    t = Thread(target=run_api, daemon=True)
    t.start()
    console.print("[blue]🌐 API local disponible en http://127.0.0.1:8000[/blue]\n")

    show_logo()

    while True:
        show_menu()
        choice = Prompt.ask("Seleccione opción (1-6)", choices=["1", "2", "3", "4", "5", "6"], default="1")

        if choice == "1":
            path = Prompt.ask("Archivo para hashes", default="./test_data/notepad_sample.exe")
            path = normalize_target_path(path)
            run_cmd(["forensics", "--file-hash", path])

        elif choice == "2":
            target = Prompt.ask("Archivo para analizar con strings", default="./test_data/notepad_sample.exe")
            target = normalize_target_path(target)
            run_cmd(["malware", "--tool", "strings", "--target", target])

        elif choice == "3":
            target = Prompt.ask("Archivo para ClamAV", default="./test_data/notepad_sample.exe")
            target = normalize_target_path(target)
            run_cmd(["malware", "--tool", "clamscan", "--target", target])

        elif choice == "4":
            target = Prompt.ask("Archivo a subir a VirusTotal", default="./test_data/notepad_sample.exe")
            target = normalize_target_path(target)
            run_cmd(["malware", "--vt-upload", target])

        elif choice == "5":
            query = Prompt.ask("Dominio o IP para OSINT", default="example.com")
            # Aquí usamos --subdomains como ejemplo;
            run_cmd(["osint", "--subdomains", query])

        elif choice == "6":
            console.print("[red]👋 Saliendo de SecurityP1...[/red]")
            break

if __name__ == "__main__":
    main()
