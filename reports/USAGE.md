# USAGE.md

## Uso General

SecurityP1 es una herramienta modular de seguridad que combina **forense digital**, **análisis de malware**, **OSINT**, y utilidades adicionales.

**Puede usarse en tres modos**:

1. **CLI directa con `main.py`** → control total por línea de comandos.
2. **Interfaz TUI con `ui_web.py`** → menú interactivo en consola con Rich.
3. **API local (FastAPI)** → para automatizar consultas y control remoto.

---

## ⚡ Instalación rápida

```bash
# Crear entorno virtual
python -m venv venv
.\venv\Scripts\activate   # Windows
source venv/bin/activate  # Linux/Mac

# Instalar dependencias
pip install -r requirements.txt
```

Dependencias principales:

* `rich` (interfaz TUI)
* `fastapi` + `uvicorn` (API local)
* `requests` (consultas externas)

---

## 🔑 Configuración de API Keys

Algunos módulos requieren claves externas:

* **VirusTotal** → `VT_API_KEY`
* **FileScan.io** → `FILESCAN_API_KEY`
* **Shodan.io** → `SHODAN_API_KEY`

Configúralas como variables de entorno:

```powershell
# Windows (PowerShell)
$env:VT_API_KEY="TU_API_KEY_AQUI"
$env:FILESCAN_API_KEY="TU_API_KEY_AQUI"
$env:SHODAN_API_KEY="TU_API_KEY_AQUI"
```

```bash
# Linux / Mac
export VT_API_KEY="TU_API_KEY_AQUI"
export FILESCAN_API_KEY="TU_API_KEY_AQUI"
export SHODAN_API_KEY="TU_API_KEY_AQUI"
```

---

## 🗂️ Casos (`--case`)

Todos los módulos aceptan el argumento opcional `--case <ID>` para asociar salidas a un caso específico.
Esto organiza los reportes en `reports/<case_id>/`.

**Ejemplo:**

```bash
python main.py forensics --file-hash ./test_data/notepad_sample.exe --case caso1
```

Generará:

```
reports/caso1/report_forensics_file-hash_<timestamp>.txt
```

---

## 🖥️ Uso de `main.py` (CLI)

```bash
python main.py <modulo> [subcomando/opciones] [--case <id>] [--report-format <formato>]
```

### 🔹 Opciones globales

* `-h, --help` → muestra ayuda.
* `--case <ID>` → asocia ejecución a un caso.
* `--report-format {console,json,both}` → salida en consola, JSON o ambos (default: both).

---

### 1. **Forensics**

```bash
python main.py forensics --file-hash <archivo> [--case <id>]
```

Opciones:

* `--file-hash <archivo>` → genera **MD5, SHA1, SHA256** del archivo.

Ejemplo:

```bash
python main.py forensics --file-hash ./test_data/notepad_sample.exe --case caso1
```

---

### 2. **Malware**

```bash
python main.py malware [opciones] [--case <id>]
```

Subcomandos / opciones:

* `--strings <archivo>` → extraer cadenas de texto.
* `--entropy <archivo>` → calcular entropía Shannon.
* `--vt-upload <archivo>` → subir archivo a VirusTotal.
* `--vt-hash <hash>` → obtener reporte por hash en VT.
* `--filescan-upload <archivo>` → subir archivo a FileScan.io.
* `--deep-scan <archivo>` → escaneo completo con varias herramientas.
* `--tool <herramienta> --target <archivo>` → ejecutar herramienta puntual (`clamscan`, `strings`, `objdump`, `dumpbin`, `sigcheck`, etc.).

Ejemplos:

```bash
# Strings
python main.py malware --strings ./test_data/notepad_sample.exe --case caso1

# Entropía
python main.py malware --entropy ./test_data/random.bin

# Subir a VirusTotal
python main.py malware --vt-upload ./test_data/notepad_sample.exe
```

---

### 3. **OSINT**

```bash
python main.py osint [opciones] [--case <id>]
```

Opciones:

* `--subdomains <dominio>` → buscar subdominios.
* `--ip-info <ip>` → reputación de IP.
* `--email-leaks <email>` → buscar filtraciones de email.

Ejemplos:

```bash
python main.py osint --subdomains example.com
python main.py osint --ip-info 8.8.8.8
python main.py osint --email-leaks usuario@example.com
```

---

### 4. **Guides**

```bash
python main.py guides [opciones]
```

Opciones:

* `--list` → listar guías disponibles.
* `--show <nombre>` → mostrar guía por nombre.

Ejemplo:

```bash
python main.py guides --list
python main.py guides --show analisis_basico
```

---

### 5. **Attack / Defend**

```bash
python main.py attack [subcomando]
python main.py defend [subcomando]
```

*(Actualmente son placeholders que se expandirán en futuras versiones.)*

---

## 🎨 Uso de `ui_web.py` (TUI)

Ejecuta el menú interactivo:

```bash
python ui_web.py
```

Menú principal:

```
1  Forensics           → Generar hashes de archivos
2  Malware - Strings   → Extraer cadenas de texto
3  Malware - ClamAV    → Escaneo antivirus
4  Malware - VT Upload → Subir archivo a VirusTotal
5  OSINT               → Consultar dominio o IP
6  Salir               → Cerrar la aplicación
```

### Funcionalidades:

* Selección de opción por **atajo de teclado (1–6)**.
* Pide parámetros interactivos (archivo, dominio, IP).
* **Guarda reportes automáticamente** en `reports/` con nombre:

  ```
  reports/report_<modulo>_<parametros>_<timestamp>.txt
  ```
* Lanza en paralelo la **API local (FastAPI)** → `http://127.0.0.1:8000`.

---

## 🌐 API local (FastAPI)

Se activa junto con la UI (`ui_web.py`).

### Endpoint principal:

```http
GET /run/{module}?tool=<tool>&target=<ruta>
```

* `module`: `forensics`, `malware`, `osint`.
* `tool`: solo para `malware`.
* `target`: archivo / dominio / IP según módulo.

Ejemplo:

```
GET http://127.0.0.1:8000/run/malware?tool=strings&target=./test_data/notepad_sample.exe
```

Respuesta JSON:

```json
{
  "stdout": "resultado de ejecución",
  "stderr": ""
}
```

---

## 📂 Formato de reportes

Todos los resultados se guardan automáticamente en la carpeta `reports/`.

Formato:

```
reports/
  ├── caso1/
  │    └── report_malware_strings_<timestamp>.txt
  └── report_forensics_file-hash_<timestamp>.txt
```

* Nombre → `report_<modulo>_<subcomando>_<timestamp>.txt`
* Codificación → UTF-8
* Si se usa `--case`, se guarda dentro de la carpeta del caso.

---

## ⚠️ Compatibilidad

* **Windows** → algunas herramientas no disponibles (`clamscan`, `objdump`, etc.).
* **Linux/Mac** → se aprovechan más comandos del sistema.
* **API Keys** → obligatorias para VirusTotal / FileScan.
* **Archivos de prueba** → usar `./test_data/` incluidos (ejemplo: `notepad_sample.exe`, `random.bin`).
  
---