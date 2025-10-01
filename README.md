# CyberTool-SecurityP1 / Guía rápida (Markdown)

> Versión documentada de la herramienta **SecurityP1**.
> Contiene estructura del proyecto, instalación, uso por CLI, uso de la TUI/UI, variables de entorno necesarias y resolución de problemas comunes.

---

## Índice

  - [Resumen del proyecto](#resumen-del-proyecto)
  - [Estructura del repositorio](#estructura-del-repositorio)
  - [Requisitos e instalación](#requisitos-e-instalación)
  - [Variables de entorno importantes](#variables-de-entorno-importantes)
  - [Cómo ejecutar — CLI (sin UI)](#cómo-ejecutar--cli-sin-ui)
  - [Interfaz TUI / UI local](#interfaz-tui--ui-local)
  - [API local (FastAPI)](#api-local-fastapi)
  - [Módulos y opciones (lista completa)](#módulos-y-opciones-lista-completa)
    - [`malware` (modules/malware.py)](#malware-modulesmalwarepy)
    - [`forensics`](#forensics)
    - [`osint`](#osint)
    - [`guides`](#guides)
    - [`attack`, `defend`](#attack-defend)
  - [Buenas prácticas y seguridad](#buenas-prácticas-y-seguridad)
  - [Solución de problemas rápida](#solución-de-problemas-rápida)
- [DISCLAIMER — Aviso legal y de uso responsable](#disclaimer--aviso-legal-y-de-uso-responsable)
  - [Aísle el entorno](#aísle-el-entorno)
  - [Haga snapshots / backups](#haga-snapshots--backups)
  - [Control de muestras y datos](#control-de-muestras-y-datos)
- [Permisos y cumplimiento](#permisos-y-cumplimiento)

---

## Resumen del proyecto

SecurityP1 es una herramienta modular de línea de comandos (con TUI y API opcional) que agrupa varios módulos de seguridad: `attack`, `defend`, `forensics`, `malware`, `osint`, `guides`. Cada módulo expone un `run(args)` y se invoca desde `main.py`. También hay una interfaz con `rich` (`ui_web.py`) que muestra un menú TUI bonito y arranca opcionalmente una API local (FastAPI + Uvicorn) para control remoto.

---

## Estructura del repositorio

<img width="648" height="770" alt="image" src="https://github.com/user-attachments/assets/a9647025-ec4e-4a54-8902-e36fb0efb543" />

> **Nota:** `reports/` y `test_data/` son carpetas usadas por la herramienta; `reports/` se crea automáticamente si no existe.

---

## Requisitos e instalación

Recomendado usar un entorno virtual (`venv`).

Windows / PowerShell (ejemplo):

```powershell
# crear y activar venv
python -m venv venv
.\venv\Scripts\Activate.ps1

# instalar dependencias
pip install --upgrade pip
pip install -r requirements.txt
```

`requirements.txt` (ejemplo mínimo) debe incluir:
<img width="1733" height="1001" alt="image" src="https://github.com/user-attachments/assets/81f29360-c771-4020-8813-f483a72cebf9" />

> Si no utilizarás la API, no es obligatorio `fastapi`/`uvicorn`. `rich` es usado para la TUI.

---

## Variables de entorno importantes

* `FILESCAN_API_KEY` — clave para FileScan.io (modules/filescan.py).
* `VT_API_KEY` — clave para VirusTotal (si usas integraciones vt.py).
* `SHODAN_API_KEY`— clave para Shodan (si usas integraciones OSINT.py).
* En Windows: para evitar problemas con caracteres Unicode en consola, ejecutar antes:

  ```powershell
  chcp 65001
  $OutputEncoding = [Console]::OutputEncoding = [Text.UTF8Encoding]::UTF8
  ```

  o abrir terminal que soporte UTF-8.

---

## Cómo ejecutar — CLI (sin UI)

Puedes ejecutar cualquier módulo directamente con `main.py`. Ejemplos:

![option cli](https://github.com/user-attachments/assets/e15f5cc1-0536-457a-aba9-7709e48b57b3)

```bash
# ayuda general
python main.py -h

# ayuda de malware
python main.py malware -h

# extraer strings del archivo de prueba
python main.py malware --strings ./test_data/notepad_sample.exe

# calcular entropía
python main.py malware --entropy ./test_data/random.bin

# ejecutar herramienta puntual (ej: objdump en Linux)
python main.py malware --tool objdump --target ./test_data/notepad_sample.exe

# subir a FileScan.io (requiere FILESCAN_API_KEY)
python main.py malware --filescan-upload ./test_data/notepad_sample.exe

# buscar informe por hash en VirusTotal (requiere VT_API_KEY)
python main.py malware --vt-hash da5807bb0997...

# forensics hash
python main.py forensics --file-hash ./test_data/notepad_sample.exe

# OSINT (placeholder / módulos simples)
python main.py osint --subdomains example.com
python main.py osint --ip-info 8.8.8.8
python main.py osint --email-leaks me@example.com
```

> Si no quieres UI, **usar `main.py` es correcto** — todo lo funcional está accesible desde CLI.

---

## Interfaz TUI / UI local

Arranca la TUI / menú bonito (usa `rich`) y opcionalmente arranca la API local:

![CyberTool](https://github.com/user-attachments/assets/32fc42ac-1157-441f-8532-fe652d3f2a9e)


```bash
# arranca la TUI interactiva (también lanza API en background si ui_web.py lo configura)
python ui_web.py
```

* En la TUI verás un logo ASCII y un menú con opciones (1..6).
* Te permite seleccionar opciones por número (atajos 1..6) sin confirmar.
* La TUI guarda automáticamente **todos** los outputs en `reports/` (archivo con timestamp).
* Si la API está disponible, la TUI lanza `uvicorn` en background: `http://127.0.0.1:8000`.

**Atajos y comportamiento TUI actual:**

* `1` Forensics → pide ruta de archivo y calcula hashes (MD5, SHA1, SHA256).
* `2` Malware - Strings → ejecuta `--tool strings` (o el extractor interno).
* `3` Malware - ClamAV → intenta `clamscan` (si está disponible).
* `4` Malware - VT Upload → ejecuta `--vt-upload` (requiere `VT_API_KEY`).
* `5` OSINT → pide dominio/IP y ejecuta una consulta (placeholder modules/osint.py).
* `6` Salir.

> La TUI está diseñada para no pedir confirmaciones extra: al elegir opción y completar input, ejecuta y guarda el informe automáticamente en `reports/`.

---

## API local (FastAPI)

Si `uvicorn`/`fastapi` están instalados, `ui_web.py` arranca una API HTTP (por defecto en `127.0.0.1:8000`).

**Endpoint principal (ejemplo):**

* `GET /run/{module}`

Parámetros:

* `module`: `forensics`, `malware`, `osint`
* `tool` (opcional): nombre de herramienta (ej: `strings`, `clamscan`, `vt-upload`, `filescan-upload`)
* `target` (opcional): ruta del archivo / dominio / ip

**Ejemplo:**

```
GET http://127.0.0.1:8000/run/malware?tool=strings&target=./test_data/notepad_sample.exe
```

La API ejecuta `python main.py ...` en el servidor y devuelve `stdout`/`stderr` en JSON. Útil para integración con otras apps.

---

## Módulos y opciones (lista completa)

### `malware` (modules/malware.py)

* `--strings <file>` — extrae cadenas ASCII (extract_strings en Python).
* `--entropy <file>` — calcula entropía Shannon.
* `--vt-upload <file>` — subir archivo a VirusTotal (vt.py).
* `--vt-hash <hash>` — obtener informe VT por hash.
* `--filescan-upload <file>` — subir a FileScan.io (filescan.py).
* `--deep-scan <file>` — ejecuta battery de herramientas del SO (clamscan, rkhunter, objdump, xxd/hexdump, strace/ltrace, ss/netstat, etc.)
* `--tool <tool>` `--target <path>` — ejecutar herramienta puntual (mapa de nombres: `clamscan`, `objdump`, `xxd`, `hexdump`, `strace`, `ltrace`, `ss`, `netstat`, `strings`/`sysstrings`, `sigcheck`, `dumpbin`, etc.)
* `--report-format {console,json,both}` — formato de salida cuando se integra con helpers de reporting.

### `forensics`

* `--file-hash <file>` — md5/sha1/sha256.

### `osint`

* `--subdomains <domain>` — buscar subdominios (placeholder).
* `--ip-info <ip>` — reputación IP (placeholder).
* `--email-leaks <email>` — buscar leaks (placeholder).

### `guides`

* `--list` — listar guías.
* `--show <name>` — mostrar guía.

### `attack`, `defend`

* Varias opciones placeholder; revisar `modules/attack.py` y `modules/defend.py`.

---

## Buenas prácticas y seguridad

* **No ejecutar muestras maliciosas** en máquinas de producción. Usa máquinas virtuales o entornos controlados.
* Los módulos que llaman a servicios externos (VirusTotal, FileScan) requieren claves y pueden enviar muestras a terceros — atención a la privacidad.
* Para pruebas seguras, usar `test_data/notepad_sample.exe`, `random.bin`, `wordlist.txt` — no EICAR ni malware real.

---

## Solución de problemas rápida

**Problema:** caracteres `✅` y otros Unicode fallan al imprimir en PowerShell → `UnicodeEncodeError`.
**Solución:** ejecutar:

```powershell
chcp 65001
$OutputEncoding = [Console]::OutputEncoding = [Text.UTF8Encoding]::UTF8
```

**Problema:** `ModuleNotFoundError: No module named 'rich'`
**Solución:** activa el `venv` correcto y `pip install rich`. Asegúrate de ejecutar `python` desde el mismo interprete que el `venv` (`.\venv\Scripts\Activate.ps1`).

**Problema:** FileScan upload falla por TLS / endpoints / headers → el módulo `modules/filescan.py` incluye lógica para probar varios endpoints y variantes de headers (`apikey`, `X-API-Key`, `Authorization: Bearer ...`) y para reintentar `verify=False` si hay problemas TLS. Si recibes 401, revisa que la clave sea válida.

**Problema:** `run_tool` dice `tool not supported on windows` → algunos nombres de herramientas difieren por OS. Usa `--tool sysstrings` (windows), o simplemente `--strings` (extractor Python) para compatibilidad cross-OS.

**Si la UI no arranca o falta `fastapi`:**

* Puedes usar sólo `main.py` (CLI) — toda la funcionalidad está disponible por CLI. UI es opcional.

---

# DISCLAIMER — Aviso legal y de uso responsable

Última actualización: 2025-09-27

1. Propósito de la herramienta

SecurityP1 es una herramienta diseñada para facilitar tareas de seguridad informativa, análisis forense básico y pruebas controladas. Provee wrappers y ayudas para herramientas, llamadas a APIs (p. ej. VirusTotal / FileScan), extracción de cadenas, cálculo de hashes y ejecución de utilidades del sistema.

1. Sobre las muestras incluidas

Los ficheros incluidos en el directorio test_data/ no son maliciosos y están ahí únicamente para pruebas y demostraciones:

eicar_placeholder.com / eicar_placeholder → cadena de prueba (placeholder) no dañina — no es código ejecutable malicioso.

notepad_sample.exe → copia de un binario de sistema o archivo de prueba no malicioso.

random.bin, wordlist.txt → datos de ejemplo.

No ejecutar muestras desconocidas fuera de un entorno controlado.

3. Uso autorizado y responsabilidades

El usuario declara que usará SecurityP1 únicamente en entornos sobre los que tiene autorización expresa.

Está terminantemente prohibido usar esta herramienta para comprometer, dañar, escanear o explotar sistemas ajenos sin consentimiento documentado.

El desarrollador y/o mantenedor de SecurityP1 no son responsables por el mal uso, daños, pérdida de datos, interrupciones de servicio ni por acciones legales derivadas del uso indebido de la herramienta.

4. Recomendaciones de seguridad para pruebas

Antes de ejecutar cualquier análisis o carga (upload) de archivos potencialmente sospechosos o ejecutar utilidades que interactúen con el sistema o la red:

## Aísle el entorno

Use máquinas virtuales (VM) o entornos aislados (snapshots) dedicados para análisis.

Desconecte la red si el análisis no requiere acceso a Internet; o use redes controladas (laboratorio).

## Haga snapshots / backups

Tome snapshots de su VM o copias de seguridad antes de ejecutar análisis que puedan modificar el sistema.

## Control de muestras y datos

No suba muestras con datos sensibles, credenciales, claves privadas o información personal identificable (PII) a servicios externos (VirusTotal, FileScan, etc.) sin política clara o autorización.

Tenga en cuenta las políticas de privacidad y retención de terceros: subir una muestra puede hacerla pública o conservarla en sus servicios.

# Permisos y cumplimiento

Obtenga aprobación por escrito del propietario del sistema objetivo antes de ejecutar pruebas.

Cumpla todas las leyes locales, nacionales e internacionales aplicables.

5. API keys y credenciales

No incluya claves ni credenciales en el repositorio ni en ficheros públicos.

Configure variables de entorno para las API keys:

VT_API_KEY → VirusTotal (si aplica)

FILESCAN_API_KEY → FileScan.io (si aplica)

La herramienta no almacena claves en el repositorio por defecto; el usuario es responsable de protegerlas.

6. Reportes y datos generados

SecurityP1 genera reportes en reports/ por defecto (JSON / TXT). Revise su contenido antes de compartirlos públicamente: pueden contener metadatos, rutas o hashes.

Si usa la API local o servicios remotos, verifique qué información se transmite y cómo se almacena en el servicio remoto.

7. Limitaciones técnicas

Algunas funcionalidades dependen de herramientas externas (ClamAV, nmap, objdump, strace, ltrace, yara, etc.). Instale y mantenga estas herramientas por separado; no forman parte del repositorio Python.

La exactitud de resultados provenientes de servicios externos (VirusTotal, FileScan) depende de las políticas y la cobertura de esos servicios.

8. Privacidad y protección de datos

Evite subir muestras que contengan datos de clientes, usuarios o información legalmente protegida.

Si por error se sube información sensible a servicios externos, contacte inmediatamente con el proveedor para solicitar eliminación y siga los procedimientos de notificación que su organización tenga definidos.

9. Riesgo y limitación de responsabilidad

SecurityP1 se provee “tal cual” sin garantías implícitas o explícitas. En la medida máxima permitida por la ley, los autores / mantenedores no serán responsables por daños directos, indirectos, incidentales, consecuentes o punitivos derivados del uso o incapacidad de uso de la herramienta.

El uso es bajo su propia responsabilidad.

10. Buenas prácticas para uso responsable

Documente todas las pruebas (objetivo, alcance, fecha/hora, autor/autorización).

Use entornos reproducibles (VMs, containers).

Automatice el guardado de reportes en reports/ y mantenga control de versiones y acceso.

Revise y cierre accesos de red que no se requieran.

Establezca retención y eliminación de muestras y reportes conforme a políticas de la organización.

11. Contacto y contribuciones

Para reportar bugs, mejoras o dudas, abra un issue en el repositorio (si aplica) o contacte al mantenedor.

Las contribuciones que agreguen funcionalidades de análisis activo (explotación, fuzzing, pentesting automatizado) requerirán documentación adicional sobre responsabilidades y mitigaciones.

12. Aceptación

Al usar SecurityP1, el usuario acepta estas condiciones y declara que entiende los riesgos asociados.

---
