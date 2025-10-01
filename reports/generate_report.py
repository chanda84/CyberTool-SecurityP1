#!/usr/bin/env python3
"""
Generador de informe Markdown a partir de los JSON guardados en reports/
Uso:
    python generate_report.py --case CASE-001
"""

import os
import json
import argparse
from datetime import datetime

REPORTS_DIR = "."

def load_reports(case_id):
    items = []
    for fname in os.listdir(REPORTS_DIR):
        if not fname.lower().endswith(".json"):
            continue
        if case_id and not fname.startswith(case_id):
            continue
        path = os.path.join(REPORTS_DIR, fname)
        try:
            with open(path, "r", encoding="utf-8") as f:
                j = json.load(f)
            items.append((fname, j))
        except Exception as e:
            print(f"[!] Error leyendo {fname}: {e}")
    # ordenar por timestamp si existe
    def ts_key(x):
        try:
            return x[1].get("timestamp","")
        except:
            return ""
    items.sort(key=ts_key)
    return items

def render_markdown(case_id, items, outpath):
    lines = []
    lines.append(f"# Informe agregado - {case_id}")
    lines.append(f"Generado: {datetime.utcnow().isoformat()}Z\n")
    for fname, data in items:
        lines.append(f"---\n## Archivo: `{fname}`")
        module = data.get("module", "unknown")
        action = data.get("action", "unknown")
        ts = data.get("timestamp", "")
        lines.append(f"- **Módulo**: {module}")
        lines.append(f"- **Acción**: {action}")
        lines.append(f"- **Timestamp**: {ts}\n")
        # Data - pretty print JSON in a fenced block
        pretty = json.dumps(data.get("data", data), indent=2, ensure_ascii=False)
        lines.append("``json")
        lines.append(pretty)
        lines.append("```\n")
    md = "\n".join(lines)
    with open(outpath, "w", encoding="utf-8") as f:
        f.write(md)
    print(f"[+] Informe Markdown guardado en: {outpath}")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--case", required=True, help="Case ID (ej: CASE-001)")
    parser.add_argument("--out", help="Ruta output (md). Si no, usa CASE-<id>_REPORT.md")
    args = parser.parse_args()
    case_id = args.case
    items = load_reports(case_id)
    if not items:
        print(f"No se encontraron reportes para {case_id} en {REPORTS_DIR}")
        return
    outpath = args.out if args.out else f"{case_id}_REPORT.md"
    render_markdown(case_id, items, outpath)

if __name__ == "__main__":
    main()
