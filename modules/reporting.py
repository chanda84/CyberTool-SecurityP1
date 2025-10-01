# modules/reporting.py
import os
import json
from datetime import datetime
import sys
sys.stdout.reconfigure(encoding="utf-8")

REPORTS_DIR = "reports"
os.makedirs(REPORTS_DIR, exist_ok=True)

def _save_raw(case_id, module, action, data):
    safe_case = case_id or "CASE-0001"
    ts = datetime.utcnow().isoformat().replace(":", "-")
    filename = f"{safe_case}_{module}_{action}_{ts}.json"
    path = os.path.join(REPORTS_DIR, filename)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)
    return path

def _normalize_vt_report(response):
    """
    Devuelve (report_dict, filename_hint) o (None, None) si no hay report.
    Soporta varias formas:
      - {'report': {...}}
      - {'analysis_report': {...}}
      - {'raw': {...}} (respuesta cruda del upload)
      - {'data': {...}} (ya es un objeto tipo VT)
    """
    if not response or not isinstance(response, dict):
        return None, None

    if "error" in response:
        return {"error": response.get("error"), "detail": response.get("detail")}, None

    # common wrappers
    if "report" in response and isinstance(response["report"], dict):
        report = response["report"]
        # filename hint: maybe names in attributes
        names = (report.get("data", {}) .get("attributes", {}) .get("names")) if isinstance(report.get("data"), dict) else None
        hint = names[0] if names else None
        return report, hint

    if "analysis_report" in response and isinstance(response["analysis_report"], dict):
        report = response["analysis_report"]
        hint = None
        try:
            hint = report.get("data", {}).get("attributes", {}).get("names", [None])[0]
        except Exception:
            hint = None
        return report, hint

    if "raw" in response and isinstance(response["raw"], dict):
        raw = response["raw"]
        # raw may contain 'data' with item link to file; try to use it
        hint = None
        try:
            hint = raw.get("data", {}).get("attributes", {}).get("names", [None])[0]
        except Exception:
            hint = None
        return raw, hint

    if "data" in response and isinstance(response["data"], dict):
        # looks already like VT object
        hint = None
        try:
            hint = response.get("data", {}).get("attributes", {}).get("names", [None])[0]
        except Exception:
            hint = None
        return response, hint

    # fallback: return whole thing
    return response, None

def _pretty_print_vt(report_obj, filename_hint=None):
    """
    Retorna string bonito resumen del report_obj.
    """
    if not report_obj:
        return "[VT] No hay datos para mostrar."

    if "error" in report_obj:
        s = f"[VT] ERROR: {report_obj.get('error')}"
        if report_obj.get("detail"):
            s += f"\nDetalle: {report_obj.get('detail')}"
        return s

    data = report_obj.get("data") if isinstance(report_obj, dict) else None
    attributes = {}
    if isinstance(data, dict):
        attributes = data.get("attributes", {}) or {}
    else:
        # try attributes at top-level
        attributes = report_obj.get("attributes", {}) or {}

    # filename / name / sha256
    name = filename_hint or (attributes.get("names", [None])[0] if attributes.get("names") else None)
    sha256 = (data.get("id") if isinstance(data, dict) else None) or (attributes.get("sha256") if attributes.get("sha256") else None)
    # stats
    stats = attributes.get("last_analysis_stats") or attributes.get("stats") or {}
    malicious = stats.get("malicious", 0)
    total = sum(v for v in stats.values()) if isinstance(stats, dict) and stats else 0
    tags = attributes.get("tags", []) or []
    reputation = attributes.get("reputation", "N/A")
    # detection engines
    scans = attributes.get("last_analysis_results") or attributes.get("results") or {}
    detections = [(e, v.get("result")) for e, v in scans.items() if v.get("category") == "malicious"]

    lines = []
    lines.append("[VT] Reporte de análisis")
    lines.append("-" * 40)
    lines.append(f"Archivo: {name or 'N/A'}")
    lines.append(f"SHA256: {sha256 or 'N/A'}")
    lines.append(f"Detecciones: {malicious} / {total}")
    if tags:
        lines.append(f"Etiquetas: {', '.join(tags)}")
    lines.append(f"Reputación: {reputation}")
    lines.append("")
    if detections:
        lines.append("Motores que lo detectaron:")
        for engine, result in detections:
            lines.append(f" - {engine}: {result}")
    else:
        lines.append("✅ Ningún motor lo marcó como malicioso")
    lines.append("-" * 40)
    return "\n".join(lines)

def present_vt_report(vt_response, filename_hint=None, case_id=None, module="malware", action="vt", output="both"):
    """
    Única función pública:
      - vt_response: objeto devuelto por tu wrapper (vt.upload_file / vt.get_file_report_by_hash)
      - filename_hint: nombre o path del archivo (solo para impresión)
      - case_id/module/action: metadatos para guardar
      - output: "console", "json" o "both"
    Comportamiento:
      - console -> imprime el resumen bonito (no guarda)
      - json    -> guarda el JSON crudo en reports/ y muestra la ruta guardada
      - both    -> guarda + muestra el resumen
    Devuelve dict con keys: {'pretty': <str>, 'saved_path': <path|None>, 'sha256': <str|None>}
    """
    vt_obj, hint = _normalize_vt_report(vt_response)
    filename_to_show = filename_hint or hint

    # prepare pretty
    pretty = _pretty_print_vt(vt_obj, filename_to_show)

    saved = None
    if output in ("json", "both"):
        try:
            saved = _save_raw(case_id, module, action, vt_response)
        except Exception as e:
            saved = f"ERROR_SAVING:{e}"

    if output in ("console", "both"):
        print(pretty)

    if output == "json":
        # only print a short message pointing where se guardó
        print(f"[REPORT] JSON guardado en: {saved}")

    # try to extract sha256
    sha256 = None
    try:
        if isinstance(vt_obj, dict):
            data = vt_obj.get("data")
            if isinstance(data, dict):
                sha256 = data.get("id")
            else:
                # maybe in attributes.meta.file_info
                attr = vt_obj.get("attributes") or {}
                meta = attr.get("meta", {}).get("file_info", {}) if isinstance(attr, dict) else {}
                sha256 = meta.get("sha256") or sha256
    except Exception:
        sha256 = None

    return {"pretty": pretty, "saved_path": saved, "sha256": sha256}
