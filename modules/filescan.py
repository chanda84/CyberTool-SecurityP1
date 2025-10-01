# modules/filescan.py
"""
FileScan.io wrapper - robusta para debugging.
Lee FILESCAN_API_KEY desde la variable de entorno.
Prueba endpoints y headers distintos; reintenta con verify=False si hay problemas TLS.
"""
import os
import time
import requests

ENDPOINTS = [
    "https://www.filescan.io/api/scan/file",
    "https://www.filescan.io/api/v2/file/scan",
    "https://www.filescan.io/api/v1/file/scan",
    "https://www.filescan.io/api/file/scan",
    "https://www.filescan.io/api/v2/scan/file",
]

REPORT_ENDPOINTS = [
    "https://www.filescan.io/api/reports",
    "https://www.filescan.io/api/v2/file/report",
    "https://www.filescan.io/api/v1/file/report",
    "https://www.filescan.io/api/file/report",
]

def _get_key():
    return os.environ.get("FILESCAN_API_KEY")

def upload_file(path, poll_until_complete=True, poll_interval=4, timeout=180):
    api_key = _get_key()
    if not api_key:
        return {"error": "FILESCAN_API_KEY not set in environment"}

    if not os.path.isfile(path):
        return {"error": "file not found", "path": path}

    headers_variants = [
        {"apikey": api_key},
        {"Authorization": f"Bearer {api_key}"},
        {"X-API-Key": api_key},
        {"x-apikey": api_key},
        {"x-api-key": api_key},
    ]

    tried = []

    for ep in ENDPOINTS:
        for hdr in headers_variants:
            for verify in (True, False):
                info = {"endpoint": ep, "header": hdr, "verify": verify}
                try:
                    with open(path, "rb") as fh:
                        files = {"file": (os.path.basename(path), fh)}
                        r = requests.post(ep, headers=hdr, files=files, timeout=60, verify=verify)
                    info["status_code"] = r.status_code
                    try:
                        info["body"] = r.json()
                    except Exception:
                        info["body"] = r.text[:4000]
                    tried.append(info)

                    if r.status_code in (200, 201):
                        result = {"endpoint": ep, "header_used": hdr, "status_code": r.status_code}
                        try:
                            result["raw"] = r.json()
                        except Exception:
                            result["raw"] = r.text

                        j = result.get("raw") if isinstance(result.get("raw"), dict) else {}
                        flow_id = j.get("flow_id") or j.get("id") or j.get("data", {}).get("id") or j.get("job_id")

                        if poll_until_complete and flow_id:
                            start = time.time()
                            for rep_ep in REPORT_ENDPOINTS:
                                candidate = f"{rep_ep}/{flow_id}"
                                while time.time() - start < timeout:
                                    try:
                                        rr = requests.get(candidate, headers=hdr, timeout=30, verify=verify)
                                        if rr.status_code == 200:
                                            jr = rr.json()
                                            if isinstance(jr, dict) and (
                                                jr.get("status") in ("completed", "done")
                                                or jr.get("report") or jr.get("analysis")
                                            ):
                                                sha256 = None
                                                if "analysis" in jr:
                                                    sha256 = jr["analysis"].get("target", {}).get("sha256")
                                                elif "report" in jr:
                                                    sha256 = jr["report"].get("sha256")
                                                result.update({
                                                    "report": jr,
                                                    "report_endpoint": candidate,
                                                    "sha256": sha256,
                                                    "url": f"https://www.filescan.io/scan/{flow_id}",
                                                    "tried": tried,
                                                })
                                                return result
                                    except Exception:
                                        pass
                                    time.sleep(poll_interval)
                            result["warning"] = "no report found within timeout"
                            return result
                        return result

                    if r.status_code in (401, 403):
                        return {"error": "unauthorized", "status_code": r.status_code, "body": info.get("body"), "tried": tried}
                except Exception as e:
                    info["exception"] = str(e)
                    tried.append(info)

    return {"error": "upload failed", "detail": "no endpoint/header returned success", "tried": tried}
