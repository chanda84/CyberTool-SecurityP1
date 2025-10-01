# modules/vt.py
"""
VirusTotal v3 small helper.
Lee la API key dinámicamente desde la variable de entorno VT_API_KEY
y expone:
 - upload_file(path)
 - get_file_report_by_hash(hash_value)
"""
import os
import time
import requests

VT_API_BASE = "https://www.virustotal.com/api/v3"

def _get_headers():
    api_key = os.environ.get("VT_API_KEY")
    if not api_key:
        return None, {"error": "VT_API_KEY not set in environment"}
    return {"x-apikey": api_key}, None

def upload_file(path, poll_until_complete=True, poll_interval=5, timeout=300):
    headers, err = _get_headers()
    if err:
        return err

    if not os.path.isfile(path):
        return {"error": "file not found", "path": path}

    url = f"{VT_API_BASE}/files"
    try:
        with open(path, "rb") as fh:
            files = {"file": (os.path.basename(path), fh)}
            resp = requests.post(url, headers=headers, files=files, timeout=60)
        if resp.status_code not in (200, 201):
            return {"error": "upload failed", "status_code": resp.status_code, "text": resp.text}
        j = resp.json()
        data_id = j.get("data", {}).get("id")
        if not data_id:
            return {"error": "no analysis id returned", "raw": j}
        result = {"analysis_id": data_id, "raw": j}
        if poll_until_complete:
            start = time.time()
            analyses_url = f"{VT_API_BASE}/analyses/{data_id}"
            while True:
                r2 = requests.get(analyses_url, headers=headers, timeout=30)
                if r2.status_code != 200:
                    return {"error": "analysis status check failed", "status_code": r2.status_code, "text": r2.text}
                j2 = r2.json()
                status = j2.get("data", {}).get("attributes", {}).get("status")
                if status == "completed":
                    result["analysis_report"] = j2
                    return result
                if time.time() - start > timeout:
                    result["timeout"] = True
                    return result
                time.sleep(poll_interval)
        return result
    except Exception as e:
        return {"error": "exception uploading file", "detail": str(e)}

def get_file_report_by_hash(hash_value):
    headers, err = _get_headers()
    if err:
        return err
    url = f"{VT_API_BASE}/files/{hash_value}"
    try:
        r = requests.get(url, headers=headers, timeout=30)
        if r.status_code == 200:
            return {"report": r.json()}
        else:
            return {"error": "lookup failed", "status_code": r.status_code, "text": r.text}
    except Exception as e:
        return {"error": "exception getting file report", "detail": str(e)}
