# modules/forensics.py
import os
import hashlib

def compute_hashes(path):
    """Devuelve md5, sha1, sha256 del archivo."""
    if not os.path.isfile(path):
        return {"error": "file not found", "path": path}
    h_md5 = hashlib.md5()
    h_sha1 = hashlib.sha1()
    h_sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            h_md5.update(chunk)
            h_sha1.update(chunk)
            h_sha256.update(chunk)
    return {
        "path": path,
        "md5": h_md5.hexdigest(),
        "sha1": h_sha1.hexdigest(),
        "sha256": h_sha256.hexdigest()
    }

def run(args):
    # acepta --file-hash <ruta>
    target = getattr(args, "file_hash", None)
    if not target:
        print("[FORENSICS] No file specified. Use --file-hash <path>")
        return
    res = compute_hashes(target)
    print("[FORENSICS] Hashes result:")
    for k, v in res.items():
        print(f"  {k}: {v}")
    return res
