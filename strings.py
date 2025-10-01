# strings.py
import argparse
import re

def extract_strings(file_path, min_length=4):
    pattern = re.compile(b"[ -~]{%d,}" % min_length)  # caracteres imprimibles
    results = []
    try:
        with open(file_path, "rb") as f:
            data = f.read()
            for match in pattern.finditer(data):
                results.append(match.group().decode("utf-8", errors="ignore"))
    except Exception as e:
        results.append(f"[ERROR] {e}")
    return results

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Strings extractor (Windows compatible)")
    parser.add_argument("target", help="Archivo a analizar")
    parser.add_argument("--min", type=int, default=4, help="Longitud mínima de cadenas")
    args = parser.parse_args()

    strings = extract_strings(args.target, args.min)
    for s in strings:
        print(s)
