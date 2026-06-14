#!/usr/bin/env python3
import json, re, sys, subprocess, tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from analyze_package import read_package_json, collect_hook_sources, analyze_text, score_categories

def main():
    if len(sys.argv) != 2:
        print("Usage: scan_deps.py <package.json>")
        sys.exit(1)

    pjson = Path(sys.argv[1])
    data = json.loads(pjson.read_text(encoding="utf-8"))

    pkgs = {}
    for section in ("dependencies", "devDependencies"):
        for name, ver in data.get(section, {}).items():
            clean = re.sub(r"[^0-9.]", "", ver.split(" ")[0])
            pkgs[name] = clean

    print(f"[*] {len(pkgs)}개 패키지 분석 시작 (정적 분석만)\n")
    results = []

    with tempfile.TemporaryDirectory() as tmp:
        tmpdir = Path(tmp)
        for i, (name, ver) in enumerate(pkgs.items(), 1):
            spec = f"{name}@{ver}" if ver else name
            print(f"[{i}/{len(pkgs)}] {spec}", end=" ", flush=True)

            safe = name.replace("/", "_").replace("@", "")
            out = tmpdir / safe
            out.mkdir(parents=True, exist_ok=True)

            r = subprocess.run(
                ["npm", "pack", spec, "--pack-destination", str(out)],
                capture_output=True, text=True
            )

            if r.returncode != 0:
                print("-> skip (pack failed)")
                continue

            tgz_files = list(out.glob("*.tgz"))
            if not tgz_files:
                print("-> skip (no tgz)")
                continue

            unpack = out / "u"
            unpack.mkdir()
            subprocess.run(
                ["tar", "xzf", str(tgz_files[0]), "-C", str(unpack), "--strip-components=1"],
                capture_output=True
            )

            pkg_json = unpack / "package.json"
            if not pkg_json.exists():
                print("-> skip (no package.json)")
                continue

            try:
                pkg = json.loads(pkg_json.read_text(encoding="utf-8"))
                scripts = pkg.get("scripts", {})
                sources = collect_hook_sources(unpack, scripts)
                max_score, max_level, top_reasons = 0, "Low", []
                for hook, src in sources.items():
                    cats, _ = analyze_text(src)
                    score, level, reasons = score_categories(cats)
                    if score > max_score:
                        max_score, max_level, top_reasons = score, level, reasons
                results.append((name, ver, max_score, max_level, top_reasons))
                print(f"-> {max_level} ({max_score})")
            except Exception as e:
                print(f"-> error ({e})")

    results.sort(key=lambda x: -x[2])

    print("\n" + "="*65)
    print(f"{'Package':<38} {'Score':>5}  Risk")
    print("="*65)
    for name, ver, score, level, _ in results:
        flag = "  ◀ REVIEW" if level == "High" else ""
        print(f"{name:<38} {score:>5}  {level}{flag}")
    print("="*65)

    high = [r for r in results if r[3] == "High"]
    med  = [r for r in results if r[3] == "Medium"]
    low  = [r for r in results if r[3] == "Low"]
    print(f"\nHigh: {len(high)}  Medium: {len(med)}  Low: {len(low)}")

    if high:
        print("\n[!] High 패키지 근거:")
        for name, ver, score, level, reasons in high:
            print(f"\n  {name}@{ver}  score={score}")
            for r in reasons:
                print(f"    {r}")

if __name__ == "__main__":
    main()
