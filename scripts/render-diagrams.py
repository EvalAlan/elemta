#!/usr/bin/env python3
"""Render the documentation diagrams from Mermaid sources to PNG.

The diagrams in the README and docs/architecture.md are PNG images, so they
look the same everywhere. Their sources are the .mmd files beside them in
docs/diagrams/. Edit a source, then run this script to regenerate its image:

    scripts/render-diagrams.py            # every diagram
    scripts/render-diagrams.py compose    # just docs/diagrams/compose.mmd

It needs Chromium (or Chrome) and network access to load Mermaid from the
jsDelivr CDN. Mermaid is pinned, so the same source always renders the same.
"""

import html
import json
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

MERMAID = "https://cdn.jsdelivr.net/npm/mermaid@10.9.1/dist/mermaid.min.js"
ROOT = pathlib.Path(__file__).resolve().parent.parent
DIAGRAMS = ROOT / "docs" / "diagrams"
SCALE = 2  # device pixels per CSS pixel, so the PNGs stay sharp when zoomed
PAD = 24

PAGE = """<!doctype html><html><head><meta charset="utf-8"><style>
body {{ margin: 0; background: #fff; }}
#d {{ display: inline-block; padding: {pad}px; }}
</style></head><body><div id="d"></div><script src="{mermaid}"></script><script>
mermaid.initialize({{startOnLoad: false, theme: "default", securityLevel: "strict",
  flowchart: {{useMaxWidth: false, htmlLabels: true}}, sequence: {{useMaxWidth: false, actorMargin: 40, width: 130, noteMargin: 8}},
  themeVariables: {{fontFamily: "Helvetica, Arial, sans-serif", fontSize: "15px"}}}});
mermaid.render("svg", {source}).then(r => {{
  const d = document.getElementById("d");
  d.innerHTML = r.svg;
  const box = d.getBoundingClientRect();
  document.title = "SIZE " + Math.ceil(box.width) + "x" + Math.ceil(box.height);
}}).catch(e => {{ document.title = "ERROR " + e.message; }});
</script></body></html>"""


def chromium():
    for name in ("chromium", "chromium-browser", "google-chrome-stable", "google-chrome"):
        path = shutil.which(name)
        if path:
            return path
    sys.exit("render-diagrams: Chromium or Chrome is required")


def headless(browser, *args):
    cmd = [browser, "--headless=new", "--disable-gpu", "--no-sandbox", "--hide-scrollbars",
           "--virtual-time-budget=20000", *args]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=120)


def render(browser, source: pathlib.Path, work: pathlib.Path):
    page = work / (source.stem + ".html")
    page.write_text(PAGE.format(pad=PAD, mermaid=MERMAID, source=json.dumps(source.read_text())))
    # First pass: lay the diagram out and read its size from the title.
    out = headless(browser, "--window-size=4000,4000", "--dump-dom", page.as_uri()).stdout
    title = re.search(r"<title>(.*?)</title>", out)
    if not title or not title.group(1).startswith("SIZE "):
        reason = html.unescape(title.group(1)) if title else "no output"
        sys.exit(f"render-diagrams: {source.name}: {reason}")
    width, height = (int(v) for v in title.group(1)[5:].split("x"))
    # Second pass: a window exactly that size, captured at SCALE.
    png = source.with_suffix(".png")
    headless(browser, f"--window-size={width},{height}", f"--force-device-scale-factor={SCALE}",
             f"--screenshot={png}", page.as_uri())
    if not png.exists():
        sys.exit(f"render-diagrams: {source.name}: no screenshot written")
    print(f"{png.relative_to(ROOT)}  {width}x{height} at {SCALE}x")


def main():
    browser = chromium()
    wanted = set(sys.argv[1:])
    sources = sorted(p for p in DIAGRAMS.glob("*.mmd") if not wanted or p.stem in wanted)
    if wanted and len(sources) != len(wanted):
        sys.exit("render-diagrams: unknown diagram; sources are in docs/diagrams/*.mmd")
    with tempfile.TemporaryDirectory() as work:
        for source in sources:
            render(browser, source, pathlib.Path(work))


if __name__ == "__main__":
    main()
