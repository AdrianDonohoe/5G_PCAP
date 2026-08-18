# docs/diagrams

Diagrams for the top-level docs and the Medium article
(`the-llm-proposes-the-code-disposes.md`).

- `article-flow.json` — fireworks-tech-graph diagram IR.
- `article-flow.svg` — rendered from the IR with
  [fireworks-tech-graph](https://github.com/yizhiyanhua-ai/fireworks-tech-graph):
  `python3 scripts/fireworks.py render agent article-flow.json article-flow.svg`
- `article-flow.png` — raster export for Medium (which can't host SVG).

The PNG has two traps on this VM: there is no system font directory (so a
font must be loaded explicitly) and no Cairo (so cairosvg/renderPM are out).
It is produced with [resvg-py](https://pypi.org/project/resvg-py/) plus
Fira Code — the SVG's font stack names Fira Code, and without a font file
resvg draws no text at all (MuPDF and svglib fail the same way: MuPDF
ignores the SVG's CSS classes and draws black-on-black; renderPM needs
Cairo). Fira Code TTFs are in the
[FiraCode 6.2 release](https://github.com/tonsky/FiraCode/releases/tag/6.2).

```
python3 - <<'EOF'
import resvg_py

fonts = [
    "…/FiraCode-Regular.ttf",
    "…/FiraCode-Medium.ttf",
    "…/FiraCode-SemiBold.ttf",
    "…/FiraCode-Bold.ttf",
]
png = resvg_py.svg_to_bytes(svg_path="article-flow.svg", width=1334,
                            font_files=fonts)
open("article-flow.png", "wb").write(png)
EOF
```
