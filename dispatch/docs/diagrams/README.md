# dispatch/docs/diagrams

- `pipeline.json` — fireworks-tech-graph diagram IR for the Dispatch
  pipeline, embedded in the dispatch README.
- `pipeline.svg` — rendered from the IR with
  [fireworks-tech-graph](https://github.com/yizhiyanhua-ai/fireworks-tech-graph):
  `python3 scripts/fireworks.py render agent pipeline.json pipeline.svg`
  (run from this directory; `check` and `inspect` validate it).
- `pipeline.png` — raster export for the README (GitHub does not render
  SVG files inline in markdown).
- `pipeline.mmd` — LangGraph's own view of the compiled graph
  (`graph.get_graph().draw_mermaid()` on `build_graph`), kept beside the
  designed diagram for comparison: the literal node/edge topology, with
  no containers, flows or gate semantics. Regenerate from the dispatch
  venv:

  ```
  cd dispatch && .venv/bin/python3 -c "from dispatch.graph import build_graph; \
  print(build_graph('/tmp/mm/state/checkpoints.sqlite', '/tmp/mm/records', \
  '/tmp/mm/sandbox').get_graph().draw_mermaid())"
  ```

The PNG has the same two traps as
[`../../docs/diagrams/README.md`](../../docs/diagrams/README.md): no
system font directory and no Cairo, so resvg-py plus an explicit font
file is the only renderer that works. One more trap is specific to
style 1: its CSS font stack is `'Helvetica Neue', Helvetica, Arial, …`
— not Fira Code — so passing Fira Code TTFs as-is draws **no text at
all**. Rename the family of the Fira Code 6.2 TTFs (from the
[release zip](https://github.com/tonsky/FiraCode/releases/tag/6.2),
`ttf/` directory) to "Helvetica Neue" first, then export and verify:

```
uv venv /tmp/diagram-venv
uv pip install --python /tmp/diagram-venv/bin/python resvg-py fonttools
python3 - <<'EOF'   # one-time: family-rename the four weights
from fontTools.ttLib import TTFont
for weight in ["Regular", "Medium", "SemiBold", "Bold"]:
    f = TTFont(f"/tmp/firacode/ttf/FiraCode-{weight}.ttf")
    f["name"].setName("Helvetica Neue", 1, 3, 1, 0x409)
    f["name"].setName("Helvetica Neue", 16, 3, 1, 0x409)
    f.save(f"/tmp/helv/HelveticaNeue-{weight}.ttf")
EOF
/tmp/diagram-venv/bin/python3 - <<'EOF'
import resvg_py
png = resvg_py.svg_to_bytes(svg_path="pipeline.svg", width=1334,
    font_files=["/tmp/helv/HelveticaNeue-Regular.ttf",
                "/tmp/helv/HelveticaNeue-Medium.ttf",
                "/tmp/helv/HelveticaNeue-SemiBold.ttf",
                "/tmp/helv/HelveticaNeue-Bold.ttf"])
open("pipeline.png", "wb").write(png)
EOF
```

The failure mode is a silently textless PNG, so verify before
committing: crop the title band (y≈20–58) of the PNG and assert it
contains non-zero near-black pixels. The `check` gate on the SVG does
not cover this.
