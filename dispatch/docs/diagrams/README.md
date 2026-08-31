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
file is the only renderer that works. Style 2's font stack is
`'SF Mono', 'Fira Code', Menlo, …`, so the Fira Code 6.2 TTFs (from the
[release zip](https://github.com/tonsky/FiraCode/releases/tag/6.2),
`ttf/` directory) match as-is — no renaming:

```
uv venv /tmp/diagram-venv
uv pip install --python /tmp/diagram-venv/bin/python resvg-py
/tmp/diagram-venv/bin/python3 - <<'EOF'
import resvg_py
png = resvg_py.svg_to_bytes(svg_path="pipeline.svg", width=1334,
    font_files=["/tmp/firacode/ttf/FiraCode-Regular.ttf",
                "/tmp/firacode/ttf/FiraCode-Medium.ttf",
                "/tmp/firacode/ttf/FiraCode-SemiBold.ttf",
                "/tmp/firacode/ttf/FiraCode-Bold.ttf"])
open("pipeline.png", "wb").write(png)
EOF
```

The failure mode is a silently textless PNG, so verify before
committing: crop the title band (y≈20–58) of the PNG and assert it
contains non-zero near-white pixels on the dark canvas. The `check`
gate on the SVG does not cover this.
