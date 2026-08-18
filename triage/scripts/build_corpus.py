#!/usr/bin/env python3
"""Fetch and chunk the 3GPP spec corpus for triage's query_3gpp_spec tool.

Pinned to the stable 19.x series (chosen over the 20.0.0 drafts — see
../docs/adr/0002-triage-v1-implementation-choices.md):

    TS 24.501 (NAS-5G)  j70 = V19.7.0
    TS 38.413 (NGAP)    j30 = V19.3.0
    TS 29.244 (PFCP)    j60 = V19.6.0
    TS 29.500 (SBI)     j70 = V19.7.0
    TS 29.503 (SBI-UDM) j70 = V19.7.0
    TS 29.531 (SBI-NSSF) j70 = V19.7.0

Downloads each spec's docx archive from 3GPP's own archive, converts the
docx to text preserving the clause tree, and writes one chunk per clause
(parent overviews and leaf definitions alike, split at table-row boundaries
when a clause is large). Output is committed
(triage/corpus/chunks.jsonl + manifest.json); the zip/docx cache under
triage/corpus/cache/ is gitignored.

This is a one-time / version-bump build step, not part of triage
invocations. Run from triage/ (python-docx comes from the pyproject dev
group, so no --with is needed):

    uv sync                                   # once: installs the dev group
    uv run scripts/build_corpus.py            # rebuild
    uv run scripts/build_corpus.py --no-fetch # cached zips
    uv run scripts/build_corpus.py --spec 24501

Notes on 3GPP's docx quirks, all handled here:
- The archive blocks non-browser clients: downloads send a browser
  User-Agent and a Referer to the listing page (plain curl gets 403).
- Heading STYLES ("Heading 1..9") do not encode hierarchy (an annex heading
  may be Heading 8 with its A.1 clauses as Heading 1) — the clause NUMBER
  does. The clause tree is built by number-prefix matching, with annex
  headings mapped to a single-letter token ("Annex A" -> "A").
- Some specs split the spec into several docx parts (24501 k00 does); the
  zip's docx files are processed in filename order.
- The table of contents ("toc 1..5" styles) and the "Contents"/list-of
  tables/figures headings are dropped — they would only pollute retrieval.
"""

import argparse
import hashlib
import io
import json
import re
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen

import docx
from docx.table import Table
from docx.text.paragraph import Paragraph

HERE = Path(__file__).resolve().parent
CORPUS = HERE.parent / "corpus"
CACHE = CORPUS / "cache"

BASE = "https://www.3gpp.org/ftp/Specs/archive"
UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/126.0 Safari/537.36")

# spec -> (archive dir, pinned zip token, title)
SPECS = {
    "24501": ("24_series/24.501", "j70", "TS 24.501"),
    "38413": ("38_series/38.413", "j30", "TS 38.413"),
    "29244": ("29_series/29.244", "j60", "TS 29.244"),
    "29500": ("29_series/29.500", "j70", "TS 29.500"),
    "29503": ("29_series/29.503", "j70", "TS 29.503"),
    "29531": ("29_series/29.531", "j70", "TS 29.531"),
}

# 3GPP zip token letter -> release number; the digits are the version * 10.
# Verified against the specs themselves: 38413-j30's title page says V19.3.0.
RELEASE_BY_LETTER = {"g": 16, "h": 17, "i": 18, "j": 19, "k": 20}

MAX_CHARS = 6000  # pack units into a chunk up to this size
MIN_CHARS = 80    # drop clauses whose whole text is below this

CLS = re.compile(r"^\d+(?:\.\d+)*[A-Z]?$")   # "5", "5.5.1", "4.2A"
ANNEX = re.compile(r"^Annex\s+([A-Z])\b", re.I)
SKIP_TITLES = re.compile(r"^(Contents|List of tables|List of figures)$", re.I)
VERSION = re.compile(r"\bV(\d+\.\d+\.\d+)\b")


def fetch(spec, token):
    """Download one spec archive (cached). Returns the zip path."""
    archive_dir = SPECS[spec][0]
    zip_name = f"{spec}-{token}.zip"
    zip_path = CACHE / zip_name
    if zip_path.exists():
        return zip_path
    CACHE.mkdir(parents=True, exist_ok=True)
    url = f"{BASE}/{archive_dir}/{zip_name}"
    print(f"downloading {url}")
    request = Request(url, headers={
        "User-Agent": UA,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Referer": f"{BASE}/{archive_dir}/",
    })
    with urlopen(request, timeout=180) as response:
        zip_path.write_bytes(response.read())
    return zip_path


def _normalize(text):
    """Collapse whitespace but KEEP the tab that separates the clause
    number from the title ("9.1.1\\tPresence")."""
    return " ".join(
        re.sub(r"[^\S\t]+", " ", line) for line in text.splitlines()).strip()


def clause_token(heading_text):
    """'5.5.1' -> '5.5.1', '4.2A' -> '4.2A', 'Annex A (...)' -> 'A',
    else None for an unnumbered heading."""
    text = _normalize(heading_text)
    if match := ANNEX.match(text):
        return match.group(1)
    field = text.split("\t", 1)[0].strip()
    return field if CLS.match(field) else None


def heading_title(heading_text):
    """The title part of a heading: everything after the clause number."""
    text = _normalize(heading_text)
    if "\t" in text:
        return text.split("\t", 1)[1].strip()
    return text


def iter_blocks(element):
    """Yield ('p'|'t', child) for paragraphs/tables at this level,
    descending into sdt wrappers but not into table cells."""
    for child in element.iterchildren():
        tag = child.tag
        if tag.endswith("}p"):
            yield "p", child
        elif tag.endswith("}tbl"):
            yield "t", child
        elif tag.endswith("}sdt"):
            yield from iter_blocks(child)


def iter_units(document):
    """Yield ('h'|'p'|'r', text) for the document body in reading order."""
    for kind, child in iter_blocks(document.element.body):
        if kind == "p":
            paragraph = Paragraph(child, document)
            style = (paragraph.style.name or "").lower()
            if style.startswith("toc"):
                continue
            if style.startswith("heading"):
                yield "h", paragraph.text
            elif paragraph.text.strip():
                # NBSPs are scattered through 3GPP's text; normalize them so
                # embedding tokenization sees plain spaces.
                yield "p", paragraph.text.replace("\xa0", " ")
        else:
            table = Table(child, document)
            for row in table.rows:
                cells = [" ".join(cell.text.split()) for cell in row.cells]
                yield "r", " | ".join(cells)


def _slices(text, max_chars):
    """Split one oversized unit at word boundaries into max_chars slices."""
    if len(text) <= max_chars:
        return [text]
    out, buf = [], ""
    for word in text.split(" "):
        if buf and len(buf) + len(word) + 1 > max_chars:
            out.append(buf)
            buf = word
        else:
            buf = f"{buf} {word}" if buf else word
    if buf:
        out.append(buf)
    return out


def pack(units, max_chars=MAX_CHARS):
    """Greedily pack units into bodies of at most max_chars (a unit is a
    paragraph or a table row, so a big table splits on row boundaries; a
    single unit larger than a chunk is word-sliced)."""
    parts, current, size = [], [], 0
    for _, text in units:
        for piece in _slices(text, max_chars):
            if current and size + len(piece) > max_chars:
                parts.append("\n\n".join(current))
                current, size = [], 0
            current.append(piece)
            size += len(piece)
    if current:
        parts.append("\n\n".join(current))
    return parts


def build_chunks(spec, title, token, version, units):
    """Build the clause tree from units and emit one chunk per clause."""
    root = {"clause": None, "heading": "", "units": [], "children": []}
    stack = [root]
    for kind, text in units:
        if kind == "h":
            tok = clause_token(text)
            if tok is None:
                # Unnumbered heading: fold into the current node's body.
                if stack[-1] is not root:
                    stack[-1]["units"].append(("p", text))
                continue
            node = {"clause": tok, "heading": heading_title(text),
                    "units": [], "children": []}
            if SKIP_TITLES.match(node["heading"]):
                # Contents / list-of-*: keep the node on the stack so its
                # children are absorbed, but never attach or emit it.
                stack.append(node)
                continue
            while (stack[-1] is not root
                   and (stack[-1]["clause"] is None
                        or not tok.startswith(stack[-1]["clause"] + "."))):
                stack.pop()
            stack[-1]["children"].append(node)
            stack.append(node)
        elif stack[-1] is not root and stack[-1]["clause"] is not None:
            stack[-1]["units"].append((kind, text))

    chunks = []

    def emit(node, crumbs):
        if node["clause"] is not None:
            heading_line = f'{node["clause"]}\t{node["heading"]}'
            bodies = pack(node["units"])
            text = [heading_line] + bodies
            if sum(len(part) for part in text) >= MIN_CHARS:
                header = f"{title} V{version} | {heading_line}"
                breadcrumb = "".join(f"[under: {line}] " for line in crumbs)
                for i, body in enumerate(bodies):
                    label = heading_line
                    if len(bodies) > 1:
                        label = f"{heading_line} (continued {i + 1}/{len(bodies)})"
                    chunks.append({
                        "spec": spec, "title": title, "token": token,
                        "version": version, "clause": node["clause"],
                        "heading": node["heading"],
                        "breadcrumb": list(crumbs),
                        "text": f"{header}\n{breadcrumb}{body}"
                                if not breadcrumb else f"{header}\n{breadcrumb}\n{body}",
                        "chars": len(body),
                    })
            crumbs = crumbs + [heading_line]
        for child in node["children"]:
            emit(child, crumbs)

    emit(root, [])
    return chunks


def spec_version(units):
    for _, text in units:
        if match := VERSION.search(text):
            return match.group(1)
    return None


def token_version(token):
    release = RELEASE_BY_LETTER.get(token[0])
    if release is None or not token[1:].isdigit():
        return None
    digits = int(token[1:])
    return f"{release}.{digits // 10}.{digits % 10}"


def build_one(spec, no_fetch):
    archive_dir, token, title = SPECS[spec]
    zip_path = CACHE / f"{spec}-{token}.zip"
    if not no_fetch or not zip_path.exists():
        zip_path = fetch(spec, token)
    sha256 = hashlib.sha256(zip_path.read_bytes()).hexdigest()
    with zipfile.ZipFile(zip_path) as archive:
        docx_names = sorted(
            name for name in archive.namelist() if name.lower().endswith(".docx"))
        units = []
        for name in docx_names:
            units.extend(iter_units(docx.Document(io.BytesIO(archive.read(name)))))
    version = spec_version(units) or token_version(token)
    if version is None:
        sys.exit(f"error: cannot determine version for {spec}-{token}")
    chunks = build_chunks(spec, title, token, version, units)
    print(f"{title} {token} V{version}: {len(chunks)} chunks "
          f"from {len(docx_names)} docx")
    return spec, {
        "title": title, "token": token, "version": version,
        "zip": f"{spec}-{token}.zip", "zip_sha256": sha256,
        "docx": docx_names, "chunks": len(chunks),
        "chars": sum(chunk["chars"] for chunk in chunks),
    }, chunks


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("--spec", choices=sorted(SPECS),
                        help="build only this one spec")
    parser.add_argument("--no-fetch", action="store_true",
                        help="use the cached zips only, never download")
    args = parser.parse_args()

    specs = [args.spec] if args.spec else list(SPECS)
    manifest = {"built": datetime.now(timezone.utc).isoformat(), "specs": {}}
    all_chunks = []
    for spec in specs:
        spec, entry, chunks = build_one(spec, args.no_fetch)
        manifest["specs"][spec] = entry
        all_chunks.extend(chunks)

    CORPUS.mkdir(exist_ok=True)
    (CORPUS / "chunks.jsonl").write_text(
        "\n".join(json.dumps(chunk, ensure_ascii=False)
                  for chunk in all_chunks) + "\n")
    (CORPUS / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"wrote {len(all_chunks)} chunks to {CORPUS / 'chunks.jsonl'}")


if __name__ == "__main__":
    main()
