#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Generate docs/references.md from the evidence IDs cited in the documents.

Every `[E:<id>]` tag found in README.md and docs/**/*.md (recursively; the two
generated files docs/references.md and docs/evidence/ledger.md are skipped) is
resolved against docs/evidence/research-findings.json. Ranges written as
`[E:a]～[E:b]` are expanded. Each entry shows the status, the claim (or, for a
contradicted claim, the correction) shortened to 180 characters, the
researcher's sources, and a link to its entry in docs/evidence/ledger.md.

The supplementary checks (S-xx) are not copied: the last section only links to
docs/01-research-survey.md section 4, which lists each check with its source
URLs and status.

    python tools/build_references.py           # (re)write docs/references.md
    python tools/build_references.py --check   # exit 1 if the file on disk is stale
"""
import argparse
import json
import pathlib
import re
import sys

from build_evidence_ledger import ROOT, TOPIC_TITLE, check_file, esc

SRC_REL = pathlib.PurePosixPath("docs/evidence/research-findings.json")
DST_REL = pathlib.PurePosixPath("docs/references.md")
# Generated files: they list evidence IDs, they do not cite them.
GENERATED = {DST_REL, pathlib.PurePosixPath("docs/evidence/ledger.md")}
SURVEY_REL = pathlib.PurePosixPath("docs/01-research-survey.md")

STATUS = {"verified": "V", "partially_verified": "P", "contradicted": "C", "unverified": "U"}
TAG = re.compile(r"E:([a-z_]+)-(\d{2,})")
RANGE = re.compile(r"E:([a-z_]+)-(\d{2,})\]～\[E:([a-z_]+)-(\d{2,})")
S_ROW = re.compile(r"^\|\s*S-(\d{2,})\s*\|", re.M)

CLAIM_LIMIT = 180
PAIRS = {"(": ")", "（": "）", "[": "]", "「": "」"}
OPENER_OF = {close: open_ for open_, close in PAIRS.items()}


def doc_paths(root: pathlib.Path) -> list[pathlib.Path]:
    docs = sorted((root / "docs").rglob("*.md"))
    return [root / "README.md",
            *(p for p in docs if pathlib.PurePosixPath(p.relative_to(root).as_posix()) not in GENERATED)]


def cited_ids(paths: list[pathlib.Path]) -> set[str]:
    ids: set[str] = set()
    for path in paths:
        text = path.read_text(encoding="utf-8")
        for m in TAG.finditer(text):
            ids.add(f"{m.group(1)}-{m.group(2)}")
        for m in RANGE.finditer(text):
            if m.group(1) == m.group(3):
                width = len(m.group(2))
                for n in range(int(m.group(2)), int(m.group(4)) + 1):
                    ids.add(f"{m.group(1)}-{str(n).zfill(width)}")
    return ids


def unmatched_openers(text: str) -> list[tuple[int, int]]:
    """(position, length) of the brackets and backtick runs still open at the end of `text`."""
    stack: list[tuple[int, int]] = []
    i = 0
    while i < len(text):
        ch = text[i]
        if ch == "`":
            j = i
            while j < len(text) and text[j] == "`":
                j += 1
            closer = re.compile(r"(?<!`)" + re.escape(text[i:j]) + r"(?!`)").search(text, j)
            if closer is None:
                stack.append((i, j - i))
                break           # everything after it was the (cut) code span's content
            i = closer.end()    # brackets inside a code span do not count
            continue
        if ch in PAIRS:
            stack.append((i, 1))
        elif ch in OPENER_OF and stack and text[stack[-1][0]] == OPENER_OF[ch]:
            stack.pop()
        i += 1
    return stack


def truncate(text: str, limit: int = CLAIM_LIMIT) -> str:
    """Shorten `text` to at most `limit` characters ending in `…`.

    Never cuts a URL in half, and never leaves a `()`, `（）`, `[]`, `「」` pair or a
    code span open: the text is cut before the first unmatched opener, or, when
    that would keep less than half of the text, the unmatched opener is dropped.
    """
    if len(text) <= limit:
        return text
    cut = text[:limit - 3]
    tail = re.search(r"\S*$", cut)                 # the last, possibly partial, word
    word = re.match(r"\S*", text[tail.start():]).group(0)
    url = re.search(r"https?://", word)
    if url and len(word) > len(tail.group(0)):     # never cut a URL (or its scheme) in half
        cut = cut[:tail.start() + url.start()]
    min_keep = (limit - 3) // 2
    while openers := unmatched_openers(cut):
        pos, length = openers[0]
        cut = cut[:pos] if pos >= min_keep else cut[:pos] + cut[pos + length:]
    return cut.rstrip(" \t,;:、，；：") + "…"


def supplementary_heading(root: pathlib.Path) -> str:
    path = root / SURVEY_REL
    nums = sorted({m.group(1) for m in S_ROW.finditer(path.read_text(encoding="utf-8"))},
                  key=int) if path.exists() else []
    title = "撰寫文件時補做的查證"
    return f"{title}（S-{nums[0]}～S-{nums[-1]}）" if nums else title


def render(root: pathlib.Path) -> tuple[str, int]:
    data = json.loads((root / SRC_REL).read_text(encoding="utf-8"))
    index = {f["id"]: (t["topic"], f) for t in data["topics"] for f in t["findings"]}
    ids = cited_ids(doc_paths(root))
    unknown = sorted(i for i in ids if i not in index)
    if unknown:
        raise SystemExit(f"unknown evidence IDs cited: {unknown}")
    lines = [
        "# 參考文獻",
        "",
        "> 本檔由 `tools/build_references.py` 依文件中實際引用的證據 ID 自動產生，請勿手動編輯。"
        "每條的 ID 連到 [evidence/ledger.md](evidence/ledger.md) 中的條目，那裡有完整主張、查核意見與所有來源。",
        "> 狀態：V＝已查證、P＝部分查證、C＝原主張被推翻（以更正為準）。",
        "",
        f"文件共引用 {len(ids)} 條證據。",
        "",
    ]
    for topic in data["topics"]:
        key = topic["topic"]
        items = [f for f in topic["findings"] if f["id"] in ids]
        if not items:
            continue
        lines += [f"## {esc(TOPIC_TITLE.get(key, key))}", ""]
        for f in items:
            claim = f["claim"].replace("\n", " ")
            if f["verification_status"] == "contradicted":
                claim = "（原主張已被推翻）更正：" + f["correction"].replace("\n", " ")
            lines.append(f"- **[E:{f['id']}](evidence/ledger.md#{f['id']})** "
                         f"[{STATUS[f['verification_status']]}] {esc(truncate(claim))}")
            for s in f["sources"]:
                lines.append(f"  - <{s}>" if s.startswith("http") else f"  - {esc(s)}")
        lines.append("")
    lines += [
        f"## {supplementary_heading(root)}",
        "",
        "見 [01 §4](01-research-survey.md#4-撰寫文件時補做的查證)，該節列出每一項的來源 URL 與狀態。",
        "",
    ]
    return "\n".join(lines) + "\n", len(ids)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true",
                    help="do not write; exit 1 if docs/references.md differs from the generated text")
    ap.add_argument("--root", type=pathlib.Path, default=ROOT,
                    help="repository root to read from and write to (default: this checkout)")
    args = ap.parse_args(argv)
    text, count = render(args.root)
    dst = args.root / DST_REL
    if args.check:
        return check_file(dst, text, DST_REL.as_posix(), "python tools/build_references.py")
    dst.write_text(text, encoding="utf-8", newline="\n")
    print(f"wrote {dst} ({count} cited evidence IDs)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
