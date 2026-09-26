#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Generate docs/evidence/ledger.md from docs/evidence/research-findings.json.

The ledger keeps the original (English) research claims, the independent
verifier's status and correction, and all source URLs, so every factual
statement in the Chinese documents can be traced to an evidence ID such as
[E:providers-10].

Anchors: each topic keeps its heading anchor (`ledger.md#providers`), and each
entry gets an anchor that depends only on its evidence ID
(`ledger.md#providers-10`, plus the heading slug `#eproviders-10`), so a
status change or a reworded claim never breaks a link.

    python tools/build_evidence_ledger.py           # (re)write the ledger
    python tools/build_evidence_ledger.py --check   # exit 1 if the file on disk is stale
"""
import argparse
import difflib
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC_REL = pathlib.PurePosixPath("docs/evidence/research-findings.json")
DST_REL = pathlib.PurePosixPath("docs/evidence/ledger.md")

# Evidence IDs are "<topic>-<sequence>", with a sequence of two or more digits.
ID_RE = re.compile(r"[a-z_]+-\d{2,}")

STATUS_LABEL = {
    "verified": "V 已查證",
    "partially_verified": "P 部分查證",
    "contradicted": "C 已更正（原主張被推翻）",
    "unverified": "U 未查證",
}

TOPIC_TITLE = {
    "orchestration": "多代理編排框架與模型閘道",
    "providers": "LLM 供應商（Claude／OpenAI／Nemotron）",
    "multi_llm_bias": "多模型與偏誤研究",
    "whitebox": "白箱測試工具與研究",
    "threat_modeling": "威脅建模方法與標準",
    "blackbox": "黑箱驗證工具與安全實務",
    "vibe_risks": "Vibe coding 風險與事件",
    "reference_systems": "參考系統架構",
}

# A CommonMark code span: a backtick run closed by a run of the same length.
_CODE_SPAN = re.compile(r"(?<!`)(`+)(?!`)(.+?)(?<!`)\1(?!`)", re.S)
# A bare URL as GFM autolinks it; it is emitted unchanged so its query string
# (`&limit=5`) is not rewritten to `&amp;`.
_BARE_URL = re.compile(r"https?://[^\s<>]+")


def _esc_plain(text: str) -> str:
    out = []
    pos = 0
    for m in _BARE_URL.finditer(text):
        out.append(_esc_chars(text[pos:m.start()]))
        out.append(m.group(0).replace("|", "\\|"))
        pos = m.end()
    out.append(_esc_chars(text[pos:]))
    return "".join(out)


def _esc_chars(text: str) -> str:
    return (text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace("|", "\\|"))


def esc(text: str) -> str:
    """Make free text render literally in Markdown.

    `&`, `<` and `>` become HTML entities (so `<model>` is shown, not swallowed
    as an HTML tag), `|` becomes `\\|` (so the text is also safe in a table
    cell), and newlines become spaces. Code spans are left as written: their
    content is already literal, and an entity there would show as `&lt;`.
    """
    text = text.replace("\r\n", " ").replace("\n", " ")
    out = []
    pos = 0
    for m in _CODE_SPAN.finditer(text):
        out.append(_esc_plain(text[pos:m.start()]))
        out.append(m.group(0))
        pos = m.end()
    out.append(_esc_plain(text[pos:]))
    return "".join(out)


def check_ids(data: dict) -> None:
    seen: set[str] = set()
    for topic in data["topics"]:
        for f in topic["findings"]:
            fid = f["id"]
            if not ID_RE.fullmatch(fid):
                raise SystemExit(f"malformed evidence ID {fid!r} (expected <topic>-<NN>)")
            if fid in seen:
                raise SystemExit(f"duplicate evidence ID {fid!r}")
            seen.add(fid)


def render(data: dict) -> str:
    check_ids(data)
    lines = [
        "# 證據帳本（Evidence Ledger）",
        "",
        "> 本檔由 `tools/build_evidence_ledger.py` 從 `research-findings.json` 自動產生，請勿手動編輯。",
        "> 主張（claim）保留研究代理的英文原文；「查核」欄是獨立查核代理的結論與更正。",
        "> 中文文件中的 `[E:<id>]` 指向本檔的條目。若查核欄有更正，**以更正為準**。",
        "> 每個條目的錨點只由證據 ID 決定，例如 `ledger.md#providers-10`。",
        "",
    ]
    counts: dict[str, int] = {}
    for topic in data["topics"]:
        for f in topic["findings"]:
            counts[f["verification_status"]] = counts.get(f["verification_status"], 0) + 1
    total = sum(counts.values())
    lines.append(f"總計 {total} 條：" + "、".join(
        f"{STATUS_LABEL.get(k, k)} {v}" for k, v in sorted(counts.items())))
    lines.append("")
    lines.append("## 目錄")
    for topic in data["topics"]:
        key = topic["topic"]
        lines.append(f"- [{esc(TOPIC_TITLE.get(key, key))}（{key}）](#{key})")
    lines.append("")
    for topic in data["topics"]:
        key = topic["topic"]
        lines.append(f"## {key}")
        lines.append("")
        lines.append(f"**{esc(TOPIC_TITLE.get(key, key))}**")
        lines.append("")
        for f in topic["findings"]:
            fid = f["id"]
            status = STATUS_LABEL.get(f["verification_status"], f["verification_status"])
            lines.append(f'### <a name="{fid}"></a>E:{fid}')
            lines.append("")
            lines.append(f"- **狀態**：{esc(status)}")
            lines.append(f"- **主張**：{esc(f['claim'])}")
            if f["correction"]:
                lines.append(f"- **查核**：{esc(f['correction'])}")
            srcs = f["sources"] + [s for s in f["independent_sources"] if s not in f["sources"]]
            if srcs:
                lines.append("- **來源**：" + " ｜ ".join(f"<{s}>" if s.startswith("http") else esc(s) for s in srcs))
            lines.append("")
        lines.append("**本主題研究限制（研究代理自述）**")
        lines.append("")
        for lim in topic["limitations"]:
            lines.append(f"- {esc(lim)}")
        lines.append("")
    return "\n".join(lines) + "\n"


def check_file(dst: pathlib.Path, expected: str, label: str, regenerate: str) -> int:
    """Compare `expected` with the file on disk (line endings ignored); 0 if identical."""
    try:
        actual = dst.read_text(encoding="utf-8")
    except FileNotFoundError:
        print(f"{label}: missing; run `{regenerate}`")
        return 1
    if actual == expected:
        print(f"{label}: up to date")
        return 0
    old, new = actual.splitlines(), expected.splitlines()
    changed = sum(1 for tag, *_ in difflib.SequenceMatcher(None, old, new, autojunk=False).get_opcodes()
                  if tag != "equal")
    print(f"{label}: out of date ({changed} changed block(s), {len(old)} -> {len(new)} lines); "
          f"run `{regenerate}`")
    diff = list(difflib.unified_diff(old, new, f"{label} (on disk)", f"{label} (generated)", n=0, lineterm=""))
    for line in diff[:20]:
        print("  " + (line if len(line) <= 160 else line[:157] + "..."))
    if len(diff) > 20:
        print(f"  ... ({len(diff) - 20} more diff line(s))")
    return 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true",
                    help="do not write; exit 1 if docs/evidence/ledger.md differs from the generated text")
    ap.add_argument("--root", type=pathlib.Path, default=ROOT,
                    help="repository root to read from and write to (default: this checkout)")
    args = ap.parse_args(argv)
    src, dst = args.root / SRC_REL, args.root / DST_REL
    data = json.loads(src.read_text(encoding="utf-8"))
    text = render(data)
    if args.check:
        return check_file(dst, text, DST_REL.as_posix(), "python tools/build_evidence_ledger.py")
    dst.write_text(text, encoding="utf-8", newline="\n")
    total = sum(len(t["findings"]) for t in data["topics"])
    print(f"wrote {dst} ({total} findings)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
