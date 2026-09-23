#!/usr/bin/env python3
"""Generate docs/references.md from the evidence IDs cited in the documents.

Every `[E:<id>]` tag found in README.md and docs/*.md is resolved against
docs/evidence/research-findings.json. Ranges written as `[E:a]～[E:b]` are
expanded. Supplementary checks (S-xx) are listed in docs/01-research-survey.md
section 4 and are copied here by URL.
"""
import json
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC = ROOT / "docs" / "evidence" / "research-findings.json"
DST = ROOT / "docs" / "references.md"
DOCS = [ROOT / "README.md", *sorted((ROOT / "docs").glob("*.md"))]

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
STATUS = {"verified": "V", "partially_verified": "P", "contradicted": "C"}
TAG = re.compile(r"E:([a-z_]+)-(\d{2})")
RANGE = re.compile(r"E:([a-z_]+)-(\d{2})\]～\[E:([a-z_]+)-(\d{2})")


def cited_ids() -> set[str]:
    ids: set[str] = set()
    for path in DOCS:
        if path.name == "references.md":
            continue
        text = path.read_text(encoding="utf-8")
        for m in TAG.finditer(text):
            ids.add(f"{m.group(1)}-{m.group(2)}")
        for m in RANGE.finditer(text):
            if m.group(1) == m.group(3):
                for n in range(int(m.group(2)), int(m.group(4)) + 1):
                    ids.add(f"{m.group(1)}-{n:02d}")
    return ids


def main() -> None:
    data = json.loads(SRC.read_text(encoding="utf-8"))
    index = {f["id"]: (t["topic"], f) for t in data["topics"] for f in t["findings"]}
    ids = cited_ids()
    unknown = sorted(i for i in ids if i not in index)
    if unknown:
        raise SystemExit(f"unknown evidence IDs cited: {unknown}")
    lines = [
        "# 參考文獻",
        "",
        "> 本檔由 `tools/build_references.py` 依文件中實際引用的證據 ID 自動產生。每條的完整主張、查核意見與所有來源見 [evidence/ledger.md](evidence/ledger.md)。",
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
        lines += [f"## {TOPIC_TITLE[key]}", ""]
        for f in items:
            claim = f["claim"].replace("\n", " ")
            if f["verification_status"] == "contradicted":
                claim = "（原主張已被推翻）更正：" + f["correction"].replace("\n", " ")
            if len(claim) > 180:
                cut = claim[:177]
                if re.search(r"https?://\S*$", cut):   # never cut a URL in half
                    cut = re.sub(r"\S*https?://\S*$", "", cut)
                claim = cut.rstrip() + "…"
            lines.append(f"- **E:{f['id']}** [{STATUS[f['verification_status']]}] {claim}")
            for s in f["sources"]:
                lines.append(f"  - <{s}>" if s.startswith("http") else f"  - {s}")
        lines.append("")
    lines += [
        "## 撰寫文件時補做的查證（S-01～S-10）",
        "",
        "見 [01 §4](01-research-survey.md#4-撰寫文件時補做的查證)，該節列出每一項的來源 URL 與狀態。",
        "",
    ]
    DST.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {DST} ({len(ids)} cited evidence IDs)")


if __name__ == "__main__":
    main()
