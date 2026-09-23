#!/usr/bin/env python3
"""Generate docs/evidence/ledger.md from docs/evidence/research-findings.json.

The ledger keeps the original (English) research claims, the independent
verifier's status and correction, and all source URLs, so every factual
statement in the Chinese documents can be traced to an evidence ID such as
[E:providers-10].
"""
import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC = ROOT / "docs" / "evidence" / "research-findings.json"
DST = ROOT / "docs" / "evidence" / "ledger.md"

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


def esc(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def main() -> None:
    data = json.loads(SRC.read_text(encoding="utf-8"))
    lines = [
        "# 證據帳本（Evidence Ledger）",
        "",
        "> 本檔由 `tools/build_evidence_ledger.py` 從 `research-findings.json` 自動產生，請勿手動編輯。",
        "> 主張（claim）保留研究代理的英文原文；「查核」欄是獨立查核代理的結論與更正。",
        "> 中文文件中的 `[E:<id>]` 指向本檔的條目。若查核欄有更正，**以更正為準**。",
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
        lines.append(f"- [{TOPIC_TITLE.get(key, key)}（{key}）](#{key})")
    lines.append("")
    for topic in data["topics"]:
        key = topic["topic"]
        lines.append(f"## {key}")
        lines.append("")
        lines.append(f"**{TOPIC_TITLE.get(key, key)}**")
        lines.append("")
        for f in topic["findings"]:
            status = STATUS_LABEL.get(f["verification_status"], f["verification_status"])
            lines.append(f"### E:{f['id']} — {status}")
            lines.append("")
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
    DST.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {DST} ({total} findings)")


if __name__ == "__main__":
    main()
