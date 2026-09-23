#!/usr/bin/env python3
"""Check relative links and #anchors in the Markdown documents.

Anchors are computed the way GitHub does (github-slugger): lower-case, drop
punctuation and symbols, keep letters/numbers/marks, '-' and '_', turn spaces
into '-', and suffix duplicates with -1, -2, ...
"""
import pathlib
import re
import sys
import unicodedata

ROOT = pathlib.Path(__file__).resolve().parents[1]
FILES = [ROOT / "README.md", *sorted((ROOT / "docs").rglob("*.md"))]
LINK = re.compile(r"(?<!!)\[[^\]]*\]\(([^)\s]+)\)")
HEADING = re.compile(r"^(#{1,6})\s+(.*?)\s*#*\s*$")


def slug(text: str) -> str:
    text = re.sub(r"`([^`]*)`", r"\1", text)
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)
    out = []
    for ch in text.lower():
        cat = unicodedata.category(ch)
        if ch in "-_ " or cat[0] in "LNM":
            out.append("-" if ch == " " else ch)
    return "".join(out)


def anchors(path: pathlib.Path) -> set[str]:
    seen: dict[str, int] = {}
    result = set()
    in_code = False
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("```"):
            in_code = not in_code
            continue
        if in_code:
            continue
        m = HEADING.match(line)
        if not m:
            continue
        base = slug(m.group(2))
        n = seen.get(base, 0)
        result.add(base if n == 0 else f"{base}-{n}")
        seen[base] = n + 1
    return result


def main() -> int:
    cache: dict[pathlib.Path, set[str]] = {}
    problems = 0
    for path in FILES:
        text = path.read_text(encoding="utf-8")
        text = re.sub(r"```.*?```", "", text, flags=re.S)
        for target in LINK.findall(text):
            if target.startswith(("http://", "https://", "mailto:")):
                continue
            file_part, _, anchor = target.partition("#")
            dest = (path.parent / file_part).resolve() if file_part else path
            if not dest.exists():
                print(f"{path.relative_to(ROOT)}: missing file -> {target}")
                problems += 1
                continue
            if anchor and dest.suffix == ".md":
                if dest not in cache:
                    cache[dest] = anchors(dest)
                if anchor not in cache[dest]:
                    print(f"{path.relative_to(ROOT)}: missing anchor -> {target}")
                    problems += 1
    print(f"{problems} broken link(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
