#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Check relative links, reference-style links and #anchors in the Markdown documents.

Links: inline links and images `[text](dest "title")`, full and collapsed
reference links `[text][ref]` / `[ref][]`, shortcut references `[ref]`, and the
destination of every `[ref]: dest` definition. Links inside fenced code blocks
(``` or ~~~, three or more, closed by the same character at least as long),
inline code spans and HTML comments are ignored. External targets (any URL
scheme, or `//host`) are skipped; `/path` is resolved against the repository
root, as GitHub does.

A full or collapsed reference whose label has no definition is reported. A
shortcut `[ref]` without a definition is plain text in CommonMark and is not
reported, and neither are the evidence annotations the documents write as
bracket runs, such as `[V][E:providers-10]`, `[P][S-03]` or `[V][單源]`.

Anchors are computed the way GitHub does. The heading is first rendered to
text: code spans are kept verbatim, emphasis markers, HTML tags (`<br>`,
`<a name=...>`), images and link destinations are dropped, and entities
(`&amp;`) are decoded. Then github-slugger is applied: lower-case, keep letters,
marks, decimal and letter numbers, `_`, `-` and ASCII spaces, drop everything
else (including full-width punctuation such as `（）「」：`), and turn spaces into
`-`. A repeated slug gets `-1`, `-2`, ..., skipping any slug already taken, for
example by an explicit heading `Dup-1`. `<a name="...">` and `id="..."`
attributes are anchors too.

    python tools/check_doc_links.py      # prints each broken link, exit 1 if any
"""
import html
import pathlib
import re
import sys
import unicodedata
from urllib.parse import unquote

ROOT = pathlib.Path(__file__).resolve().parents[1]
FILES = [ROOT / "README.md", *sorted((ROOT / "docs").rglob("*.md"))]

FENCE = re.compile(r"^[ \t]*(?:>[ \t]?)*[ \t]*(`{3,}|~{3,})(.*)$")
HEADING = re.compile(r"^[ \t]{0,3}(?:>[ \t]?[ \t]{0,3})*(#{1,6})(?:[ \t]+(.*?))?[ \t]*$")
COMMENT = re.compile(r"<!--.*?-->", re.S)
PARA_BREAK = re.compile(r"\n[ \t]*\n")
DEFINITION = re.compile(
    r"^[ \t]{0,3}(?:>[ \t]?)*\[((?:[^\[\]\\\n]|\\.)+)\]:[ \t]*(?:<([^<>\n]*)>|(\S+))"
    r"(?:[ \t]+(?:\"[^\"\n]*\"|'[^'\n]*'|\([^()\n]*\)))?[ \t]*$", re.M)
HTML_ANCHOR = re.compile(
    r"<[A-Za-z][A-Za-z0-9-]*\s[^<>]*?(?<![\w-])(?:id|name)\s*=\s*(?:\"([^\"]*)\"|'([^']*)'|([^\s\"'<>]+))")
SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")
ENTITY = re.compile(r"&(?:#[0-9]{1,7}|#[xX][0-9a-fA-F]{1,6}|[A-Za-z][A-Za-z0-9]{1,31});")
ESCAPABLE = set("!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~")
# Bracket runs the documents use as annotations, not as links.
ANNOTATION = re.compile(r"E:[a-z_]+-\d{2,}|S-\d{2,}|[VPCHU](?:[：:].*)?|單源(?:[：:].*)?", re.S)

# Heading rendering (placeholders \ue000<n>\ue001 protect code spans and escaped characters).
_PH = re.compile("\ue000(\\d+)\ue001")
_AUTOLINK = re.compile(r"<([A-Za-z][A-Za-z0-9+.-]{1,31}:[^\s<>]*|[\w.!#$%&'*+/=?^`{|}~-]+@[\w.-]+)>")
_HTML_TAG = re.compile(r"</?[A-Za-z][A-Za-z0-9-]*(?:\s[^<>]*)?/?>|<!--.*?-->", re.S)
_BRACKETED = r"\[((?:[^\[\]]|\[[^\[\]]*\])*)\]"
_PARENS = r"\([^()]*(?:\([^()]*\)[^()]*)*\)"
_IMAGE = re.compile(r"!" + _BRACKETED + _PARENS)
_LINK = re.compile(_BRACKETED + _PARENS)
_REF_LINK = re.compile(_BRACKETED + r"\[([^\[\]]*)\]")


def _blank(s: str) -> str:
    """Same length and line breaks, no content."""
    return re.sub(r"[^\n]", " ", s)


def blank_fences(text: str) -> str:
    """Blank every line of fenced code blocks (an unclosed fence runs to the end)."""
    out = []
    fence: tuple[str, int] | None = None
    for line in text.split("\n"):
        m = FENCE.match(line)
        if fence is None:
            if m and not (m.group(1)[0] == "`" and "`" in m.group(2)):
                fence = (m.group(1)[0], len(m.group(1)))
                out.append("")
            else:
                out.append(line)
        else:
            if m and m.group(1)[0] == fence[0] and len(m.group(1)) >= fence[1] and not m.group(2).strip():
                fence = None
            out.append("")
    return "\n".join(out)


def _code_span_end(s: str, i: int) -> tuple[int, int] | None:
    """If a backtick run starts at s[i] and opens a code span, return (content_start, span_end)."""
    j = i
    while j < len(s) and s[j] == "`":
        j += 1
    closer = re.compile(r"(?<!`)" + "`" * (j - i) + r"(?!`)").search(s, j)
    return (j, closer.end()) if closer else None


def blank_code_spans(text: str) -> str:
    """Blank inline code spans; a span never crosses a blank line."""
    out = []
    pos = 0
    for para_end in [m.start() for m in PARA_BREAK.finditer(text)] + [len(text)]:
        para = text[pos:para_end]
        res = []
        i = 0
        while i < len(para):
            c = para[i]
            if c == "\\" and i + 1 < len(para):
                res.append(para[i:i + 2])
                i += 2
            elif c == "`":
                span = _code_span_end(para, i)
                if span:
                    res.append(_blank(para[i:span[1]]))
                    i = span[1]
                else:
                    j = i
                    while j < len(para) and para[j] == "`":
                        j += 1
                    res.append(para[i:j])
                    i = j
            else:
                res.append(c)
                i += 1
        out.append("".join(res))
        pos = para_end
    return "".join(out)


def strip_code(text: str) -> str:
    """Blank fenced code blocks, code spans and HTML comments, keeping line structure."""
    text = blank_code_spans(blank_fences(text))
    return COMMENT.sub(lambda m: _blank(m.group(0)), text)


# ---------------------------------------------------------------- heading slugs

def _is_space(c: str) -> bool:
    return c == "" or c.isspace()


def _is_punct(c: str) -> bool:
    return c in ("\ue000", "\ue001") or (c != "" and unicodedata.category(c)[0] in "PS")


def _drop_underscore_emphasis(s: str) -> str:
    """Remove `_` / `__` emphasis delimiters (CommonMark flanking rules); keep snake_case."""
    runs = [[m.start(), m.end() - m.start()] for m in re.finditer(r"_+", s)]
    remove = [0] * len(runs)
    stack: list[int] = []
    for idx, (start, length) in enumerate(runs):
        prev = s[start - 1] if start else ""
        nxt = s[start + length] if start + length < len(s) else ""
        left = not _is_space(nxt) and (not _is_punct(nxt) or _is_space(prev) or _is_punct(prev))
        right = not _is_space(prev) and (not _is_punct(prev) or _is_space(nxt) or _is_punct(nxt))
        can_open = left and (not right or _is_punct(prev))
        can_close = right and (not left or _is_punct(nxt))
        avail = length
        while can_close and stack and avail:
            o = stack[-1]
            k = min(avail, runs[o][1] - remove[o])
            remove[o] += k
            remove[idx] += k
            avail -= k
            if remove[o] == runs[o][1]:
                stack.pop()
        if can_open and avail:
            stack.append(idx)
    out = []
    pos = 0
    for (start, length), rm in zip(runs, remove):
        out.append(s[pos:start])
        out.append("_" * (length - rm))
        pos = start + length
    out.append(s[pos:])
    return "".join(out)


def heading_text(md: str, definitions: frozenset[str] | set[str] = frozenset()) -> str:
    """The text GitHub renders for a heading's inline Markdown.

    `definitions` holds the normalized labels of the file's `[ref]: dest` definitions: a
    reference link `[text][ref]` renders as `text` only when its label is defined.
    """
    literals: list[str] = []

    def keep(text: str) -> str:
        literals.append(text)
        return f"\ue000{len(literals) - 1}\ue001"

    raw = []
    i = 0
    while i < len(md):
        c = md[i]
        if c == "\\" and i + 1 < len(md) and md[i + 1] in ESCAPABLE:
            raw.append(keep(md[i + 1]))
            i += 2
        elif c == "`":
            span = _code_span_end(md, i)
            if span:
                content = md[span[0]:span[1] - (span[0] - i)].replace("\n", " ")
                if len(content) >= 2 and content[0] == content[-1] == " " and content.strip():
                    content = content[1:-1]
                raw.append(keep(content))
                i = span[1]
            else:
                j = i
                while j < len(md) and md[j] == "`":
                    j += 1
                raw.append(md[i:j])
                i = j
        else:
            raw.append(c)
            i += 1
    s = "".join(raw)
    s = _AUTOLINK.sub(lambda m: keep(m.group(1)), s)
    s = _HTML_TAG.sub("", s)
    s = _IMAGE.sub("", s)
    for _ in range(3):                      # nested brackets: [a [b](x)](y)
        s = _LINK.sub(r"\1", s)
        s = _REF_LINK.sub(lambda m: m.group(1) if normalize_label(m.group(2) or m.group(1)) in definitions
                          else m.group(0), s)
    s = _drop_underscore_emphasis(s)
    s = ENTITY.sub(lambda m: html.unescape(m.group(0)), s)
    return _PH.sub(lambda m: literals[int(m.group(1))], s)


def slugify(text: str) -> str:
    """github-slugger on already rendered text."""
    out = []
    for ch in text.lower():
        if ch == " ":
            out.append("-")
        elif ch in "-_":
            out.append(ch)
        else:
            cat = unicodedata.category(ch)
            if cat[0] in "LM" or cat in ("Nd", "Nl", "Pc"):
                out.append(ch)
    return "".join(out)


def slug(md: str, definitions: frozenset[str] | set[str] = frozenset()) -> str:
    return slugify(heading_text(md, definitions))


def heading_content(line: str) -> str | None:
    m = HEADING.match(line)
    if not m:
        return None
    content = re.sub(r"(?:^|[ \t]+)#+$", "", (m.group(2) or "").strip())
    return content.strip()


def anchors(path: pathlib.Path) -> set[str]:
    source = path.read_text(encoding="utf-8")
    definitions = set(extract(source)[1])
    text = COMMENT.sub(lambda m: _blank(m.group(0)), blank_fences(source))
    occurrences: dict[str, int] = {}
    result = set()
    for line in text.split("\n"):
        content = heading_content(line)
        if content is None:
            continue
        base = candidate = slug(content, definitions)
        while candidate in occurrences:     # github-slugger: skip slugs already taken
            occurrences[base] += 1
            candidate = f"{base}-{occurrences[base]}"
        occurrences[candidate] = 0
        result.add(candidate)
    for m in HTML_ANCHOR.finditer(blank_code_spans(text)):
        result.add(html.unescape(next(g for g in m.groups() if g is not None)))
    return result


# ---------------------------------------------------------------- links

def normalize_label(label: str) -> str:
    return " ".join(label.split()).casefold()


def _unescape(dest: str) -> str:
    dest = re.sub(r"\\([!-/:-@\[-`{-~])", r"\1", dest)
    return ENTITY.sub(lambda m: html.unescape(m.group(0)), dest)


def _is_escaped(text: str, i: int) -> bool:
    n = 0
    while i - n - 1 >= 0 and text[i - n - 1] == "\\":
        n += 1
    return n % 2 == 1


def _match_bracket(text: str, i: int) -> int | None:
    depth = 0
    j = i
    while j < len(text):
        c = text[j]
        if c == "\\":
            j += 2
            continue
        if c == "[":
            depth += 1
        elif c == "]":
            depth -= 1
            if depth == 0:
                return j
        elif c == "\n" and PARA_BREAK.match(text, j):
            return None
        j += 1
    return None


def _inline_destination(text: str, p: int) -> str | None:
    """Parse `(dest "title")` starting at text[p] == '('; None if it is not a link."""
    n = len(text)
    j = p + 1

    def skip_ws(j: int) -> int:
        newline = False
        while j < n and text[j] in " \t\n":
            if text[j] == "\n":
                if newline:
                    return -1
                newline = True
            j += 1
        return j

    j = skip_ws(j)
    if j < 0:
        return None
    if j < n and text[j] == "<":
        k = text.find(">", j)
        if k < 0 or "\n" in text[j:k]:
            return None
        dest = text[j + 1:k]
        j = k + 1
    else:
        start, depth = j, 0
        while j < n:
            c = text[j]
            if c == "\\" and j + 1 < n:
                j += 2
                continue
            if c.isspace() or ord(c) < 0x20:
                break
            if c == "(":
                depth += 1
            elif c == ")":
                if depth == 0:
                    break
                depth -= 1
            j += 1
        dest = text[start:j]
    j = skip_ws(j)
    if j < 0:
        return None
    if j < n and text[j] in "\"'(" and j > p + 1 and text[j - 1] in " \t\n":
        close = ")" if text[j] == "(" else text[j]
        k = j + 1
        while k < n and text[k] != close:
            k += 2 if text[k] == "\\" else 1
        if k >= n or PARA_BREAK.search(text, j, k):
            return None
        j = skip_ws(k + 1)
        if j < 0:
            return None
    return dest if j < n and text[j] == ")" else None


def extract(text: str) -> tuple[list[str], dict[str, str], list[str]]:
    """(inline link destinations, definitions {label: dest}, undefined reference labels)."""
    text = strip_code(text)
    definitions: dict[str, str] = {}
    for m in DEFINITION.finditer(text):
        label = m.group(1)
        if label.startswith("^"):          # footnote
            continue
        definitions.setdefault(normalize_label(label), _unescape(m.group(2) if m.group(2) is not None else m.group(3)))
    text = DEFINITION.sub(lambda m: m.group(0) if m.group(1).startswith("^") else _blank(m.group(0)), text)
    inline: list[str] = []
    undefined: list[str] = []
    i = 0
    while (i := text.find("[", i)) >= 0:
        if _is_escaped(text, i):
            i += 1
            continue
        close = _match_bracket(text, i)
        if close is None:
            i += 1
            continue
        after = close + 1
        if text.startswith("(", after):
            dest = _inline_destination(text, after)
            if dest is not None:
                inline.append(_unescape(dest))
        elif text.startswith("[", after):
            end = after + 1
            while end < len(text) and text[end] not in "[]\n":
                end += 2 if text[end] == "\\" else 1
            if end < len(text) and text[end] == "]":
                label = text[after + 1:end] or text[i + 1:close]
                if (normalize_label(label) not in definitions and not label.startswith("^")
                        and not ANNOTATION.fullmatch(label.strip())):
                    undefined.append(label)
        i += 1
    return inline, definitions, undefined


def check_target(path: pathlib.Path, target: str, root: pathlib.Path,
                 cache: dict[pathlib.Path, set[str]]) -> str | None:
    """None if `target` (as written in `path`) resolves, else the problem kind."""
    if not target or SCHEME.match(target) or target.startswith("//"):
        return None
    file_part, _, anchor = target.partition("#")
    file_part = unquote(file_part.split("?", 1)[0])
    anchor = unquote(anchor)
    if file_part.startswith("/"):
        dest = root / file_part.lstrip("/")
    elif file_part:
        dest = path.parent / file_part
    else:
        dest = path
    dest = dest.resolve()
    if not dest.exists() or not dest.is_relative_to(root.resolve()):
        return "missing file"
    if anchor and dest.is_file() and dest.suffix == ".md":
        if dest not in cache:
            cache[dest] = anchors(dest)
        if anchor not in cache[dest]:
            return "missing anchor"
    return None


def check_file(path: pathlib.Path, root: pathlib.Path = ROOT,
               cache: dict[pathlib.Path, set[str]] | None = None) -> list[str]:
    """Problems in one Markdown file, one line each, in the CLI's format."""
    cache = {} if cache is None else cache
    rel = path.relative_to(root)
    inline, definitions, undefined = extract(path.read_text(encoding="utf-8"))
    problems = []
    for target in [*inline, *definitions.values()]:
        kind = check_target(path, target, root, cache)
        if kind:
            problems.append(f"{rel}: {kind} -> {target}")
    problems += [f"{rel}: undefined reference -> [{label}]" for label in undefined]
    return problems


def main() -> int:
    cache: dict[pathlib.Path, set[str]] = {}
    problems = 0
    for path in FILES:
        for line in check_file(path, ROOT, cache):
            print(line)
            problems += 1
    print(f"{problems} broken link(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
