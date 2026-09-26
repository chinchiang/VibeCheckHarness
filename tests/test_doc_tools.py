"""Tests for the documentation tools: the two generators, the link checker and the
external-link checker (whose network code is never exercised here)."""
import hashlib
import json
import pathlib
import re
import shutil

import pytest

import build_evidence_ledger as ledger
import build_references as refs
import check_doc_links as links
import check_external_links as ext

ROOT = pathlib.Path(__file__).resolve().parents[1]
FINDINGS = ROOT / "docs" / "evidence" / "research-findings.json"
LEDGER = ROOT / "docs" / "evidence" / "ledger.md"
REFERENCES = ROOT / "docs" / "references.md"


def sha(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def finding(fid, claim="A claim.", status="verified", correction="", sources=("https://a.org/x",)):
    return {"id": fid, "claim": claim, "sources": list(sources), "researcher_confidence": "high",
            "relevance": "high", "verification_status": status, "independent_sources": [],
            "correction": correction}


def dataset(*findings, topic="providers"):
    return {"generated_from": "test", "topics": [{"topic": topic, "findings": list(findings), "limitations": []}]}


def write(path: pathlib.Path, text: str) -> pathlib.Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")
    return path


# ---------------------------------------------------------------- escaping

def test_esc_html_escapes_angle_brackets_ampersands_and_pipes():
    assert ledger.esc("nvidia_nim/<model> for IEEE S&P | x") == "nvidia_nim/&lt;model&gt; for IEEE S&amp;P \\| x"


def test_esc_leaves_code_spans_and_bare_url_queries_alone():
    assert ledger.esc("install `crewai[<x>]` & go") == "install `crewai[<x>]` &amp; go"
    assert ledger.esc("``a ` <b>`` <c>") == "``a ` <b>`` &lt;c&gt;"
    assert ledger.esc("see https://o.net/s?term=a&limit=5 & more") == "see https://o.net/s?term=a&limit=5 &amp; more"
    assert ledger.esc("line one\nline two") == "line one line two"


def test_ledger_renders_placeholders_literally():
    text = ledger.render(dataset(finding("providers-20", claim="prefix nvidia_nim/<model>, p<0.05 & more",
                                         correction="'-server <port>' mode")))
    assert "nvidia_nim/&lt;model&gt;, p&lt;0.05 &amp; more" in text
    assert "'-server &lt;port&gt;' mode" in text
    assert "<model>" not in text and "<port>" not in text
    assert "<https://a.org/x>" in text           # sources stay autolinks


def test_real_ledger_has_no_raw_placeholders():
    body = LEDGER.read_text(encoding="utf-8")
    for placeholder in ("<model>", "<port>", "<encoded-cwd>", "<url>", "<client>"):
        assert placeholder not in body
    assert "nvidia_nim/&lt;model&gt;" in body


# ---------------------------------------------------------------- anchors

def entry_heading(text: str, fid: str) -> str:
    return next(line for line in text.splitlines() if line.startswith("### ") and f"E:{fid}" in line)


def test_entry_anchor_depends_only_on_the_id(tmp_path):
    a = ledger.render(dataset(finding("providers-10", claim="Old wording.", status="verified")))
    b = ledger.render(dataset(finding("providers-10", claim="New <wording> & more.", status="contradicted",
                                      correction="It was wrong.")))
    assert entry_heading(a, "providers-10") == entry_heading(b, "providers-10") == \
        '### <a name="providers-10"></a>E:providers-10'
    for text in (a, b):
        found = links.anchors(write(tmp_path / "ledger.md", text))
        assert {"providers", "providers-10", "eproviders-10"} <= found


def test_real_ledger_anchors_cover_every_id_topic_and_doc_link():
    data = json.loads(FINDINGS.read_text(encoding="utf-8"))
    found = links.anchors(LEDGER)
    ids = {f["id"] for t in data["topics"] for f in t["findings"]}
    topics = {t["topic"] for t in data["topics"]}
    assert ids <= found and topics <= found
    cited = set()
    for path in [ROOT / "README.md", *(ROOT / "docs").rglob("*.md")]:
        cited |= set(re.findall(r"ledger\.md#([A-Za-z0-9_-]+)", path.read_text(encoding="utf-8")))
    assert {"orchestration", "providers", "multi_llm_bias", "whitebox", "threat_modeling"} <= cited
    assert cited <= found


def test_ids_with_three_digits_are_accepted_and_malformed_ids_rejected():
    assert '<a name="providers-100"></a>' in ledger.render(dataset(finding("providers-100")))
    with pytest.raises(SystemExit):
        ledger.render(dataset(finding("providers-1")))
    with pytest.raises(SystemExit):
        ledger.render(dataset(finding("providers-10"), finding("providers-10")))


# ---------------------------------------------------------------- --check

@pytest.fixture
def repo_copy(tmp_path):
    """A temporary copy of README.md and docs/ (the real files are never written)."""
    before = {p: sha(p) for p in (LEDGER, REFERENCES)}
    shutil.copy2(ROOT / "README.md", tmp_path / "README.md")
    shutil.copytree(ROOT / "docs", tmp_path / "docs")
    yield tmp_path
    assert {p: sha(p) for p in (LEDGER, REFERENCES)} == before


@pytest.mark.parametrize("tool,rel", [(ledger, "docs/evidence/ledger.md"), (refs, "docs/references.md")])
def test_check_mode(tool, rel, repo_copy, capsys):
    root = str(repo_copy)
    assert tool.main(["--root", root]) == 0                      # regenerate the copy
    generated = (repo_copy / rel).read_bytes()
    assert tool.main(["--root", root, "--check"]) == 0
    assert "up to date" in capsys.readouterr().out
    target = repo_copy / rel
    target.write_text(target.read_text(encoding="utf-8").replace("\n", "\nstray line\n", 1),
                      encoding="utf-8", newline="\n")
    assert tool.main(["--root", root, "--check"]) == 1
    out = capsys.readouterr().out
    assert "out of date" in out and "+" in out and "stray line" in out
    assert target.read_text(encoding="utf-8") != generated.decode("utf-8")   # --check never writes
    target.unlink()
    assert tool.main(["--root", root, "--check"]) == 1
    assert tool.main(["--root", root]) == 0
    assert target.read_bytes() == generated                       # deterministic, LF only
    assert b"\r\n" not in generated


def test_check_ignores_line_endings_only(repo_copy):
    root = str(repo_copy)
    assert ledger.main(["--root", root]) == 0
    target = repo_copy / "docs" / "evidence" / "ledger.md"
    target.write_bytes(target.read_bytes().replace(b"\n", b"\r\n"))
    assert ledger.main(["--root", root, "--check"]) == 0


# ---------------------------------------------------------------- build_references

def test_cited_ids_recursive_three_digit_and_ranges(tmp_path):
    write(tmp_path / "README.md", "[V][E:providers-01]")
    write(tmp_path / "docs" / "sub" / "deep.md", "[E:providers-100] and [E:whitebox-098]～[E:whitebox-101]")
    write(tmp_path / "docs" / "references.md", "[E:blackbox-01]")
    write(tmp_path / "docs" / "evidence" / "ledger.md", "[E:blackbox-02]")
    paths = refs.doc_paths(tmp_path)
    assert tmp_path / "docs" / "sub" / "deep.md" in paths
    assert tmp_path / "docs" / "references.md" not in paths
    assert tmp_path / "docs" / "evidence" / "ledger.md" not in paths
    assert refs.cited_ids(paths) == {"providers-01", "providers-100", "whitebox-098", "whitebox-099",
                                     "whitebox-100", "whitebox-101"}


def balanced(text: str) -> bool:
    return not refs.unmatched_openers(text)


@pytest.mark.parametrize("opener,closer", [("(", ")"), ("（", "）"), ("[", "]"), ("「", "」"), ("`", "`")])
def test_truncate_cuts_before_a_late_unmatched_opener(opener, closer):
    text = "x" * 150 + " " + opener + "inside the pair that runs past the limit" + closer + " tail"
    out = refs.truncate(text)
    assert out == "x" * 150 + "…"


@pytest.mark.parametrize("opener,closer", [("(", ")"), ("（", "）"), ("「", "」"), ("`", "`")])
def test_truncate_drops_an_early_unmatched_opener(opener, closer):
    text = "Intro " + opener + "a long aside " + "y" * 200 + closer + " end"
    out = refs.truncate(text)
    assert out.endswith("…") and len(out) <= refs.CLAIM_LIMIT
    assert opener not in out and out.startswith("Intro a long aside y")
    assert balanced(out)


def test_truncate_keeps_closed_pairs_nested_pairs_and_code_content():
    text = "A (closed) and `code (with paren` and 「quoted」 " + "z" * 200
    out = refs.truncate(text)
    assert out.startswith("A (closed) and `code (with paren` and 「quoted」 z") and balanced(out)
    nested = "Outer (inner [deep] still open " + "w" * 200
    out = refs.truncate(nested)
    assert "(" not in out and "[deep]" in out and balanced(out)


def test_truncate_never_cuts_a_url_and_leaves_short_text_alone():
    assert refs.truncate("q" * 170 + " see https://example.org/a/very/long/path") == "q" * 170 + " see…"
    assert refs.truncate("q" * 160 + " at (https://example.org/a/very/long/path)") == "q" * 160 + " at…"
    assert refs.truncate("q" * 150 + " https://example.org/ok and more text " + "r" * 40) == \
        "q" * 150 + " https://example.org/ok and…"
    assert refs.truncate("short (unbalanced") == "short (unbalanced"
    assert len(refs.truncate("v" * 500)) == 178


def test_every_real_truncated_claim_is_balanced():
    data = json.loads(FINDINGS.read_text(encoding="utf-8"))
    for f in (f for t in data["topics"] for f in t["findings"]):
        for claim in (f["claim"], "（原主張已被推翻）更正：" + (f["correction"] or "")):
            out = refs.truncate(claim.replace("\n", " "))
            assert len(out) <= refs.CLAIM_LIMIT
            if out != claim:
                assert out.endswith("…") and balanced(out), f["id"]


def test_references_link_each_entry_to_its_ledger_anchor():
    body = REFERENCES.read_text(encoding="utf-8")
    assert "- **[E:orchestration-01](evidence/ledger.md#orchestration-01)** [V] " in body
    assert "&lt;model&gt;" in body and "nvidia_nim/<model>" not in body


# ---------------------------------------------------------------- link checker

A = str(pathlib.PurePath("docs", "a.md"))     # how the CLI prints docs/a.md on this OS


@pytest.fixture
def site(tmp_path):
    root = tmp_path / "repo"
    write(root / "README.md", "# Title\n\n## Setup &amp; run\n")
    write(root / "docs" / "b.md", "# B\n\n## Part\n")
    return root


def problems(site, text):
    path = write(site / "docs" / "a.md", text)
    return links.check_file(path, site)


def test_links_in_fences_and_code_spans_are_ignored(site):
    text = "\n".join([
        "```", "[x](missing1.md)", "```",
        "~~~ text", "[x](missing2.md)", "```", "[x](missing3.md)", "~~~",
        "````md", "```", "[x](missing4.md)", "````",
        "Inline `[x](missing5.md)` and `` a ` [x](missing6.md) `` done.",
        "<!-- [x](missing7.md) -->",
        r"\[x](missing8.md) is escaped.",
        "[after](missing9.md)",
    ])
    assert problems(site, text) == [f"{A}: missing file -> missing9.md"]


def test_unclosed_fence_runs_to_the_end(site):
    assert problems(site, "[ok](b.md)\n~~~~\n[x](missing.md)\n~~~\n") == []


def test_reference_links(site):
    text = "\n".join([
        "Full [text][ok], collapsed [OK][], shortcut [ok] and [Mixed Case][ok].",
        "Missing [text][nope] and [nope2][]; plain [shortcut] stays text.",
        "Annotations [V][E:providers-10][E:providers-11], [P][S-03], [V][單源：SoK], [C][V].",
        "",
        "[ok]: b.md#part",
        "[bad]: missing.md",
        "[badanchor]: <b.md#nowhere> \"title\"",
    ])
    assert problems(site, text) == [
        f"{A}: missing file -> missing.md",
        f"{A}: missing anchor -> b.md#nowhere",
        f"{A}: undefined reference -> [nope]",
        f"{A}: undefined reference -> [nope2]",
    ]


def test_inline_link_forms(site):
    text = ('[t](b.md "title") [t](<b.md#part>) [t](b.md#part) ![img](missing.png) '
            "[t](https://x.org/a) [t](mailto:a@b.c) [t](#local) [t](#nowhere)\n\n# Local\n")
    assert problems(site, text) == [
        f"{A}: missing file -> missing.png",
        f"{A}: missing anchor -> #nowhere",
    ]


def test_root_absolute_links_resolve_against_the_repo_root(site):
    text = "[r](/README.md) [r](/README.md#setup--run) [r](/docs/b.md#part) [r](/nope.md) [r](/README.md#no)"
    assert problems(site, text) == [
        f"{A}: missing file -> /nope.md",
        f"{A}: missing anchor -> /README.md#no",
    ]


def test_links_outside_the_repo_are_missing(site):
    write(site.parent / "outside.md", "# Out\n")
    assert problems(site, "[o](../../outside.md)") == [f"{A}: missing file -> ../../outside.md"]


@pytest.mark.parametrize("heading,expected", [
    ("Setup &amp; run", "setup--run"),
    ("Line<br>break", "linebreak"),
    ("A<br/>B <sub>2</sub>", "ab-2"),
    ("`<br>` and &lt;br&gt;", "br-and-br"),
    ("**Bold** *it* _under_ __strong__ ~~gone~~", "bold-it-under-strong-gone"),
    ("snake_case_name and `co_de`", "snake_case_name-and-co_de"),
    (r"\_escaped\_", "_escaped_"),
    ("中文（全形）「引號」：測試、完成。", "中文全形引號測試完成"),
    ("5.6 預先登記的主要假設：③ 是否勝過 ②", "56-預先登記的主要假設-是否勝過-"),
    ("E:orchestration-01 — V 已查證", "eorchestration-01--v-已查證"),
    ('<a name="providers-10"></a>E:providers-10', "eproviders-10"),
    ("2.1 元件（[03 §1](03-system-architecture.md#1-元件總覽)）", "21-元件03-1"),
    ("OWASP 2026 [V][E:threat_modeling-32]", "owasp-2026-vethreat_modeling-32"),
    ("Café Ünïcode", "café-ünïcode"),
])
def test_github_slugs(heading, expected):
    assert links.slug(heading) == expected


def test_heading_parsing_and_duplicate_slugs(tmp_path):
    text = "\n".join([
        "# Dup", "## Dup", "## Dup-1", "## Dup", "## C#", "## Foo ##", "#NoSpace", "> ## Quoted", "    # Indented code",
        "```", "## In code", "```", '<span id="custom"></span>', "`<a name=\"notreal\">`",
    ])
    assert links.anchors(write(tmp_path / "x.md", text)) == {
        "dup", "dup-1", "dup-1-1", "dup-2", "c", "foo", "quoted", "custom"}
    text = "# Dup-1\n# Dup\n# Dup\n"
    assert links.anchors(write(tmp_path / "y.md", text)) == {"dup-1", "dup", "dup-2"}


def test_reference_link_in_heading_uses_its_text(tmp_path):
    text = "## See [the spec][s] now\n\n[s]: https://x.org\n"
    assert links.anchors(write(tmp_path / "z.md", text)) == {"see-the-spec-now"}


# ---------------------------------------------------------------- external links (no network)

@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def refuse(*_a, **_k):
        raise AssertionError("tests must not touch the network")
    monkeypatch.setattr(ext, "make_fetch", refuse)
    monkeypatch.setattr(ext.urllib.request, "urlopen", refuse)


def test_extract_urls():
    text = "\n".join([
        "Autolink <https://a.org/one> and [inline](https://b.org/two?x=1&y=2 \"t\").",
        "Bare https://c.org/three. And (see https://d.org/four_(x)) and https://e.org/five，中文.",
        "Ref [r][d]. `https://code.org/inline` and templates https://api.github.com/repos/{owner}/x.",
        "Reserved https://example.com/x http://www.example.org https://svc.example/ http://localhost:8080/",
        "Private http://10.0.0.1/ http://z4-proxy:3128/ ftp://f.org/x",
        "```", "https://fenced.org/x", "```",
        "",
        "[d]: https://f.org/six",
    ])
    assert ext.extract_urls(text) == [
        "https://b.org/two?x=1&y=2", "https://f.org/six", "https://a.org/one",
        "https://c.org/three", "https://d.org/four_(x)", "https://e.org/five",
    ]


def test_collect_dedups_fragments_and_counts_skipped(tmp_path):
    write(tmp_path / "README.md", "<https://a.org/p#one> and https://a.org/p#two and https://example.com/")
    write(tmp_path / "docs" / "x.md", "[x](https://a.org/p) https://b.org/")
    write(tmp_path / "docs" / "evidence" / "link-check-2026-01-01.md", "<https://old-report.org/>")
    found, skipped = ext.collect(ext.default_paths(tmp_path), tmp_path)
    assert sorted(found) == ["https://a.org/p", "https://b.org/"]
    assert found["https://a.org/p"].count == 3
    assert found["https://a.org/p"].files == {"README.md", "docs/x.md"}
    assert skipped == {"https://example.com/"}


@pytest.mark.parametrize("status,category", [
    (200, "ok"), (204, "ok"), (401, "blocked"), (403, "blocked"), (429, "blocked"), (999, "blocked"),
    (404, "broken"), (410, "broken"), (400, "error"), (500, "error"), (503, "error"), (None, "unreachable"),
])
def test_classify(status, category):
    assert ext.classify(status) == category


class FakeFetch:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def __call__(self, url, method):
        self.calls.append(method)
        return self.responses.pop(0)


def test_check_url_head_then_get_fallback():
    f = FakeFetch([ext.Fetch(200, "https://a.org/")])
    r = ext.check_url("https://a.org/", f)
    assert (r.category, r.method, f.calls) == ("ok", "HEAD", ["HEAD"])

    f = FakeFetch([ext.Fetch(405), ext.Fetch(200, "https://a.org/")])
    r = ext.check_url("https://a.org/", f)
    assert (r.category, r.status, r.method, f.calls) == ("ok", 200, "GET", ["HEAD", "GET"])

    f = FakeFetch([ext.Fetch(403), ext.Fetch(403)])
    assert ext.check_url("https://a.org/", f).category == "blocked"

    f = FakeFetch([ext.Fetch(429), ext.Fetch(None, note="timed out"), ext.Fetch(None, note="timed out")])
    r = ext.check_url("https://a.org/", f)
    assert (r.category, r.status, r.method, f.calls) == ("blocked", 429, "HEAD", ["HEAD", "GET", "GET"])

    f = FakeFetch([ext.Fetch(None), ext.Fetch(None), ext.Fetch(404)])
    assert ext.check_url("https://a.org/", f).category == "broken"

    f = FakeFetch([ext.Fetch(None), ext.Fetch(None), ext.Fetch(None)])
    assert ext.check_url("https://a.org/", f).category == "unreachable"


def test_redirect_then_success_counts_once_as_ok():
    f = FakeFetch([ext.Fetch(200, "https://new.org/page")])
    r = ext.check_url("http://old.org/page#frag", f)
    assert (r.category, r.final_url) == ("ok", "https://new.org/page") and "轉址" in r.note
    same = ext.check_url("https://a.org/p#x", FakeFetch([ext.Fetch(200, "https://a.org/p")]))
    assert same.final_url is None and same.note == ""

    results = [r, same,
               ext.check_url("https://c.org/", FakeFetch([ext.Fetch(403), ext.Fetch(403)])),
               ext.check_url("https://d.org/", FakeFetch([ext.Fetch(404), ext.Fetch(404)]))]
    report = ext.render_report(results, {}, skipped=2, date="2026-09-26")
    counts = dict(re.findall(r"^\| (ok|blocked|broken|error|unreachable)[^|]*\| (\d+) \|$", report, re.M))
    assert counts == {"ok": "2", "blocked": "1", "broken": "1", "error": "0", "unreachable": "0"}
    assert "| 合計 | 4 |" in report and "其中 1 個經轉址" in report and "另有 2 個 URL 未檢查" in report
    assert report.startswith("# 連結檢查紀錄（2026-09-26）")
    rows = [line for line in report.splitlines() if line.startswith("| ") and "<http" in line]
    assert sum("https://c.org/" in line for line in rows) == 2   # once in the problem table, once in the full list
    assert sum(line.startswith("| ok ") for line in rows) == 2


def test_list_mode_prints_urls_without_network(tmp_path, capsys):
    write(tmp_path / "README.md", "<https://a.org/x> https://b.org/y")
    assert ext.main(["--root", str(tmp_path), "--list"]) == 0
    assert capsys.readouterr().out.split() == ["https://a.org/x", "https://b.org/y"]
    assert not list(tmp_path.rglob("link-check-*.md"))


def test_main_writes_dated_report_with_injected_fetch(tmp_path, monkeypatch):
    write(tmp_path / "README.md", "<https://a.org/x> <https://b.org/y>")
    replies = {"https://a.org/x": ext.Fetch(200, "https://a.org/x"), "https://b.org/y": ext.Fetch(403)}
    monkeypatch.setattr(ext, "make_fetch", lambda timeout: lambda url, method: replies[url])
    assert ext.main(["--root", str(tmp_path), "--date", "2026-01-02", "--workers", "2"]) == 0
    report = (tmp_path / "docs" / "evidence" / "link-check-2026-01-02.md").read_text(encoding="utf-8")
    assert "| 合計 | 2 |" in report and "| blocked | 403 | <https://b.org/y> | README.md |" in report
