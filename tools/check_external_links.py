#!/usr/bin/env python3
"""Check the external http(s) links in README.md and docs/**/*.md (opt-in, not run in CI).

Earlier reports (docs/**/link-check-YYYY-MM-DD.md) are not scanned. From the
other files every external URL is collected: autolinks `<https://...>`, inline and
reference-style link destinations, and bare URLs. Fenced code blocks, code
spans and HTML comments are skipped, and so are URL templates (`.../{owner}`),
the reserved example domains (example.com/.net/.org, .test, .invalid, ...) and
loopback or private addresses. URLs are de-duplicated; the #fragment is never
sent to the server, so `page#a` and `page#b` are one check.

Each URL is requested with HEAD, then with GET when HEAD fails or is refused.
Redirects are followed, and a URL that redirects and then succeeds is counted
once, as ok. Every URL lands in exactly one class:

    ok           2xx after redirects
    blocked      401, 403, 429 or 999: the site refused an automated client; the
                 link is unverified, which is not the same as ok
    broken       404 or 410
    error        any other 4xx/5xx status, or a redirect loop
    unreachable  DNS, TLS or connection failure, or timeout (retried once)

The result is a dated Markdown report, docs/evidence/link-check-YYYY-MM-DD.md by
default. Only the standard library is used: urllib honours HTTP(S)_PROXY and
NO_PROXY like requests does, and the first CA bundle named by SSL_CERT_FILE,
REQUESTS_CA_BUNDLE or CURL_CA_BUNDLE replaces the default trust store.

    python tools/check_external_links.py              # check and write the report
    python tools/check_external_links.py --list       # print the URLs only, no network
    python tools/check_external_links.py -o /tmp/links.md --workers 4 --timeout 20
"""
import argparse
import concurrent.futures
import dataclasses
import datetime
import http.client
import ipaddress
import os
import pathlib
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

from check_doc_links import DEFINITION, extract, strip_code

ROOT = pathlib.Path(__file__).resolve().parents[1]
USER_AGENT = "Mozilla/5.0 (compatible; vibecheck-link-check/1.0; +tools/check_external_links.py)"

_URL_CHARS = r"[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]"
BARE_URL = re.compile(r"(?<![\w(<\"'=/])https?://" + _URL_CHARS + "+")
AUTOLINK = re.compile(r"<(https?://[^\s<>]+)>")
EXAMPLE_HOSTS = ("example.com", "example.net", "example.org")
RESERVED_TLDS = ("example", "test", "invalid", "localhost", "local", "internal")
REPORT_NAME = re.compile(r"link-check-\d{4}-\d{2}-\d{2}\.md")

CATEGORIES = [
    ("ok", "ok（2xx）"),
    ("blocked", "blocked／未查證（401、403、429）"),
    ("broken", "broken（404、410）"),
    ("error", "error（其他 4xx／5xx）"),
    ("unreachable", "unreachable（逾時、DNS、TLS、連線失敗）"),
]


# ---------------------------------------------------------------- extraction

def _blank(m: re.Match) -> str:
    return re.sub(r"[^\n]", " ", m.group(0))


def trim_url(url: str) -> str:
    """Drop trailing punctuation the way GFM autolinks do (and unbalanced `)` / `]`)."""
    while True:
        before = url
        url = url.rstrip("?!.,:;*_~'\"")
        for open_, close in ("()", "[]"):
            if url.endswith(close) and url.count(close) > url.count(open_):
                url = url[:-1]
        if url == before:
            return url


def is_checkable(url: str) -> bool:
    """False for URL templates, reserved example domains and local or private hosts."""
    if any(c in url for c in "{}<>…") or "..." in url:
        return False
    try:
        host = (urllib.parse.urlsplit(url).hostname or "").rstrip(".").lower()
    except ValueError:
        return False
    if not host:
        return False
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        return ip.is_global
    if "." not in host:
        return False
    if host.rsplit(".", 1)[1] in RESERVED_TLDS:
        return False
    return not any(host == h or host.endswith("." + h) for h in EXAMPLE_HOSTS)


def candidate_urls(text: str) -> list[str]:
    """Every http(s) URL in one Markdown text, in order of appearance, before filtering."""
    inline, definitions, _ = extract(text)
    stripped = strip_code(text)
    found = [u for u in inline + list(definitions.values()) if u.lower().startswith(("http://", "https://"))]
    found += AUTOLINK.findall(stripped)
    stripped = AUTOLINK.sub(_blank, DEFINITION.sub(_blank, stripped))   # already collected above
    for m in BARE_URL.finditer(stripped):
        url = trim_url(m.group(0))
        if m.end() < len(stripped) and stripped[m.end()] in "{<":
            url += stripped[m.end()]      # a template (https://host/repos/{owner}): keep the
        found.append(url)                 # brace so is_checkable() rejects it
    return found


def extract_urls(text: str) -> list[str]:
    """The external URLs worth checking in one Markdown text (not de-duplicated)."""
    return [u for u in candidate_urls(text) if is_checkable(u)]


def dedup_key(url: str) -> str:
    return urllib.parse.urldefrag(url)[0]


@dataclasses.dataclass
class Link:
    url: str
    files: set[str] = dataclasses.field(default_factory=set)
    count: int = 0


def collect(paths: list[pathlib.Path], root: pathlib.Path) -> tuple[dict[str, Link], set[str]]:
    """(links to check keyed by URL without fragment, URLs skipped by is_checkable)."""
    links: dict[str, Link] = {}
    skipped: set[str] = set()
    for path in paths:
        rel = path.relative_to(root).as_posix()
        for url in candidate_urls(path.read_text(encoding="utf-8")):
            if not is_checkable(url):
                skipped.add(url)
                continue
            link = links.setdefault(dedup_key(url), Link(dedup_key(url)))
            link.files.add(rel)
            link.count += 1
    return links, skipped


def default_paths(root: pathlib.Path) -> list[pathlib.Path]:
    """README.md and docs/**/*.md, without earlier link-check reports."""
    docs = sorted(p for p in (root / "docs").rglob("*.md") if not REPORT_NAME.fullmatch(p.name))
    return [root / "README.md", *docs]


# ---------------------------------------------------------------- checking

@dataclasses.dataclass
class Fetch:
    status: int | None           # HTTP status, None when no response arrived
    final_url: str | None = None
    note: str = ""


@dataclasses.dataclass
class Result:
    url: str
    category: str
    status: int | None
    method: str
    final_url: str | None
    note: str


def classify(status: int | None) -> str:
    if status is None:
        return "unreachable"
    if 200 <= status < 300:
        return "ok"
    if status in (401, 403, 429, 999):
        return "blocked"
    if status in (404, 410):
        return "broken"
    return "error"


def ssl_context() -> ssl.SSLContext:
    for var in ("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"):
        cafile = os.environ.get(var)
        if cafile and os.path.isfile(cafile):
            return ssl.create_default_context(cafile=cafile)
    return ssl.create_default_context()


def make_fetch(timeout: float):
    """A fetch(url, method) -> Fetch using urllib (environment proxies, redirects followed)."""
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ssl_context()))

    def fetch(url: str, method: str) -> Fetch:
        req = urllib.request.Request(url, method=method, headers={"User-Agent": USER_AGENT, "Accept": "*/*"})
        try:
            with opener.open(req, timeout=timeout) as resp:
                return Fetch(resp.status, resp.geturl())
        except urllib.error.HTTPError as e:
            e.close()
            return Fetch(e.code, e.geturl(), e.reason if isinstance(e.reason, str) else "")
        except (OSError, http.client.HTTPException, ValueError) as e:   # URLError, timeout, TLS, reset
            reason = getattr(e, "reason", e)
            return Fetch(None, None, f"{type(reason).__name__}: {reason}"[:200])

    return fetch


def check_url(url: str, fetch, retries: int = 1) -> Result:
    """HEAD first; GET when HEAD does not give a 2xx. One class per URL."""
    head = fetch(url, "HEAD")
    if head.status is not None and 200 <= head.status < 300:
        chosen, method = head, "HEAD"
    else:
        get = fetch(url, "GET")
        for _ in range(retries):
            if get.status is not None:
                break
            get = fetch(url, "GET")
        if get.status is None and head.status is not None:
            chosen, method = head, "HEAD"
        else:
            chosen, method = get, "GET"
    note = chosen.note
    final = chosen.final_url
    if final and dedup_key(final) != dedup_key(url):
        note = (f"轉址到 {final}" + (f"；{note}" if note else ""))
    else:
        final = None
    return Result(url, classify(chosen.status), chosen.status, method, final, note)


def check_all(urls: list[str], fetch, workers: int, retries: int = 1) -> list[Result]:
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        return list(pool.map(lambda u: check_url(u, fetch, retries), urls))


# ---------------------------------------------------------------- report

def _cell(text: str) -> str:
    return (text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace("|", "\\|").replace("\n", " "))


def render_report(results: list[Result], links: dict[str, Link], skipped: int, date: str) -> str:
    counts = {key: 0 for key, _ in CATEGORIES}
    for r in results:
        counts[r.category] += 1
    redirected_ok = sum(1 for r in results if r.category == "ok" and r.final_url)
    order = {key: i for i, (key, _) in enumerate(CATEGORIES)}
    rows = sorted(results, key=lambda r: (order[r.category], r.url))
    lines = [
        f"# 連結檢查紀錄（{date}）",
        "",
        "> 由 `tools/check_external_links.py` 產生：README.md 與 docs/**/*.md 中的外部 URL（去重、不含程式碼區塊），"
        "先送 HEAD，失敗或被拒時改送 GET，並跟隨轉址。每個 URL 只計一次；轉址後成功算 ok。"
        "**blocked 表示網站拒絕自動化請求（401／403／429），連結未查證，不代表正常。**",
        "",
        "## 統計",
        "",
        "| 類別 | 數量 |",
        "|---|---|",
    ]
    for key, label in CATEGORIES:
        extra = f"（其中 {redirected_ok} 個經轉址）" if key == "ok" and redirected_ok else ""
        lines.append(f"| {label}{extra} | {counts[key]} |")
    lines += [f"| 合計 | {len(results)} |", ""]
    if skipped:
        lines += [f"另有 {skipped} 個 URL 未檢查（URL 範本、保留的範例網域或內部位址）。", ""]
    problems = [r for r in rows if r.category != "ok"]
    lines += ["## 非 ok 的 URL", ""]
    if problems:
        lines += ["| 類別 | HTTP | URL | 出現於 | 備註 |", "|---|---|---|---|---|"]
        for r in problems:
            files = "、".join(sorted(links[r.url].files)) if r.url in links else ""
            lines.append(f"| {r.category} | {r.status or '—'} | <{r.url}> | {_cell(files)} | {_cell(r.note)} |")
    else:
        lines.append("無。")
    lines += ["", "## 全部 URL", "", "| 類別 | HTTP | 方法 | URL | 備註 |", "|---|---|---|---|---|"]
    for r in rows:
        lines.append(f"| {r.category} | {r.status or '—'} | {r.method} | <{r.url}> | {_cell(r.note)} |")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", type=pathlib.Path, default=ROOT, help="repository root (default: this checkout)")
    ap.add_argument("-o", "--output", type=pathlib.Path,
                    help="report path (default: docs/evidence/link-check-<date>.md under the root)")
    ap.add_argument("--date", default=datetime.date.today().isoformat(), help="date for the report (YYYY-MM-DD)")
    ap.add_argument("--timeout", type=float, default=20.0, help="seconds per request (default 20)")
    ap.add_argument("--workers", type=int, default=4, help="concurrent requests (default 4)")
    ap.add_argument("--retries", type=int, default=1, help="GET retries after a timeout or connection error")
    ap.add_argument("--list", action="store_true", help="print the de-duplicated URLs and exit; no network")
    args = ap.parse_args(argv)

    paths = default_paths(args.root)
    links, skipped = collect(paths, args.root)
    urls = sorted(links)
    if args.list:
        for url in urls:
            print(url)
        print(f"{len(urls)} unique URL(s) in {len(paths)} file(s)", file=sys.stderr)
        return 0
    results = check_all(urls, make_fetch(args.timeout), args.workers, args.retries)
    out = args.output or args.root / "docs" / "evidence" / f"link-check-{args.date}.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render_report(results, links, len(skipped), args.date), encoding="utf-8", newline="\n")
    summary = ", ".join(f"{key} {sum(r.category == key for r in results)}" for key, _ in CATEGORIES)
    print(f"wrote {out}: {len(results)} URL(s): {summary}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
