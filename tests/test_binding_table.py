# SPDX-License-Identifier: Apache-2.0
"""The Binding table of docs/04 section 4.3 (2026-11-22 review C7, docs/09 BL-75).

The table had no row for the connection / subscription authorisation of WebSocket and SSE channels, for the rendering of
model output (auto-loaded images and links), or for an injection check a Lite run may execute. The OAuth / OIDC and JWT
rows existed but tested one thing each. Three rows are added and two extended; no adapter is added.

A correction is part of this change: the paragraph listing what the table does not cover said "none of these has a row"
while OAuth / OIDC and JWT had one each. That sentence was written from an unverified agent report.

The tests parse the six sub-tables, so they also hold for every row that was already there:
  - a row has as many cells as its header;
  - its adapter is a mode registered in tools.yaml, `manual`, or marked 候選, and its safety class is not below the
    mode's base_class;
  - a WSTG id carries an evidence tag in the same cell (the JWT row must not cite SESS-10: WSTG v4.2 has no such test).

This is specification text; the adapters are not implemented. tests/mutations/binding_table.json; see CONTRIBUTING.md."""
import pathlib
import re

import pytest
import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
ADAPTER_RE = re.compile(r"`([a-z][a-z0-9_]*:[a-z][a-z0-9_]*)`")


def text(rel):
    return (ROOT / rel).read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def section():
    return text("docs/04-threat-to-testcase.md").split("### 4.3 Binding 表", 1)[1].split("\n### ", 1)[0]


@pytest.fixture(scope="module")
def tables(section):
    """{letter: (header cells, [row cells])} of the sub-tables A-F."""
    out, cur = {}, None
    for ln in section.splitlines():
        if m := re.match(r"\*\*([A-F])\. ", ln):
            cur = m.group(1)
            out[cur] = (None, [])
        elif ln.startswith("**這張表沒有涵蓋的類別**"):
            cur = None
        elif cur and ln.startswith("| ") and not ln.startswith("|---"):
            cells = [c.strip() for c in ln.strip().strip("|").split("|")]
            if out[cur][0] is None:
                out[cur] = (cells, [])
            else:
                out[cur][1].append(cells)
    return out


@pytest.fixture(scope="module")
def modes():
    tools = yaml.safe_load(text("docs/examples/tools.yaml"))["tools"]
    return {f"{t}:{m}": v.get("base_class") for t, d in tools.items() for m, v in d["modes"].items()}


def rows(tables):
    return [(k, hdr, r) for k, (hdr, rs) in tables.items() for r in rs]


def find(tables, letter, name):
    hits = [r for r in tables[letter][1] if name in r[0]]
    assert len(hits) == 1, (letter, name, [r[0] for r in hits])
    return dict(zip(tables[letter][0], hits[0]))


# ================================================================ every row
def test_the_six_sub_tables_parse_and_every_row_matches_its_header(tables):
    assert sorted(tables) == list("ABCDEF")
    assert all(hdr and "kind＋adapter" in hdr and "安全等級" in hdr for hdr, _ in tables.values())
    bad = [(k, r[0], len(r), len(hdr)) for k, hdr, r in rows(tables) if len(r) != len(hdr)]
    assert not bad, bad
    assert len(rows(tables)) >= 82                             # 79 before this change, three rows added


def test_every_adapter_is_registered_or_marked_a_candidate(tables, modes):
    bad = []
    for k, hdr, r in rows(tables):
        cell = r[hdr.index("kind＋adapter")]
        for adapter in ADAPTER_RE.findall(cell):
            if adapter.split(":")[0] + ":*" in cell and adapter not in modes:
                continue                                        # a `tool:*` mention, not a binding
            if adapter not in modes and "候選" not in cell:
                bad.append((k, r[0], adapter))
    assert not bad, bad


def test_a_row_is_never_safer_than_its_adapter(tables, modes):
    bad = []
    for k, hdr, r in rows(tables):
        cell, level = r[hdr.index("kind＋adapter")], re.findall(r"S([0-3])", r[hdr.index("安全等級")])
        for adapter in ADAPTER_RE.findall(cell.split("（", 1)[0]):   # the binding itself, not a parenthesised remark
            base = modes.get(adapter)
            if base and level and max(map(int, level)) < int(base[1]):
                bad.append((k, r[0], adapter, base, r[hdr.index("安全等級")]))
    assert not bad, bad


def test_every_wstg_id_carries_an_evidence_tag(tables):
    ledger = text("docs/evidence/ledger.md")
    bad = []
    for k, hdr, r in rows(tables):
        cell = r[-1]
        if re.search(r"WSTG-v42-[A-Z]+-\d+", cell):
            tags = re.findall(r"\[E:([a-z_]+-\d+)\]", cell)
            if not (tags or re.search(r"\[S-\d+\]", cell)) or any(f'name="{t}"' not in ledger for t in tags):
                bad.append((k, r[0], cell))
    assert not bad, bad
    cited = set(re.findall(r"WSTG-v42-[A-Z]+-\d+", " ".join(r[-1] for _, _, r in rows(tables))))
    assert not cited & {"WSTG-v42-SESS-10", "WSTG-v42-CLNT-10", "WSTG-v42-ATHZ-05"}, "ids nobody verified (SESS-10 is not in v4.2)"


# ================================================================ the five surfaces
def test_the_oauth_row_checks_state_pkce_redirect_and_code_replay(tables):
    r = find(tables, "A", "OAuth／OIDC 流程")
    check = r["驗證方式（oracle）"]
    for needle in ("未登錄的 `redirect_uri`", "`state` 被改動", "`code_verifier`", "同一個授權碼用第二次", "不發 token"):
        assert needle in check, needle
    assert "帳號連結的混淆與身分提供者端的設定不測" in check and "以測試帳號" in check
    assert "`playwright:api`" in r["kind＋adapter"] and r["安全等級"] == "S1"
    assert "未對到官方 ID" in r["WSTG／AITG"] and "E:threat_modeling-40" in r["需求類型（G1 來源）"]


def test_the_jwt_row_checks_the_algorithm_key_id_and_issuer(tables):
    r = find(tables, "A", "JWT 處理")
    check = r["驗證方式（oracle）"]
    for needle in ("**單一欄位**", "一律 401", "簽章位元組改動", "過期", "錯誤受眾", "`iss`", "`alg` 改為 `none`", "以伺服器的公開金鑰當 HMAC 金鑰", "`kid` 指向不存在的金鑰"):
        assert needle in check, needle
    assert "JWKS 來源被替換與金鑰輪替不測" in check
    assert "ASVS 5.0 V9 Self-contained Tokens [V][E:threat_modeling-40]" in r["需求類型（G1 來源）"]
    assert "WSTG v4.2 無專屬 ID [V][E:threat_modeling-56]" in r["WSTG／AITG"]
    assert "V9 Self-contained Tokens" in text("docs/evidence/ledger.md").split('name="threat_modeling-40"', 1)[1][:1500]


def test_the_websocket_row_stays_inside_what_the_scope_proxy_allows(tables):
    r = find(tables, "A", "WebSocket／SSE 的連線與訂閱授權")
    check, bind = r["驗證方式（oracle）"], r["kind＋adapter"]
    assert "升級請求" in check and "**只接收**的訂閱" in check and "不收到租戶 B 種子資料的事件" in check
    assert "只能逐字送 G4 核准的 `script_turns`，否則是 MANUAL" in check and "訊息注入不測" in check
    assert "候選 [H]" in bind and "M4" in bind and r["安全等級"].startswith("S1")
    proxy = text("docs/08-implementation-spec.md").split("### 11.7 Scope Proxy 實作", 1)[1].split("\n### ", 1)[0]
    assert "(a) 只接收的訂閱；(b) 逐字送出 G4 核准的 `script_turns`" in proxy and "經 WebSocket 或 SSE 的測試限 S0／S1" in proxy


def test_the_rendering_row_uses_two_deterministic_oracles(tables):
    r = find(tables, "B", "輸出的渲染外洩")
    check = r["驗證方式（oracle）"]
    assert "`tester_controlled` canary 網址的 Markdown 圖片與連結" in check and "（`CANARY`）" in check and "（`DOM_ASSERTION`）" in check
    assert "`policies.csp`" in r["需求類型"] and "`playwright:ui`" in r["kind＋adapter"] and r["安全等級"] == "S1"
    kinds = yaml.safe_load(text("docs/schemas/invariants.schema.json"))
    assert "csp" in str(kinds) and "outbound_hosts" in str(kinds)          # the requirement sources the row names exist


def test_the_injection_probe_row_is_s1_and_says_what_it_cannot_find(tables, modes):
    r = find(tables, "A", "注入類定點檢查")
    check = r["驗證方式（oracle）"]
    assert "固定、少量、不具破壞性的語法標記" in check and "不含任何語句" in check
    assert "盲注與二階注入測不到" in check and "`E_pass_weak`" in check
    assert "`playwright:api`" in r["kind＋adapter"].split("（", 1)[0] and r["安全等級"].startswith("S1") and "`s1_request_cap`" in r["安全等級"]
    assert modes["schemathesis:hook"] == "S1" and "只跑 GET／HEAD" in r["kind＋adapter"]     # why it is not schemathesis
    broad = find(tables, "A", "注入類廣泛檢查")
    assert "`zap:active`" in broad["kind＋adapter"] and "S2" in broad["安全等級"]            # the active scan is untouched


def test_lite_reports_a_probe_not_an_injection_test(section):
    para = next(ln for ln in section.splitlines() if ln.startswith("**Lite 只有注入類的定點檢查**"))
    assert "它不是主動掃描的替代品" in para and "盲注與二階注入未測" in para and "不得寫成「沒有注入漏洞」" in para
    assert "**Lite 沒有黑箱注入測試**" not in section


# ================================================================ what is still not covered
def test_the_uncovered_paragraph_names_rows_that_exist_and_no_longer_says_none_has_a_row(section, tables):
    para = section.split("**這張表沒有涵蓋的類別**", 1)[1].split("這兩個 inventory 旗標", 1)[0]
    assert "下列攻擊面沒有任何一列，也沒有樣板 adapter" not in para
    assert "那是錯的：OAuth／OIDC 與 JWT 當時已各有一列" in para        # the correction is on the page
    names = [r[0] for _, _, r in rows(tables)]
    table = [ln for ln in para.splitlines() if ln.startswith("| ") and not ln.startswith("| 類別")]
    assert len(table) == 5
    for ln in table:
        cited = re.findall(r"「([^」]+)」", ln.strip().strip("|").split("|")[2].split("；見上面", 1)[0])
        assert cited, ln
        for c in cited:
            assert sum(c in n for n in names) == 1, (c, [n for n in names if c in n])


def test_the_backlog_says_listed_not_implemented():
    row = next(ln for ln in text("docs/09-backlog.md").splitlines() if ln.startswith("| BL-75 |"))
    assert "| 已補列；全部未實作，websocket 能力仍是候選 |" in row and "沒有新增 adapter" in row and "PKCE" in row
