# SPDX-License-Identifier: Apache-2.0
"""Review r11 (external review of 2823823), mutation runner: a mutation counts as CAUGHT only when the selected tests
pass on the unmutated source and then fail an assertion on the mutated one. The runner used to treat any non-zero pytest
exit status as a catch, so a `-k` that selects nothing (exit 5), a usage error (4) or a collection error looked like
success. Each test builds a tiny git repository, so it exercises the real runner end to end (tools/mutation_check.py)."""
import subprocess

import pytest

import mutation_check as mc

SRC = "def f():\n    return 1\n"
TESTS = (
    "from src import f\n\n"
    "def test_covers_f():\n    assert f() == 1\n\n"
    "def test_ignores_f():\n    assert True\n\n"
    "def test_already_red():\n    assert False\n"
)


@pytest.fixture
def repo(tmp_path):
    (tmp_path / "src.py").write_text(SRC, encoding="utf-8")
    (tmp_path / "test_x.py").write_text(TESTS, encoding="utf-8")
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True)
    return tmp_path


def run(repo, k, new="    return 2"):
    spec = {"_name": "t.json", "tests": "test_x.py",
            "mutations": [{"name": "m", "file": "src.py", "old": "    return 1", "new": new, "k": k}]}
    lines, bad = mc.evaluate([spec], repo)
    return lines[0].split("]")[0].strip("[ "), bad, lines


def test_a_failed_assertion_is_caught(repo):
    status, bad, _ = run(repo, "test_covers_f")
    assert (status, bad) == ("CAUGHT", 0)


def test_tests_that_still_pass_are_missed(repo):
    status, bad, _ = run(repo, "test_ignores_f")
    assert (status, bad) == ("MISSED", 1)


def test_a_k_that_selects_nothing_is_not_a_catch(repo):
    status, bad, lines = run(repo, "no_such_test_zzz")
    assert (status, bad) == ("VERIFY", 1)
    assert "selects no test" in lines[0]


def test_a_baseline_that_already_fails_is_not_a_catch(repo):
    status, bad, lines = run(repo, "test_already_red")
    assert (status, bad) == ("VERIFY", 1)
    assert "do not all pass on the unmutated source" in lines[0]


def test_a_collection_error_caused_by_the_mutation_is_not_a_catch(repo):
    status, bad, lines = run(repo, "test_covers_f", new="    return (")
    assert (status, bad) == ("VERIFY", 1)
    assert "not an assertion failure" in lines[0]


def test_a_bad_k_expression_is_not_a_catch(repo):
    status, bad, _ = run(repo, "bad (( expr")
    assert (status, bad) == ("VERIFY", 1)


def test_a_missing_test_file_is_not_a_catch(repo):
    spec = {"_name": "t.json", "tests": "does_not_exist.py",
            "mutations": [{"name": "m", "file": "src.py", "old": "    return 1", "new": "    return 2", "k": "x"}]}
    lines, bad = mc.evaluate([spec], repo)
    assert bad == 1 and lines[0].startswith("[VERIFY]")


def test_a_stale_anchor_is_skipped_and_counts(repo):
    spec = {"_name": "t.json", "tests": "test_x.py",
            "mutations": [{"name": "m", "file": "src.py", "old": "not in the file", "new": "x", "k": "test_covers_f"}]}
    lines, bad = mc.evaluate([spec], repo)
    assert bad == 1 and lines[0].startswith("[SKIP")


def test_the_source_is_restored_between_mutations(repo):
    spec = {"_name": "t.json", "tests": "test_x.py", "mutations": [
        {"name": "a", "file": "src.py", "old": "    return 1", "new": "    return 2", "k": "test_covers_f"},
        {"name": "b", "file": "src.py", "old": "    return 1", "new": "    return 3", "k": "test_covers_f"}]}
    lines, bad = mc.evaluate([spec], repo)
    assert bad == 0 and all(ln.startswith("[CAUGHT") for ln in lines[:2])
    assert (repo / "src.py").read_text(encoding="utf-8") == SRC


def test_the_exit_status_follows_the_result(repo, tmp_path, monkeypatch, capsys):
    def write(name, k):
        f = tmp_path / name
        f.write_text('{"tests": "test_x.py", "mutations": [{"name": "m", "file": "src.py", "old": "    return 1",'
                     ' "new": "    return 2", "k": "%s"}]}' % k, encoding="utf-8")
        return str(f)
    monkeypatch.setattr(mc, "ROOT", repo)
    monkeypatch.setattr(mc, "evaluate", lambda lists, root=repo, _ev=mc.evaluate: _ev(lists, repo))
    assert mc.main([write("good.json", "test_covers_f")]) == 0
    assert mc.main([write("bad.json", "no_such_test_zzz")]) == 1
    assert "[VERIFY]" in capsys.readouterr().out


def test_a_run_leaves_no_bytecode_behind(repo, monkeypatch):
    """A same-size mutation written within the same second would otherwise load the cached original (stale .pyc)."""
    monkeypatch.delenv("PYTHONDONTWRITEBYTECODE", raising=False)      # the runner itself must set it
    assert mc.run_tests(repo, "test_x.py", "test_covers_f").code == 0
    assert not list(repo.rglob("__pycache__")) and not list(repo.rglob("*.pyc"))
