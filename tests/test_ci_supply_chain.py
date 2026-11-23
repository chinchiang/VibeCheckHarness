# SPDX-License-Identifier: Apache-2.0
"""CI hardening of the 2026-11-22 review (findings E9 and E10).

E9   requirements.lock pinned versions only (docs/09 BL-57): pip accepted any file an index served under a version.
     Both requirement files now list the sha256 of every file of each pinned release (tools/lock_hashes.py) and every
     `pip install -r` in CI passes --require-hashes.
E10  CI checked only that mutation anchors still match (--anchors-only); it never ran a mutation. A pull request now runs
     the lists it touched (tools/changed_mutation_lists.py, job `mutations`), and a weekly workflow runs all of them.

Each test failed before the change and passes after it (tests/mutations/ci_supply_chain.json); see CONTRIBUTING.md."""
import importlib.util
import pathlib
import re

import pytest
import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
LOCKS = ("requirements.lock", "requirements-dev.txt")


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "tools" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def lh():
    return load("lock_hashes")


@pytest.fixture(scope="module")
def cml():
    return load("changed_mutation_lists")


def workflow(name):
    return yaml.safe_load((ROOT / ".github" / "workflows" / name).read_text(encoding="utf-8"))


def runs(wf):
    return [s["run"] for job in wf["jobs"].values() for s in job["steps"] if "run" in s]


# ================================================================ E9: hashes
@pytest.mark.parametrize("name", LOCKS)
def test_every_pinned_requirement_carries_a_hash(lh, name):
    text = (ROOT / name).read_text(encoding="utf-8")
    assert lh.problems(text) == []
    pins = [e for e in lh.parse(text) if "name" in e]
    assert len(pins) >= 5 and all(e["hashes"] and all(re.fullmatch(r"[0-9a-f]{64}", h) for h in e["hashes"]) for e in pins)
    assert lh.render(lh.parse(text)) == text                  # the file is exactly what the tool writes


def test_a_pin_without_a_hash_is_reported(lh):
    assert lh.problems("a==1.0\nb==2.0 \\\n    --hash=sha256:" + "0" * 64 + "\n") == ["a==1.0: no --hash line"]
    assert lh.problems("# only a comment\n") == ["no pinned requirement"]
    assert lh.problems("a>=1.0\n")[0].startswith("line 1: not a comment")
    assert lh.problems("    --hash=sha256:" + "0" * 64 + "\n")[0].startswith("line 1:")      # a hash that belongs to no pin
    assert lh.problems("a==1.0 \\\n    --hash=md5:abc\n")[0].startswith("line 2:")


def test_render_keeps_comments_and_sorts_hashes(lh):
    h1, h2 = "b" * 64, "a" * 64
    text = lh.render([{"comment": "# note"}, {"name": "x", "version": "1", "hashes": [h1, h2, h1]}, {"name": "y", "version": "2", "hashes": []}])
    assert text == f"# note\nx==1 \\\n    --hash=sha256:{h2} \\\n    --hash=sha256:{h1}\ny==2\n"
    assert lh.parse(text)[1]["hashes"] == [h2, h1]


def test_ci_installs_every_requirement_file_with_require_hashes():
    seen = 0
    for name in ("validate.yml", "mutations.yml"):
        for cmd in runs(workflow(name)):
            for line in cmd.splitlines():
                if "pip install" in line and " -r " in line:
                    seen += 1
                    assert "--require-hashes" in line, (name, line)
    assert seen >= 7
    assert any("tools/lock_hashes.py --check requirements.lock requirements-dev.txt" in c for c in runs(workflow("validate.yml")))


def test_a_dependency_only_some_platforms_need_must_be_pinned(lh):
    """The first hashed lock installed where it was made and failed on three of four CI platforms: referencing needs
    typing_extensions below Python 3.13 and pytest needs colorama on Windows; neither was pinned."""
    requires = {"referencing": ["attrs>=22.2.0", 'typing-extensions>=4.4.0; python_version < "3.13"'],
                "pytest": ['colorama>=0.4; sys_platform == "win32"', "pluggy<2,>=1.5", 'tomli>=1; python_version < "3.11"'],
                "pytest-xdist": ["pytest>=7.0.0", 'psutil>=3.0; extra == "psutil"']}
    lock = {"referencing": "0.37.0", "attrs": "26.1.0", "pytest": "9.1.1", "pluggy": "1.7.0"}
    got = lh.closure_problems([("requirements.lock", lock)], requires)
    assert got == ["requirements.lock: pytest needs colorama on python 3.11 / win32, which is not pinned in this file or an earlier one",
                   "requirements.lock: pytest needs colorama on python 3.13 / win32, which is not pinned in this file or an earlier one",
                   "requirements.lock: referencing needs typing-extensions on python 3.11 / linux, which is not pinned in this file or an earlier one",
                   "requirements.lock: referencing needs typing-extensions on python 3.11 / win32, which is not pinned in this file or an earlier one"]
    full = dict(lock, typing_extensions="4.16.0", colorama="0.4.6")
    assert lh.closure_problems([("requirements.lock", full)], requires) == []
    # a later file may rely on an earlier one, not the other way round; an extra is not followed
    dev = {"pytest-xdist": "3.8.0"}
    assert lh.closure_problems([("requirements.lock", full), ("requirements-dev.txt", dev)], requires) == []
    assert any("pytest-xdist needs pytest" in m for m in lh.closure_problems([("requirements-dev.txt", dev), ("requirements.lock", full)], requires))
    # a pin outside the required range
    assert lh.closure_problems([("l", dict(full, pluggy="2.0.0"))], requires) == ["l: pytest needs pluggy<2,>=1.5, but pluggy is pinned to 2.0.0"]


def test_the_lock_pins_the_platform_dependent_requirements(lh):
    pins = {lh.norm(e["name"]) for e in lh.parse((ROOT / "requirements.lock").read_text(encoding="utf-8")) if "name" in e}
    assert {"typing-extensions", "colorama"} <= pins
    lint = workflow("validate.yml")["jobs"]["lint"]
    installs = [s["run"] for s in lint["steps"] if "pip install" in str(s.get("run"))]
    assert [("requirements.lock" in c, "requirements-dev.txt" in c) for c in installs] == [(True, False), (False, True)]    # lock first


# ================================================================ E10: mutations run in CI
def test_a_list_is_selected_by_its_own_change_or_its_tests(cml):
    lists = {"tests/mutations/a.json": "tests/test_a.py", "tests/mutations/b.json": "tests/test_b.py", "tests/mutations/c.json": None}
    pick = lambda *changed: cml.changed_lists(set(changed), lists)
    assert pick("tests/mutations/a.json") == ["tests/mutations/a.json", "tests/mutations/c.json"]     # c: unreadable -> look at it
    assert pick("tests/test_b.py") == ["tests/mutations/b.json", "tests/mutations/c.json"]
    assert pick("tools/vchlib/checks.py", "README.md") == ["tests/mutations/c.json"]                  # a mutated file selects nothing
    assert cml.changed_lists({"tests/test_a.py", "tests/mutations/b.json"}, {k: v for k, v in lists.items() if v}) == \
        ["tests/mutations/a.json", "tests/mutations/b.json"]


def test_every_list_in_the_repository_names_its_tests(cml):
    lists = cml.all_lists()
    assert len(lists) >= 49 and all(t and (ROOT / t).is_file() for t in lists.values()), {k: v for k, v in lists.items() if not v}
    assert cml.changed_lists(set(), lists) == []
    assert cml.changed_lists({"tests/mutations/ci_supply_chain.json"}, lists) == ["tests/mutations/ci_supply_chain.json"]
    assert "tests/mutations/ci_supply_chain.json" in cml.changed_lists({"tests/test_ci_supply_chain.py"}, lists)


def test_the_pull_request_job_runs_the_touched_lists():
    job = workflow("validate.yml")["jobs"]["mutations"]
    assert job.get("if") == "github.event_name == 'pull_request'"
    checkout = next(s for s in job["steps"] if str(s.get("uses", "")).startswith("actions/checkout@"))
    assert checkout["with"].get("fetch-depth") == 0                # the merge base must be in the clone
    run = job["steps"][-1]["run"]
    assert 'python tools/changed_mutation_lists.py "origin/$BASE_REF"' in run and "python tools/mutation_check.py" in run
    assert "--anchors-only" not in run                         # the mutations are run, not only located
    assert "${{" not in run                                    # the branch name reaches the shell through the environment
    assert job["env"]["BASE_REF"] == "${{ github.base_ref }}"
    assert sorted(job["strategy"]["matrix"]["shard"]) == [0, 1, 2, 3] and "NR % 4 == s" in run


def test_the_weekly_workflow_runs_every_list():
    wf = workflow("mutations.yml")
    on = wf.get("on") or wf.get(True)                          # YAML 1.1 reads the key `on` as true
    assert "schedule" in on and "workflow_dispatch" in on
    run = wf["jobs"]["all-lists"]["steps"][-1]["run"]
    assert "python tools/changed_mutation_lists.py --all" in run and "python tools/mutation_check.py" in run
    assert wf["permissions"] == {"contents": "read"}


def test_the_documents_say_so():
    c = (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
    assert "python tools/lock_hashes.py requirements.lock requirements-dev.txt" in c and "**CI 會執行突變清單**" in c
    row = next(ln for ln in (ROOT / "docs" / "09-backlog.md").read_text(encoding="utf-8").splitlines() if ln.startswith("| BL-57 |"))
    assert "`tools/lock_hashes.py`" in row and "已完成" in row and "不能證明檔案無害" in row
