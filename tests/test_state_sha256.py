# SPDX-License-Identifier: Apache-2.0
"""`state_sha256` of a checkpoint is the content hash of the run record (2026-11-24; found while writing docs/08 11.21).

docs/08 section 7.1 and the checkpoint-metadata schema said "the JCS hash of RunState". The reference validator has
always derived it from the RUN RECORD (vchlib.expectations: content_hash(run.data), E-DERIVED), sign_examples writes it
that way, and a bundle holds no RunState document at all, so the written rule could not be checked. docs/03 section 5.1
also had the relation backwards ("the run record is a subset of RunState"): the sketched class lacked three fields the
run record has.

The specification now says what the validator does. Nothing in the validator or the examples changed; these tests hold
the three places together and pin the behaviour, so the text was not loosened along the way.

Each docs test failed before the change and passes after it (tests/mutations/state_sha256.json); see CONTRIBUTING.md."""
import json
import pathlib
import re

from conftest import doc
from vchlib.canonical import content_hash
from vchlib.checks import run_all

ROOT = pathlib.Path(__file__).resolve().parents[1]
RUN, CKPT = "run.followup.example.json", "checkpoint-metadata.followup.example.json"


def text(rel):
    return (ROOT / rel).read_text(encoding="utf-8")


def derived(b):
    return [i for i in run_all(b).errors if i.code == "E-DERIVED" and "state_sha256" in i.msg]


# ---------------------------------------------------------------- behaviour (unchanged; pinned)
def test_the_example_checkpoint_carries_the_hash_of_its_run_record(b):
    assert doc(b, CKPT).data["state_sha256"] == content_hash(doc(b, RUN).data)
    assert derived(b) == []


def test_a_run_record_that_changed_without_its_checkpoint_is_reported(b):
    doc(b, RUN).data["w4_iteration"] = (doc(b, RUN).data.get("w4_iteration") or 0) + 1
    assert derived(b), "the checkpoint still carries the hash of the earlier run record"
    doc(b, CKPT).data["state_sha256"] = content_hash(doc(b, RUN).data)
    assert derived(b) == []


def test_a_hash_of_anything_else_is_not_accepted(b):
    doc(b, CKPT).data["state_sha256"] = content_hash({"run_id": doc(b, RUN).data["run_id"]})
    assert derived(b)


# ---------------------------------------------------------------- the three places say the same thing
def test_the_spec_defines_it_as_the_hash_of_the_run_record():
    s71 = text("docs/08-implementation-spec.md").split("### 7.1 LangGraph checkpointer", 1)[1].split("### 7.2", 1)[0]
    assert "**`state_sha256` 是該 checkpoint 當下 run 紀錄的內容雜湊**" in s71
    assert "`content_hash`" in s71 and "run.schema.json" in s71 and "`E-DERIVED`" in s71 and "`E-CHECKPOINT`" in s71
    assert "**最後一個** checkpoint" in s71 and "`IntegrityError`" in s71
    assert "`state_sha256`（`RunState` 的 JCS hash）" not in s71


def test_the_schema_describes_the_same_thing():
    sch = json.loads(text("docs/schemas/checkpoint-metadata.schema.json"))
    for d in (sch["description"], sch["properties"]["state_sha256"]["description"]):
        assert "run 紀錄" in d and "content_hash" in d, d
        assert "RunState 的 JCS hash" not in d and "序列化 RunState" not in d
    assert sch["properties"]["state_sha256"].get("$ref") == "common.schema.json#/$defs/sha256"   # the constraint is untouched


def test_the_validator_derives_it_from_the_run_record():
    src = text("tools/vchlib/expectations.py")
    assert 'exp(d, ["state_sha256"], content_hash(run.data), "content hash of the run state")' in src


def test_the_spike_case_no_longer_asks_for_a_definition():
    row = next(ln for ln in text("docs/08-implementation-spec.md").splitlines() if ln.startswith("| LG-09 |"))
    assert "已在 §7.1 定案" in row and "兩者要統一" not in row and "`IntegrityError`" in row


# ---------------------------------------------------------------- RunState and the run record
def runstate_fields():
    cls = text("docs/03-system-architecture.md").split("class RunState(BaseModel):", 1)[1].split("```", 1)[0]
    return re.findall(r"^    (\w+):", cls, re.M)


def test_the_sketched_runstate_has_exactly_the_fields_of_the_run_record():
    fields = runstate_fields()
    props = set(json.loads(text("docs/schemas/run.schema.json"))["properties"])
    assert len(fields) == len(set(fields))
    assert set(fields) == props, (sorted(set(fields) - props), sorted(props - set(fields)))


def test_docs03_states_the_relation_the_right_way_round():
    s = text("docs/03-system-architecture.md")
    assert "是 RunState 的子集" not in s
    assert "是 RunState 的持久化形式" in s and "欄位以 `run.schema.json` 為準" in s
    assert "**RunState 不得有 run 紀錄以外、又會影響續跑的欄位**" in s
