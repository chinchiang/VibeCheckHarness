# 資料模型（JSON Schema 2020-12）

這裡的 schema 是**存檔與交換用**的完整版本。送給 LLM 的「輸出用 schema」由程式自動**降級**為跨廠商的最小公約數：去除數值與長度限制、`pattern`、`format`、`multipleOf`、`$ref`；所有物件設 `additionalProperties: false` 並把所有欄位列為 required；`minItems` 最大為 1。LLM 輸出取得後，再以這裡的完整 schema 驗證（見 [03 §8.3](../03-system-architecture.md#83-結構化輸出跨廠商最小公約數)）。

| Schema | 用途 | 範例 |
|---|---|---|
| [finding](finding.schema.json) | 發現項（含程式證據） | [finding.example.json](examples/finding.example.json) |
| [cluster](cluster.schema.json) | 叢集鍵、成員、家族 | [cluster.example.json](examples/cluster.example.json) |
| [verdict](verdict.schema.json) | 驗證票、缺票、裁決狀態 | [verdict.example.json](examples/verdict.example.json)、[verdict.executable.example.json](examples/verdict.executable.example.json) |
| [threat](threat.schema.json) | 威脅、分類版本、證據、簽核、對照表連結 | [threat.example.json](examples/threat.example.json) |
| [requirement](requirement.schema.json) | ASVS／AISVS 需求與 G1 安全不變量 | [asvs](examples/requirement.asvs.example.json)、[invariant](examples/requirement.invariant.example.json) |
| [testcase](testcase.schema.json) | 測試案例 | [IDOR](examples/testcase.idor.example.json)、[LLM](examples/testcase.llm.example.json) |
| [gate-record](gate-record.schema.json) | 人工關卡簽章紀錄 | [G3](examples/gate-record.g3.example.json)、[G5](examples/gate-record.g5.example.json) |
| [roe](roe.schema.json) | 交戰規則 | [../examples/roe.yaml](../examples/roe.yaml) |
| [commander-plan](commander-plan.schema.json) | 指揮官計畫 | [commander-plan.example.json](examples/commander-plan.example.json) |
| [model-registry](model-registry.schema.json) | 模型登錄 | [../examples/models.yaml](../examples/models.yaml) |
| [agent-registry](agent-registry.schema.json) | 代理登錄 | [../examples/agents.yaml](../examples/agents.yaml) |

## 驗證

```bash
python3 -m pip install jsonschema pyyaml
python3 tools/validate_schemas.py
```

驗證程式除了 schema 驗證，還檢查設計依賴的語意規則：
- 程式片段 hash 正確
- fallback 只限同家族
- 雲端 Nemotron（build.nvidia.com）只收 P 級資料、不用於正式用途
- C 級資料的 reviewer 至少涵蓋 2 個家族，而且每個家族都有來自其他家族與血統的 verifier
- G5 核准者與發起者不同
- 測試案例的計算等級不低於提議等級、目標都是 ROE 目標 ID、速率不超過 ROE
- ROE 有效期間順序正確
- 已接受的威脅沒有未審的 llm-suggested 對照連結
- 降級後的 LLM 輸出 schema 只使用共通子集

範例中的簽章、金鑰指紋、網域（example.com／example.net）都是示意值。
