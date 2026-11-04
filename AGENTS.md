# AGENTS.md

本檔是本 repo 給 AI 代理（agent）的唯一規則來源（single source of truth）。
`CLAUDE.md` 只以 `@AGENTS.md` 引用本檔，請勿在 `CLAUDE.md` 另寫規則。

## Language

- 一律以正體中文、臺灣慣用語回覆。
- 專有名詞以中／英雙語呈現，例如：唯一來源（single source of truth）。
- 只有在必須使用英文時才用英文：指令、程式碼、檔名與路徑、API 名稱、
  錯誤訊息原文、引用的英文原文等。

## Output Locations

- `$improve-codebase-architecture`（或同類架構分析）產生的架構報告，一律存放在
  repo 根目錄的 `scratch/`，不要放在系統暫存目錄（`/tmp`、`%TEMP%`），因為關機後會被清除。
- `scratch/` 已列入 `.gitignore`，內容不進版控。

## Interactive Next-Step Workflow

After completing each user-requested task:

1. Summarize completed work in Traditional Chinese (Taiwan).
2. Report actual verification results and any unverified assumptions.
3. Identify remaining risks, errors, and incomplete work.
4. Recommend 3 to 5 prioritized next steps.
5. Provide numbered options using this format:

   1. [Recommended] Highest-priority action
   2. Alternative improvement
   3. Run verification or tests
   4. Perform security review
   5. Update documentation
   0. Finish without further action

6. Include the expected outcome for each option.
7. Include executable commands where relevant.
8. Wait for the user to select a number.
9. Do not execute suggested follow-up actions automatically.
10. Require explicit approval for destructive, privileged,
    security-sensitive, or irreversible operations.

Security requirements:
- Prefer read-only verification before modifications.
- Do not claim a test passed unless it was executed.
- Do not automatically push, merge, deploy, or delete.
- Distinguish confirmed findings from assumptions.
