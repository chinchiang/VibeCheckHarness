# VibeCheck Harness

以多個模型家族交叉驗證 AI 安全測試發現，並把每一步的證據、關卡決定與裁決記錄成可簽章、可重驗的 bundle。

## 裁決（Verdict）

**叢集（cluster）**：
同一個疑似問題的回報被歸成的一組，是裁決的對象。
_Avoid_：群組、finding group

**裁決（verdict）**：
一個叢集的整條裁決版本鏈，代表系統對該疑似問題目前與過去的結論。
_Avoid_：判定、判決、decision

**裁決版本（verdict version）**：
裁決鏈上的一份紀錄，在某個階段（W3、G2、W4、B5）寫下，並取代它的前一版。
_Avoid_：裁決紀錄、verdict record、verdict revision

**最新裁決版本（head verdict version）**：
在某個 run 的裁決版本中，沒有被同一 run 的其他版本取代的那一版；「最新」永遠相對於某個 run，不是全域。
_Avoid_：最終裁決、current verdict

**裁決階段（adjudication phase）**：
寫下裁決版本的時間點，依序為 W3（初次裁決）、G2（套用關卡決定）、W4（重新裁決）、B5（黑箱後重新裁決）；各階段看得到的測試結果不同。
_Avoid_：round、stage

**推導欄位（derived field）**：
裁決版本上必須由 bundle 中其他證據重新算出、不能由寫入者自行宣告的值。
_Avoid_：計算欄位、自我宣告欄位、computed field

## 簽章（Signing）

**簽章政策（signing policy）**：
「哪一份紀錄由誰簽」的規則：gate record 由 approvers 簽（G0a/G0b 與 EXPIRED 不簽）、feedback 由 signed_by 再 co_signed_by 簽、報告撤回由 signers 依序簽、human 的 initiator_claim／run_resume／spot_check_result 事件由 actor 簽。checker 與寫入端共用 `vchlib.seal` 的同一份。
_Avoid_：簽章規則、signer rules

**重新封存（reseal）**：
修改 bundle 之後，用 TEST ONLY 金鑰重算推導值、重簽、重新串起稽核鏈，直到不再改變，讓 bundle 回到內部一致的狀態。只用於範例、variant 與測試，從不用於真正的核准。
_Avoid_：重簽、resign、re-sign
