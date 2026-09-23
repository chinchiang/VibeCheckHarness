# 自架模型啟動範例（Z4）

> 這些是**伺服器端**參數，不屬於用戶端的 `models.yaml`。版本與參數以各模型卡為準，實作時重新確認。

## Nemotron 3 Nano（vLLM）

工具呼叫需要在伺服器端啟用自動工具選擇，並使用 `qwen3_coder` parser（[V] E:providers-14）。`--reasoning-parser nemotron_v3` 出現在 Super 卡與 NIM 的設定中，Nano 是否相同請依模型卡確認：

```bash
vllm serve nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B-BF16 \
  --served-model-name nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B-BF16 \
  --enable-auto-tool-choice \
  --tool-call-parser qwen3_coder \
  --reasoning-parser nemotron_v3 \
  --max-model-len 262144
```

- SGLang：只用 `--tool-call-parser qwen3_coder`（沒有 `--enable-auto-tool-choice`），reasoning parser 為 `nemotron_3`（[V] E:providers-14）。
- 硬體：單張 A100／H100 級 GPU（[V] E:providers-13）。
- context：Hugging Face 設定因 VRAM 預設為 256K（[V] E:providers-05）。
- 結構化輸出：使用 `response_format` json_schema，或 vLLM 的 `structured_outputs`；`guided_*` 已在 vLLM v0.12.0 移除（[P] E:providers-18）。
- 用戶端：LiteLLM `hosted_vllm/<served-model-name>`，並設定 `api_base`；LiteLLM 會移除 tools 的 `strict`／`additionalProperties`（[C] E:providers-22），所以用戶端一律以 Pydantic 再驗證。

## Nemotron（NIM 容器）

- NIM 2.x 啟用 Nemotron 工具呼叫的 `NIM_PASSTHROUGH_ARGS` 字串，目前只在 Nemotron 3.5 Lightning 的文件中查到（[P] E:providers-15）：
  `--reasoning-parser nemotron_v3 --enable-auto-tool-choice --tool-call-parser qwen3_coder`
- NIM 不會自己連 MCP server；由用戶端把工具轉成 OpenAI tools 格式（[P] E:providers-15，此句已逐字確認）。
- 授權：免費使用限研究、開發、測試且 ≤16 GPU；正式用途需 NVIDIA AI Enterprise，**需法務確認**（[P] E:providers-12）。

## gpt-oss-120b（vLLM，選用）

- Apache-2.0（另有 usage policy），支援 function calling 與 Structured Outputs；MXFP4 可放入單張 80GB GPU（[V] E:providers-37）。自架時結構化輸出取決於推論引擎的 constrained decoding。
- 在 C 級資料不能送往 OpenAI API 時，用來補 `family: openai` 的自架選項。
