# 自架模型啟動範例（Z4）

> 這些是**伺服器端**參數，不屬於用戶端的 `models.yaml`。版本與參數以各模型卡為準，實作時重新確認。

## Nemotron 3 Nano（vLLM）

工具呼叫需要在伺服器端啟用自動工具選擇，並使用 `qwen3_coder` parser（E:providers-14）：

```bash
vllm serve nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B-BF16 \
  --served-model-name nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B-BF16 \
  --enable-auto-tool-choice \
  --tool-call-parser qwen3_coder \
  --max-model-len 262144
```

- 硬體：單張 A100／H100 級 GPU（E:providers-13）。
- context：Hugging Face 設定因 VRAM 預設為 256K（E:providers-05）。
- 結構化輸出：使用 `response_format` json_schema，或 vLLM 的 `structured_outputs`；`guided_*` 已在 vLLM v0.12.0 移除（E:providers-18）。
- 用戶端：LiteLLM `hosted_vllm/<served-model-name>`，並設定 `api_base`；LiteLLM 會移除 tools 的 `strict`／`additionalProperties`（E:providers-22），所以用戶端一律以 Pydantic 再驗證。

## Nemotron（NIM 容器）

- NIM 2.x 啟用 Nemotron 工具呼叫的 `NIM_PASSTHROUGH_ARGS` 字串，目前只在 Nemotron 3.5 Lightning 的文件中查到（E:providers-15，部分查證）：
  `--reasoning-parser nemotron_v3 --enable-auto-tool-choice --tool-call-parser qwen3_coder`
- NIM 不會自己連 MCP server；由用戶端把工具轉成 OpenAI tools 格式（E:providers-15）。
- 授權：免費使用限研究、開發、測試且 ≤16 GPU；正式用途需 NVIDIA AI Enterprise，**需法務確認**（E:providers-12）。

## gpt-oss-120b（vLLM，選用）

- Apache-2.0，支援 function calling 與 Structured Outputs（E:providers-37）。
- 在 C 級資料不能送往 OpenAI API 時，用來補 `family: openai` 的自架選項。
