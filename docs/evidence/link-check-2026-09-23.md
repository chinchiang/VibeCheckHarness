# 連結檢查紀錄（2026-09-23）

> 以 curl 檢查 README、docs 與證據帳本中的所有外部 URL（範例用的 example.com／example.net 與 Z4 內部位址除外）。依計畫，**403 等錯誤只記錄、不刪除**：研究時這些來源多半已由 WebFetch 讀取過，而本環境的 proxy 會擋下 curl 對 github.com 的直接存取。

## 統計

| HTTP 狀態 | 數量 |
|---|---|
| 206 | 262 |
| 200 | 262 |
| 403 | 136 |
| 429 | 2 |
| 202 | 2 |
| 404 | 2 |
| 400 | 1 |
| 503 | 1 |

說明：206＝伺服器接受範圍請求（正常）；403 以 github.com 為主（環境限制），其餘多為網站擋自動化請求（ACM、openai.com、npm 等），不代表連結失效；429＝速率限制；逾時的 URL 已重試並記錄重試結果。

## 非 2xx 的 URL（github.com 的 403 除外）

| 狀態 | URL | 備註 |
|---|---|---|
| 400 | <https://github.com/OWASP/wstg/> |  |
| 403 | <https://dl.acm.org/doi/10.1007/s10515-024-00478-1> |  |
| 403 | <https://dl.acm.org/doi/10.1145/3663529.3663839> |  |
| 403 | <https://dl.acm.org/doi/10.1145/3729398> |  |
| 403 | <https://dl.acm.org/doi/10.1145/3733812.3765533> |  |
| 403 | <https://dl.acm.org/doi/full/10.1145/3597205> |  |
| 403 | <https://dlnext.acm.org/doi/10.1145/3533767.3534401> |  |
| 403 | <https://medium.com/@romerorico.hugo/langgraph-1-0-released-no-breaking-changes-all-the-hard-won-lessons-8939d500ca7c> |  |
| 403 | <https://onlinelibrary.wiley.com/doi/abs/10.1002/spe.2111> |  |
| 403 | <https://openai.com/index/codex-security-now-in-research-preview/> |  |
| 403 | <https://openai.com/index/introducing-aardvark/> |  |
| 403 | <https://openai.com/index/openai-to-acquire-promptfoo/> |  |
| 403 | <https://socket.dev/blog/opengrep-forks-semgrep> |  |
| 403 | <https://socket.dev/blog/slopsquatting-how-ai-hallucinations-are-fueling-a-new-class-of-supply-chain-attacks> |  |
| 403 | <https://visualstudiomagazine.com/articles/2026/04/06/microsoft-ships-production-ready-agent-framework-1-0-for-net-and-python.aspx> |  |
| 403 | <https://www.cnbc.com/2026/03/09/open-ai-cybersecurity-promptfoo-ai-agents.html> |  |
| 403 | <https://www.npmjs.com/package/@playwright/mcp> |  |
| 403 | <https://www.npmjs.com/package/playwright> |  |
| 403 | <https://www.researchgate.net/publication/254058560_Automated_Security_Test_Generation_with_Formal_Threat_Models> |  |
| 404 | <https://integrate.api.nvidia.com/v1> | API base URL，不是網頁；404 屬正常 |
| 404 | <https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References> | OWASP 網站改版；改用 GitHub v4.2 原始檔（S-06） |
| 429 | <https://api.semanticscholar.org/graph/v1/paper/arXiv:2211.03622?fields=title,venue,year,abstract> |  |
| 429 | <https://docs.vllm.ai/en/latest/features/structured_outputs.html> |  |
| 503 | <https://shostack.org/blog/threat-modeling-manifesto/> |  |

另有 118 個 github.com URL 回傳 403（環境限制，研究時已透過 WebFetch 讀取）。
