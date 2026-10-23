# 探针脚本（真实环境验证）

这些脚本**连真实 Cloudflare**，不是单元测试。单元测试用假 cloudflared 保证快；
这些用来证明"在真实世界里也能跑通"。

先准备二进制：把 `cloudflared.exe` 放到上一层（插件根）的 `tools/` 目录。

| 脚本 | 验证什么 | 耗时 |
|---|---|---|
| `tunnel-e2e.mjs` | 起真隧道 → 抓域名 → 从公网访问本地服务 | ~40s |
| `full-chain.mjs` | **完整产品链路**：公网 → listener → Host 栅栏 → 鉴权 → 前缀剥离 → 上游 | ~60s |
| `tunnel-ownership.mjs` | 强杀父进程后不留孤儿 cloudflared | ~30s |

```bash
cd <插件目录>
ELECTRON_RUN_AS_NODE=1 "C:\Data\APP\dsh\DeepSeek Harness.exe" _probe/tunnel-e2e.mjs
ELECTRON_RUN_AS_NODE=1 "C:\Data\APP\dsh\DeepSeek Harness.exe" _probe/full-chain.mjs
ELECTRON_RUN_AS_NODE=1 "C:\Data\APP\dsh\DeepSeek Harness.exe" _probe/tunnel-ownership.mjs
```

`idle-timeout.mjs` 是空闲超时的测试（用假 exe，不联网，可当普通测试跑）：
每次要 12-14 秒，所以刻意没放进 `test/`，避免拖慢常规测试。
