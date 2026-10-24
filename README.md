# dsh-plugin-remote-mobile · 手机同步

把 DSH 桌面版的**完整 Web UI** 搬到手机上：手机浏览器打开 `http://<LAN-IP>:17890/m`，
看到的就是 PC 上那个界面——工作区分组、会话、插件设置、排队提示，全都在。

**所有操作都在 PC 上执行**：手机只是一个远端的遥控器和显示器，模型、工具、文件系统、
终端，全部跑在你那台电脑上。

- **对外契约**：[`PROTOCOL.md`](./PROTOCOL.md)
- **零第三方依赖**：只用 `node:` 内置模块（`http`/`net`/`crypto`/`fs`/`os`/`stream`），ESM，无构建。

---

## 1. 它到底是什么（先看这一节）

```
手机 ──http://<LAN-IP>:17890/m/*──▶ 插件监听器（0.0.0.0:17890）
      ──WS /m/api/remote.mux────▶
                                        │ ① Host/Origin 栅栏（挡 DNS rebinding）
                                        │ ② 设备 cookie 校验（配对过才放行）
                                        │ ③ 剥前缀 /m → /
                                        │ ④ 注入上游 cookie、抹掉手机凭据
                                        ▼
                              DSH 自己的 Web 端口（127.0.0.1:<随机>）
```

**它不是"重新实现的移动版"**，而是一层反向代理：把 `localhost:<port>` 上的网站，
挂到 `0.0.0.0:17890/m/` 上，并加了一道配对门。

这样做的直接好处：DSH 加什么新功能，手机上就有——不用维护第二套界面。

### ⚠️ 重要：反代只搬「界面」，不搬「能力」

这是使用前必须理解的一条。

手机浏览器里跑的是**页面 JavaScript 本身**，而不是 PC 的 Electron 渲染进程。
所以任何依赖 **Electron / 本机 Node** 的功能，到手机上会显示正常但**点了会失败**：

| 功能 | 手机上 | 原因 |
|---|---|---|
| 会话、消息、工作区分组 | ✅ 可用 | 纯网络请求，走反代 |
| 发消息、选模型、切换工作区 | ✅ 可用 | 纯网络请求 |
| 插件设置、账号、审批 | ✅ 可用 | 纯网络请求 |
| 文件浏览 / 读工作区文件 | ✅ 可用 | 走 RPC 回 PC 读 |
| **Agent 浏览器（webview）** | ❌ **不可用** | 需要 Electron 主进程的 `webview` lease API |
| **终端** | ⚠️ 取决于实现 | 若走 Host RPC 则可用；若依赖本地 pty 则不可用 |
| **选目录 / 打开文件对话框** | ❌ 弹在 PC 上 | 原生对话框由 PC 的 Electron 弹出 |

看到「受控浏览器只在 DSH 桌面版可用」这句提示时，就是这个原因——不是权限问题，
是手机浏览器**没有那个 API**。

> 想彻底解决「手机上操控网页」，需要另做**云浏览器**（PC 上跑有头浏览器、截图回传、
> 点击转 CDP 输入）。那是另一个量级的工程，本插件不做。

---

## 2. 安装

```bash
# 在 DSH 里（需要 danger-full-access 或逐次批准）
plugin_manager install_bundle target=C:\path\to\dsh-plugin-remote-mobile
```

**安装 ≠ 开启**。装好之后还要在配置里设 `enabled: true`（或在设置页的「手机同步」里打开开关）。

> **配置陷阱**：插件重载（`set_plugin enabled=false/true`）会用运行时状态**重写**
> `~/.dsh/profiles/<profile>/cordis.yml`。所以手工改完配置后必须**重启 DSH**，
> 不要在中间重载插件，否则配置会被覆盖回旧值。

示例配置（`cordis.yml` 中本插件那一行的 `config`）：

```yaml
enabled: true
bindAddress: 0.0.0.0
port: 17890
allowedNetworks: []      # 空 = 只允许私有网段（192.168/10/172.16-31）+ 链路本地 + loopback
deviceOnlineWindowMs: 90000
deviceOfflineTtlMs: 43200000
```

---

## 3. 第一次用

1. 手机连上和 PC **同一个 WiFi / 热点**（PC 开热点就是 `192.168.137.1`）
2. 手机打开 `http://<PC-IP>:17890/m`
3. 会被跳到配对页，输入 PC 面板上显示的**配对码**（默认 60 秒有效、5 次尝试）
4. 配对成功后进入完整界面；cookie 有效期 `cookieMaxAgeDays`（默认 180 天）

找不到 IP？在 PC 上跑：

```bash
netstat -ano | findstr :17890
```

或直接看插件面板，它会列出所有可用 URL。

---

## 4. 端点

| 路径 | 谁处理 | 说明 |
|---|---|---|
| `GET /m/ping` | 插件 | 健康检查（无鉴权），配对页靠它判断 PC 是否在线 |
| `GET /m/pair` | 插件 | 配对页 |
| `POST /m/pair` | 插件 | 配对提交（JSON 或 urlencoded） |
| `/m/**`（其余） | **反代到上游** | 缺尾斜杠会 302 到 `/m/`，否则相对路径会跳出前缀 |
| `WS /m/api/remote.mux` | **反代到上游** | 会话流；缺它页面只剩静态外壳 |

**尾斜杠是功能要求**：上游 `index.html` 注入 `<base href="./">`，资源全是相对路径。
地址栏停在 `/m`（无斜杠）时 `./assets/x.js` 会解析成 `/assets/x.js`（跳出前缀）→ 整站 404。

### 面板 RPC（PC 侧，需要连接凭据）

| op | 作用 |
|---|---|
| `status` / `set.enabled` | 状态 / 开关监听 |
| `pair.create` / `pair.cancel` | 生成 / 取消配对码 |
| `devices.*` | 列设备、改名、撤销、只读 |
| **`tunnel.start` / `tunnel.stop` / `tunnel.status`** | **开关公网隧道、查状态** |
| `kill` / `audit.head` / `selftest` | 急停 / 审计 / 自检 |

---

## 4.1 公网隧道（可选，默认关闭）

不开隧道时，手机必须和 PC 在**同一个 WiFi / 热点**。开了隧道，手机可以用任意网络访问。
用的是 **Cloudflare Quick Tunnel**：匿名、免账号、免服务器、免公网 IP。

### 怎么装 cloudflared

插件本身**不带** cloudflared（55MB，不适合进仓库）。三种方式任选：

1. **放便携版（最简单）**：把 `cloudflared.exe` 丢进本插件的 `tools/` 目录，插件会自动找到。
2. **指定路径**：配置 `tunnel.binaryPath: "C:/path/to/cloudflared.exe"`。
3. **装进 PATH**：`winget install Cloudflare.cloudflared`，插件会自动从 PATH 找。

下载地址（官方 Release，建议核对 SHA-256）：

```
https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-amd64.exe
```

### 怎么开

1. 先把「手机同步」开起来（隧道要指向监听端口）
2. 设置页 →「手机同步」→「公网隧道」→ **开启隧道**
3. 等 10-60 秒（Cloudflare 分配域名），面板会显示公网地址
4. 用手机打开那个地址 → 配对 → 进入

**这个开关是手动的，刻意不跟 `enabled` 联动**：开了监听不等于要开公网。

### 四条行为约定

| 行为 | 说明 |
|---|---|
| **域名每次都变** | Quick Tunnel 不做持久域名。重连或重启后就是新地址 |
| **空闲自动断开** | `tunnel.idleTimeoutSec`（默认 1800 秒）内没有请求就自动关。**设 0 = 永不主动关** |
| **断开后自动重连** | `tunnel.reconnect`（默认开）。指数退避重试，`reconnectBudgetSec` 内一直试 |
| **父死子亡** | DSH 崩溃或被任务管理器结束，隧道会跟着消失（靠管道所有权，不依赖清理代码） |

### 「链接多久失效」怎么配

Quick Tunnel 的域名由 Cloudflare 分配，**cloudflared 进程一退出域名就作废**。
所以"有效期"是两层，**都能配**：

```yaml
tunnel:
  # ① 我们主动关：多久没请求就关。0 = 永不主动关。
  idleTimeoutSec: 0
  # ② 意外断开后自动重连（会换新域名）。不想要就设 false。
  reconnect: true
  reconnectBudgetSec: 86400   # 重连额度：一天内一直尝试
  reconnectMaxDelaySec: 60    # 退避上限
```

**想尽量不失效**：`idleTimeoutSec: 0` + `reconnect: true` + 大 `reconnectBudgetSec`。

> 面板上也能改：设置 → 手机同步 →「公网隧道」→ **空闲断开**下拉框。
> 改完**立即生效**，不用重启；选「永不主动关」等于 `idleTimeoutSec: 0`。
> 面板改的是运行时值，重启后会回到 `cordis.patch.yml` 里的配置。

**必须知道的硬限制**：DSH 一关（或被强杀），域名必然失效。这是 Quick Tunnel
的固有代价，不是本插件的限制——想拿固定域名得用 Cloudflare named tunnel
（需要账号与自有域名），本插件不做。

### 配置项

```yaml
tunnel:
  provider: quick              # none | quick（frpc 仍是预留形状，未实现）
  binaryPath: ''               # 空 = 自动找 PATH 与 tools/
  idleTimeoutSec: 1800         # 空闲多久自动关（0 = 永不主动关）
  reconnect: true              # 意外断开后自动重连（换新域名）
  reconnectBudgetSec: 3600     # 重连总时长上限
  reconnectMaxDelaySec: 60     # 指数退避上限
  startTimeoutSec: 90          # 等域名的最长时间
```

---

## 5. 安全模型（决定要不要开之前读）

**核心边界**：手机只拿到一个**设备 cookie**（`dshm_d`）；DSH 自己的 `dsh-auth-*`
凭据只存在插件内存里，**永远不下发给手机**。

| 防线 | 做法 |
|---|---|
| 来源网段 | `allowedNetworks` 为空时只放行私有网段 + 链路本地 + loopback |
| DNS rebinding | `Host` 必须是本机真实监听地址之一（LAN IP / hostname / localhost） |
| 跨站请求 | `Origin` 必须与 `Host` 同 authority；`Sec-Fetch-Site: cross-site` 一律拒 |
| 凭据隔离 | 上行抹掉手机的 `Cookie`/`Authorization`/`Sec-Fetch-*`/`X-Forwarded-*`；下行抹掉 `Set-Cookie`/HSTS |
| 永久黑名单 | `terminal/`、`credentials/`、`plugin/`、`plugin-manager/`、`settings/` —— 任何设备任何路由都拒 |
| 只读设备 | fail-closed 白名单：只允许读取类端点，未知端点直接 403 |
| 撤权 | 单设备撤销立即断开在途连接；`kill` 急停但保留设备表，可恢复 |

**必须知道的残余风险**：

- 插件跑在**宿主进程内、工作区沙箱之外**，和你的用户权限相同。
- 开了监听就等于**同一网络里的人可以探测到这个端口**（虽然有配对门）。
  在公共 WiFi 下建议关掉，或把 `allowedNetworks` 收紧到你家网段。
- **开了隧道 = 全球可达**。这时候「同一 WiFi」这道天然边界没有了，
  只剩配对码。所以：配对码是 **8 位**（31 字符表，≈39.6 bit，已排除 0/O/1/I/L 等易混字符），
  并且**按 IP 限流**（10 次/分钟）+ 单码 5 次错误即锁 60 秒。
  在公网暴露期间请勿把配对码发到会被转发的渠道。
- 隧道用的是**匿名 Quick Tunnel**，流量经 Cloudflare 边缘。不要通过它传你不想让第三方看见的内容。
- Cloudflare 不保证 Quick Tunnel 的可用性；本插件会在空闲超时后主动关闭，减少暴露窗口。

---

## 6. 已知限制

1. **隧道只有 Quick Tunnel**：域名每次重启都变（不做持久域名，那需要 Cloudflare 账号与 named tunnel）。
   `frpc` 仅在配置里预留形状，未实现。
2. **手机上的「能力」降级**：见 §1 的表格。
3. **布局不专门适配手机**：DSH Web UI 是给宽屏设计的，手机上侧栏会挤。
   目前"能用"，但没有专门的移动端 CSS。
4. **`webview` 类插件在手机上不可用**：架构限制，不是配置问题。

---

## 7. 实测状态（2026-10-23 / 24）

| 项 | 状态 | 证据 |
|---|---|---|
| 整站反代 | ✅ | 手机打开 `/m/` 看到完整 UI，会话内容正常渲染 |
| 工作区分组 | ✅ | 补齐 `remoteAccess/follow` 流后，会话从「未分组」回到正确归属 |
| 账号/登录态显示 | ✅ | 补齐 `account/watch` 流后恢复正常 |
| 设备配对 | ✅ | 真机 Android，配对码 → 设备 cookie → 免密进入 |
| WebSocket | ✅ | `/m/api/remote.mux` 剥前缀转发，会话流实时更新 |
| **公网隧道** | ✅ | 真 cloudflared 起隧道 → 公网 302 到配对页 → 配对 → 200 且前缀正确剥离 |
| **Host 栅栏放行** | ✅ | 隧道域名可过；无关域名仍 400（开隧道不放宽边界） |
| **父死子亡** | ✅ | 强杀父进程后 8 秒内 cloudflared 自行消失，零孤儿 |
| **空闲超时** | ✅ | 到点自动关；持续 touch 可保活 |
| 单元 + 集成测试 | ✅ | **92 / 92 通过** |
| Agent 浏览器 | ❌ | 预期失败：需要 Electron 主进程 API |

验证方式：

```bash
# 全部单测 + 集成测试（用桌面自带的 Electron Node，PATH 里通常没有 node）
ELECTRON_RUN_AS_NODE=1 "C:\Data\APP\dsh\DeepSeek Harness.exe" --test test/*.test.mjs

# 真实隧道端到端（会真的连 Cloudflare，需要 tools/cloudflared.exe）
ELECTRON_RUN_AS_NODE=1 "C:\Data\APP\dsh\DeepSeek Harness.exe" _probe/tunnel-e2e.mjs
ELECTRON_RUN_AS_NODE=1 "C:\Data\APP\dsh\DeepSeek Harness.exe" _probe/full-chain.mjs
ELECTRON_RUN_AS_NODE=1 "C:\Data\APP\dsh\DeepSeek Harness.exe" _probe/tunnel-ownership.mjs
```

---

## 8. 排障

| 现象 | 原因 / 处理 |
|---|---|
| 连不上、端口没监听 | `enabled` 还是 `false`。改了配置要**重启 DSH**，不要用插件重载 |
| 页面白板但 UI 在 | 某个 WebSocket 流被拒。看 `~/.dsh/remote-mobile/debug.jsonl` 里的 `ws-frame-denied` |
| 会话全在「未分组」 | 同上，通常是 `remoteAccess/follow` 被拦 |
| 资源 404 | 地址少了尾斜杠，确认是 `/m/` 不是 `/m` |
| 被弹回配对页 | 设备 cookie 过期或被撤销，重新配对 |
| 点「Agent 浏览器」报错 | 预期行为，见 §1 的能力表 |
| **开隧道报 `rm/tunnel-no-binary`** | 找不到 cloudflared。放进 `tools/`，或配 `tunnel.binaryPath`，或装进 PATH |
| **开隧道报 `rm/tunnel-no-listener`** | 手机同步没开。先开监听再开隧道 |
| **开隧道报 `rm/tunnel-timeout`** | 90 秒内没拿到域名。多半是网络到 Cloudflare 不通，或被安全软件拦 |
| **公网打开是 400** | 隧道域名没进 Host 白名单。确认隧道状态是 `running`（面板上显示公网地址） |
| **公网打开超时** | 边缘还没铺开，等 30-60 秒重试；或隧道已因空闲超时关闭 |

日志位置：`~/.dsh/remote-mobile/`
- `audit.jsonl` —— 谁在什么时候访问了什么（只记元数据）；隧道开关记为 `kind: "tunnel"`
- `debug.jsonl` —— 路由、WS 帧、cookie 交换、cloudflared 输出等细节
- `devices.json` —— 设备表（只有哈希，没有明文 secret）

---

## 9. 开发

```bash
# 语法检查
ELECTRON_RUN_AS_NODE=1 "C:\Data\APP\dsh\DeepSeek Harness.exe" --check lib/net/listener.js

# 单元测试
ELECTRON_RUN_AS_NODE=1 "C:\Data\APP\dsh\DeepSeek Harness.exe" --test test/*.test.mjs
```

改 Host 代码之后：**重启 DSH**（不要只重载插件，见 §2 的配置陷阱）。

## License

MIT
