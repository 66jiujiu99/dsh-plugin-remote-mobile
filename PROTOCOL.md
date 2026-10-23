# remote-mobile 对外契约 v1（Host ⇄ 手机页面 ⇄ PC 面板）

> 本文件是 `dsh-plugin-remote-mobile` 的**唯一接口契约**。Host 半边、`/m` 前端、PC 面板三方都按它实现；
> 改字段必须三处一起改并升 `v`。设计方案见 `../mobile-sync/PLAN.md`（§3.3 / §3.4 / §3.6 是 /m 的实现依据）。

## 0. 物理形态

- 插件包：`C:\Data\deepseek\remote-mobile`，包名 `dsh-plugin-remote-mobile`，entry id `remote-mobile`。
- 监听器：插件自己起 `http.Server`（**不用** `ctx.webServer` 的 loopback 栅栏），`enabled=true` 时 `listen(bindAddress, port)`；
  `enabled=false`（默认）时**不绑任何非环回地址**。
- 上游：`ctx.webServer.getOrigin()` → `http://127.0.0.1:<port>`，所有请求**改写 Host/Origin 为上游 authority** 后转发。
- 上游鉴权：启动时 `ctx.connection.authenticatedUrl()` → `GET /?token=` → 拿 `Set-Cookie`；之后每个转发请求带该 cookie。
  cookie 名 = `dsh-auth-` + base64url(sha256(upstreamAuthority))，值来自上游；401 时自动重交换一次再重试。

## 1. 手机侧端点（只暴露这些）

| 方法 | 路径 | 鉴权 | 说明 |
|---|---|---|---|
| GET | `/m` `/m/` | 设备 cookie（无则 302 `/m/pair`） | 页面壳 `web/m.html` |
| GET | `/m/<file>` | 无（静态资源） | `m.js` `m.css` `manifest.webmanifest` `sw.js` `icon*` |
| GET | `/m/ping` | **无** | `{ok, v, secureContext, upstreamOk, paired}` —— 用于自检与「未开启」说明页 |
| GET | `/m/pair` | 无 | 配对页（输入 6 位码 / `?code=` 自动提交） |
| POST | `/m/pair` | 无 | `{code, name?}`：**表单提交 → `303 /m` + `Set-Cookie`**；**JSON 提交（`m.js` 的 fetch）→ `200` + `{ok:true, device, location:'/m'}` + `Set-Cookie`**。失败见 §5 |
| GET | `/m/state` | 设备 cookie | `{device:{id,name,readonly}, session:{…}, approvals:{pending}}` |
| POST | `/m/api/<endpoint>` | 设备 cookie | **unary 代理**：body `{args}` → 转发 `POST /api/<endpoint>`，响应体原样返回 |
| GET | `/m/approvals?since&wait` | 设备 cookie | 长轮询，见 §3 |
| POST | `/m/approvals/<id>` | 设备 cookie | `{decision}`，见 §3 |
| POST | `/m/api/upload` | 设备 cookie | `multipart` 或 `{name,type,dataBase64}` → `{receiptId, name, size}` |
| GET | `/m/api/file?path=` | 设备 cookie | 下载/看图，带 `Content-Disposition` |
| WS | `/api/remote.mux` | 设备 cookie | **裸透传**到上游同名路径（帧原样，不改内容，只在 `$events` 首帧脱敏） |

- **路径白名单**：除以上之外一律 404（不转发 `/`、`/assets`、`/plugins/*`）。
- **Host/Origin 自检**：请求头里的 `Host` 必须是本监听器的 `LAN-IP:port` 或 `hostname:port`，否则 **400**；
  `Origin`（若有）必须与 `Host` 同 authority，否则 **403**。
- **来源网段**：默认只接受 RFC1918 / 链路本地 / loopback 的对端地址，其他 **403**（`allowedNetworks` 可覆盖）。
- **`/m/pair` 失败响应**：JSON 分支回 `{ok:false,error:{code,message}}`（HTTP 4xx）；**表单分支回 HTML 错误页**（带返回配对页链接，无 `error.code`，因为浏览器表单不会解析 JSON）。两条分支的判定规则一致。

## 2. PC 面板 RPC（走 `ctx.webServer`，只给本机 SPA 用）

`POST /plugin/remote-mobile/rpc`，body `{op, payload?}`，先 `ctx.connection.requestRejection(req)` 拒绝外部来源。

| op | payload | 返回 |
|---|---|---|
| `status` | — | `{enabled, port, urls:[], lanIps:[], upstreamOk, cookieOk, devices:[], pendingApprovals, killSwitch}` |
| `set.enabled` | `{enabled}` | `{enabled, port, urls}` |
| `pair.create` | `{ttlSec?}` | `{code, expiresAt, urls:[], ttlSec}`（同一时刻只有效一个码；`ttlSec` 10–900 覆盖本次码，缺省用配置 `pairCodeTtlSec`） |
| `pair.cancel` | — | `{ok}` |
| `devices.list` | — | `{devices:[{id,name,lastSeenAt,createdAt,readonly,online,ua}]}` |
| `devices.rename` | `{id,name}` | `{ok}` |
| `devices.revoke` | `{id}` | `{ok, revokedSockets}` |
| `devices.readonly` | `{id,readonly}` | `{ok}` |
| `devices.revokeAll` | — | `{ok, revoked}`（安全事件用；**`kill` 不再顺带撤销设备**） |
| `kill` | — | `{ok, closed}`：关监听器 + 断开全部 socket + 清空待裁决审批；**不动设备表**；`enabled` 保持用户意图、`killSwitch=true`，再开需 `set.enabled true`（急停要可快速恢复，撤销设备是独立动作） |
| `audit.head` | `{n?}` | `{lines:[…]}`：取**尾部**最近 n 行（旧→新） |
| `selftest` | — | `{upstream, cookieOk, upstreamOk, ms}` |

响应统一 `{ok:true, data}` / `{ok:false, error:{code,message}}`；HTTP 200（除非鉴权失败 401/403）。

**设备上限**：最多 32 台已配对设备；超出时 `POST /m/pair` 回 `403 rm/forbidden`。**已过期**的设备不占名额（可被新配对顶替）。

## 3. 审批（手机优先）

- Host 在 `approval/request` 上挂 `prepend` 监听器：
  - 闸门 1：没有在线设备（45s 内有请求）→ **不拦截**，同步 `return next()`；
  - 闸门 2：在线设备全都 `readonly` → 不拦截；
  - 否则入队、`await` 手机裁决，**最多 `askTimeoutMs`（默认 12000）**，超时 `return next()` 交还 PC。
- 手机长轮询 `GET /m/approvals?since=<seq>&wait=20000` → `{items:[{id, seq, kind, title, detail, choices:[{id,label,style}], createdAt, deadline}], nextSeq}`；
  有变更立即返回，否则挂起到 `wait` 或 25s 上限。
- 手机裁决 `POST /m/approvals/<id>` `{decision:"approve"|"reject"|"<choiceId>"}` → `{ok, settled:true}`；重复裁决 409。
- **只读设备**：`GET /m/approvals` 与 `POST /m/approvals/<id>` 一律 **403**（连卡片都不下发），`/m/state.approvals` 恒为 `{pending:0}`。
- `approvalRouting:'pc-first'` 时手机只看 `{items:[{kind:'info', title:'PC 正在等待确认'}]}`，不可裁决。

## 4. 只读策略（`policy.js`）

- 永久黑名单（任何设备都拒，包括读写）：`terminal/*`、`credentials/*`、`plugin/*`、`plugin-manager/*`、`remote-mobile` 自身管理 RPC、`/m/api/*` 之外的内部端点。
- 只读设备允许的端点白名单：`session/list`、`session/page`、`session/projections`、`session/modelCatalog`、
  `workspace/list`、`workspace/readFile`(只读文件)、`$events`、`session/follow`、`session/control`(仅 follow 语义)。
- 只读设备禁止：`session/prompt`、`session/cancel`、`session/attachment`、上传、审批裁决、任何 `POST /m/api/*` 写操作。

## 5. 错误码

`rm/unauthorized` `rm/forbidden` `rm/not-found` `rm/pair-invalid` `rm/pair-expired` `rm/pair-used`
`rm/pair-locked`（连续错 5 次）`rm/readonly` `rm/upstream` `rm/disabled` `rm/bad-request` `rm/too-large`
`rm/approval-gone` `rm/stream-not-allowed`（把 unary 端点当流开，**本地拒绝、不打上游**）`rm/internal`

手机侧统一渲染：`{ok:false, error:{code, message}}`，HTTP 4xx/5xx 对应。

## 6. `/m` 页面与主机通道形状（摘要，细节看 PLAN §3.3）

- 流式：`WS /api/remote.mux`，文本帧 JSON：
  上行 `{type:'open', streamId, endpoint, payload:{args}}`、`{type:'cancel', streamId}`、`{type:'item', streamId, value}`；
  下行 `{type:'item', streamId, value}`、`{type:'end', streamId}`、`{type:'error', streamId, error:{code,message}}`。
- **stream 端点**：`session/follow` `session/control` `workspace/follow` `$events`；**其余走 unary** `POST /m/api/<endpoint>`。
- 首帧脱敏：`$events` 的 `item.value.type==='ready'` 时删除 `value.host`（或置 `{home:'~'}`）。
- 断线重连：指数退避（500→10s），重连后 `session/page` 补拉缺口，按 `seq` 去重。
- PWA：`sw.js` 只在 `isSecureContext` 时注册（本期 LAN http 下不会执行，代码要写对）。
