/**
 * 局域网监听器：`http.Server` + 路由表 + Host/Origin 自检 + 反代 + WS 升级分发。
 *
 * 这是插件的「合规责任」所在（PLAN §3.1.1 的边界铁律）：
 *
 *   - 只暴露 `/m*` 与 `/api/remote.mux`；**绝不**转发 `/`、`/assets`、`/plugins`
 *     （那些是 PC 的 SPA），其余一律 404。
 *   - 每个请求先过三道门：来源网段（默认私有/链路本地）→ `Host` 必须是本机
 *     `LAN-IP:port` / `hostname:port` / `localhost:port`（挡 DNS rebinding）→
 *     `Origin`（若有）必须与 `Host` 同 authority。
 *   - 数据路径再要设备 cookie；手机 → 上游永远删 `Cookie`/`Authorization`/
 *     `Sec-Fetch-*`/`X-Forwarded-*`，永远注入插件内存里的上游 cookie。
 *   - 上游 → 手机永远删 `Set-Cookie`/`Strict-Transport-Security`。
 *
 * ## `/m` 的形态
 *
 *   `/m/*` 是**整站反代**到 DSH Web 端（见 `proxy-site.js`），手机拿到的是完整
 *   Web UI —— 工作区分组、插件设置、运行时排队提示等自动具备，上游加新功能
 *   手机端跟着走，不需要维护第二套界面。
 *
 *   鉴权不放松：仍然需要设备 cookie（先在 `/m/pair` 配对），未配对一律 302 到
 *   配对页。`/m/ping`（健康检查）与 `/m/pair`（配对）由插件自己应答。
 *
 * 超时：`requestTimeout=0`、`headersTimeout=0`，upgrade socket `setTimeout(0)`——
 * 否则 Node 默认的 300s 会把 `/api/remote.mux` 掐断。
 *
 * @module dsh-plugin-remote-mobile/listener
 */

import http from 'node:http'
import path from 'node:path'

import {
  MAX_APPROVAL_WAIT_MS,
  PORT_SCAN_SPAN,
  RmError,
  failureBody,
  statusForError,
} from '../config.js'

import { isUnderPrefix, proxySiteRequest } from './proxy-site.js'
import { decide } from '../policy/policy.js'
import {
  allowedAuthorities,
  buildUrls,
  isAllowedSource,
  isSameAuthorityOrigin,
  listLanAddresses,
  urlHost,
} from './lan.js'
import { createWorkspaceRoots } from './workspace-roots.js'
import { FILE_DENY_MESSAGES, checkFilePath } from '../policy/files.js'
import { proxyWebSocket } from './proxy-ws.js'
import { rewriteRequestHeaders, rewriteResponseHeaders } from './upstream.js'

/** 普通 JSON body 上限（保留给配对提交等自有端点）。 */
const JSON_BODY_LIMIT = 4 * 1024 * 1024

/** 配对/审批这类小 body 的上限。 */
const SMALL_BODY_LIMIT = 64 * 1024

/**
 * 整站反代允许的请求体上限。
 *
 * 走这条路径的基本都是 Web UI 的 JSON-RPC（几十 KB 量级）；
 * 真正的上传走上游自己的上传端点，也在 `/m/*` 下，所以留 32MB 兜住。
 */
const SITE_BODY_LIMIT = 32 * 1024 * 1024

/** `/m/api/upload` 的上限（手机拍照/PDF 都够）。 */
const UPLOAD_BODY_LIMIT = 32 * 1024 * 1024

/** 上游上传响应（JSON 回执）的上限。 */
const UPLOAD_RECEIPT_LIMIT = 256 * 1024

/** 本插件版本（`/m/ping` 的 `v` 字段）。 */
export const PLUGIN_VERSION = '0.1.0'

/** 设备 cookie 无效时 `/m` 统一跳这里。 */
const PAIR_PATH = '/m/pair'

/** 每个 JSON 响应默认带的头。 */
const NO_STORE = Object.freeze({
  'cache-control': 'no-store',
  'x-content-type-options': 'nosniff',
})

/** 内置兜底页：`web/**` 还没交付时也能完成 M2 自检。 */
const FALLBACK_HTML = {
  'm.html': `<!doctype html><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>DSH 手机端</title>
<body style="font:16px system-ui;background:#0b0d12;color:#e8eaef;padding:24px">
<h1>DSH 手机端</h1>
<p>页面壳 <code>web/m.html</code> 尚未安装（开发期兜底页）。</p>
<p>已连接。<a style="color:#7aa2ff" href="/m/ping">/m/ping</a> 可自检。</p>
</body>`,
  'pair.html': `<!doctype html><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>配对 · DSH 手机端</title>
<body style="font:16px system-ui;background:#0b0d12;color:#e8eaef;padding:24px">
<h1>配对</h1>
<p>输入 PC 面板上显示的 8 位配对码（数字与大写字母，不含 0/O/1/I/L）。</p>
<form method="post" action="/m/pair">
  <input name="code" inputmode="text" autocapitalize="characters" autocorrect="off" spellcheck="false"
         maxlength="8" autocomplete="one-time-code" placeholder="ABCD2345"
         style="font-size:24px;letter-spacing:6px;padding:8px;width:220px;text-transform:uppercase">
  <button style="font-size:18px;padding:8px 16px">配对</button>
</form>
</body>`,
}

/**
 * 是否是普通对象。
 * @param {unknown} value - 任意值。
 * @returns {boolean} 结论。
 */
function isRecord(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

/**
 * 写一个 JSON 响应。
 * @param {import('node:http').ServerResponse} res - 响应。
 * @param {number} status - 状态码。
 * @param {unknown} body - 内容。
 * @param {Record<string, string>} [extra] - 额外头。
 * @returns {void}
 */
function json(res, status, body, extra) {
  if (res.writableEnded || res.destroyed) return
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', ...NO_STORE, ...extra })
  res.end(JSON.stringify(body))
}

/**
 * 写一个纯文本响应（案发现场能直接看懂的那种）。
 * @param {import('node:http').ServerResponse} res - 响应。
 * @param {number} status - 状态码。
 * @param {string} text - 内容。
 * @param {Record<string, string>} [extra] - 额外头。
 * @returns {void}
 */
function text(res, status, textBody, extra) {
  if (res.writableEnded || res.destroyed) return
  res.writeHead(status, { 'content-type': 'text/plain; charset=utf-8', ...NO_STORE, ...extra })
  res.end(textBody)
}

/**
 * 读取原始 body，超限立即失败（不 collect 到内存之外）。
 * @param {import('node:http').IncomingMessage} req - 请求。
 * @param {number} limit - 上限。
 * @returns {Promise<Buffer>} body。
 */
function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    /** @type {Buffer[]} */
    const chunks = []
    let size = 0
    let settled = false
    /**
     * 结束读取。
     * @param {Error} error - 失败原因。
     * @returns {void}
     */
    function fail(error) {
      if (settled) return
      settled = true
      req.removeAllListeners('data')
      req.removeAllListeners('end')
      req.removeAllListeners('error')
      req.pause()
      reject(error)
    }
    req.on('data', (chunk) => {
      if (settled) return
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)
      size += buffer.length
      if (size > limit) {
        fail(new RmError('rm/too-large', `请求体超过 ${limit} 字节上限`))
        return
      }
      chunks.push(buffer)
    })
    req.on('end', () => {
      if (settled) return
      settled = true
      resolve(Buffer.concat(chunks))
    })
    req.on('error', (error) => fail(new RmError('rm/bad-request', `读取请求体失败：${String(error?.message ?? error)}`)))
    req.on('aborted', () => fail(new RmError('rm/bad-request', '请求被客户端中断')))
  })
}

/**
 * 读 JSON body（空体返回空对象）。
 * @param {import('node:http').IncomingMessage} req - 请求。
 * @param {number} limit - 上限。
 * @returns {Promise<Record<string, unknown>>} 解析结果。
 */
async function readJson(req, limit) {
  const bytes = await readBody(req, limit)
  const bodyText = bytes.toString('utf8')
  if (bodyText.trim() === '') return {}
  let parsed
  try {
    parsed = JSON.parse(bodyText)
  } catch (error) {
    throw new RmError('rm/bad-request', `body 不是合法 JSON：${String(error?.message ?? error).slice(0, 200)}`)
  }
  if (!isRecord(parsed)) throw new RmError('rm/bad-request', 'body 必须是 JSON 对象')
  return parsed
}

/**
 * 从 `multipart/form-data` 里取第一个文件与字段。
 * @param {Buffer} body - 原始 body。
 * @param {string} contentType - `Content-Type` 头。
 * @returns {{ file?: { name: string, type: string, bytes: Buffer }, fields: Record<string, string> }} 解析结果。
 */
export function parseMultipart(body, contentType) {
  const boundaryMatch = /boundary=(?:"([^"]+)"|([^;]+))/i.exec(contentType ?? '')
  const boundary = (boundaryMatch?.[1] ?? boundaryMatch?.[2] ?? '').trim()
  if (boundary === '') throw new RmError('rm/bad-request', 'multipart 缺少 boundary')
  /** @type {Record<string, string>} */
  const fields = {}
  /** @type {{ name: string, type: string, bytes: Buffer }|undefined} */
  let file
  const separator = `--${boundary}`
  let cursor = 0
  for (;;) {
    const start = body.indexOf(separator, cursor)
    if (start < 0) break
    const headerStart = start + separator.length
    // 结束标记 `--boundary--`。
    if (body.subarray(headerStart, headerStart + 2).toString('latin1') === '--') break
    // 跳过分隔符后的 CRLF。
    let partStart = headerStart
    if (body.subarray(partStart, partStart + 2).toString('latin1') === '\r\n') partStart += 2
    const headerEnd = body.indexOf('\r\n\r\n', partStart)
    if (headerEnd < 0) break
    const headerText = body.subarray(partStart, headerEnd).toString('utf8')
    const next = body.indexOf(separator, headerEnd + 4)
    if (next < 0) break
    // 去掉尾部 CRLF。
    const payloadEnd = body[next - 2] === 13 && body[next - 1] === 10 ? next - 2 : next
    const payload = body.subarray(headerEnd + 4, payloadEnd)
    const nameMatch = /name="([^"]*)"/i.exec(headerText)
    const filenameMatch = /filename="([^"]*)"/i.exec(headerText)
    const typeMatch = /content-type:\s*([^\r\n]+)/i.exec(headerText)
    const field = nameMatch?.[1] ?? ''
    if (filenameMatch !== null && file === undefined) {
      file = {
        name: filenameMatch[1] || field || 'upload.bin',
        type: (typeMatch?.[1] ?? 'application/octet-stream').trim(),
        bytes: Buffer.from(payload),
      }
    } else if (field !== '') {
      fields[field] = payload.toString('utf8')
    }
    cursor = next
  }
  return { ...(file === undefined ? {} : { file }), fields }
}

/**
 * 建监听器。
 *
 * @param {object} options - 依赖。
 * @param {import('../config.js').ResolvedConfig} options.config - 配置。
 * @param {object} options.devices - 设备表。
 * @param {object} options.pairing - 配对服务。
 * @param {object} options.approvals - 审批队列。
 * @param {object} options.upstream - 上游适配器。
 * @param {ReturnType<import('../static.js').createStatic>} options.statics - 静态资源。
 * @param {ReturnType<import('../audit.js').createAudit>} options.audit - 审计器。
 * @param {(level: 'debug'|'info'|'warn'|'error', message: string) => void} options.log - 日志。
 * @returns {object} 监听器 API。
 */
export function createListener({ config, devices, pairing, approvals, upstream, statics, audit, log, tunnel }) {
  // workspace 根发现：配置优先，其次上游 `/api/workspace/list`（30s 缓存）。
  // 拿不到就 fail-closed —— `/m/api/file` 全部 403 `rm/file-denied`（reason=no-root）。
  const workspaceRoots = createWorkspaceRoots({ config, upstream, log, audit })

  /** @type {http.Server|undefined} */
  let server
  let listeningPort = 0
  let killSwitch = false
  /** 全部连接（HTTP + upgrade），kill switch 时统一销毁。 */
  const sockets = new Set()
  /** 设备 id → 该设备的在途 socket / WS 句柄（撤销时精确断开）。 */
  const deviceSockets = new Map()
  /** WS 句柄集合（服务端 closeAllConnections 不管 upgrade socket）。 */
  const wsHandles = new Set()

  /**
   * 把一条 socket 记到设备名下。
   * @param {string} deviceId - 设备 id。
   * @param {import('node:net').Socket} socket - socket。
   * @returns {void}
   */
  function bindDeviceSocket(deviceId, socket) {
    let set = deviceSockets.get(deviceId)
    if (set === undefined) {
      set = new Set()
      deviceSockets.set(deviceId, set)
    }
    const record = { socket }
    set.add(record)
    socket.once('close', () => {
      set.delete(record)
      if (set.size === 0) deviceSockets.delete(deviceId)
    })
  }

  /**
   * 关掉某台设备的全部在途连接（撤销时用）。
   * @param {string} deviceId - 设备 id。
   * @returns {number} 断开的连接数。
   */
  function closeDeviceSockets(deviceId) {
    const set = deviceSockets.get(deviceId)
    if (set === undefined) return 0
    let closed = 0
    for (const record of [...set]) {
      try {
        record.socket.destroy()
        closed += 1
      } catch {
        // 已断开。
      }
    }
    deviceSockets.delete(deviceId)
    return closed
  }

  /**
   * 断开**所有**设备的在途连接（`devices.revokeAll` 用；kill 不走这里，
   * 因为 kill 的语义是「急停但保留设备」，由 `stop()` 统一销毁全部 socket）。
   * @returns {number} 断开的连接数。
   */
  function closeAllDeviceSockets() {
    let closed = 0
    for (const deviceId of [...deviceSockets.keys()]) closed += closeDeviceSockets(deviceId)
    return closed
  }

  /**
   * 兼容旧 Node：`server.closeAllConnections` 不存在时自己遍历。
   * @returns {number} 销毁的连接数。
   */
  function destroyAllSockets() {
    let closed = 0
    for (const socket of [...sockets]) {
      try {
        socket.destroy()
        closed += 1
      } catch {
        // 已断开。
      }
    }
    sockets.clear()
    return closed
  }

  /**
   * 请求来源闸门（网段 → Host → Origin → Sec-Fetch-Site）。
   * @param {import('node:http').IncomingMessage} req - 请求。
   * @returns {RmError|undefined} 拒绝原因。
   */
  function guard(req) {
    const remote = req.socket?.remoteAddress
    // 走隧道时来源**不是**局域网地址：cloudflared 从本机连 127.0.0.1，
    // 但 Cloudflare 边缘→cloudflared 那段在外部。这里的 remoteAddress 实际是
    // 本机（127.0.0.1），因为隧道客户端把请求转回本机回环。
    // 所以网段闸门仍然要过，但要有明确的"隧道开着"的语义——见下面的 publicHost。
    const fromTunnel = tunnel?.publicHost !== undefined && isLoopback(remote)
    if (!fromTunnel && !isAllowedSource(remote, config.allowedNetworks)) {
      return new RmError('rm/forbidden', `来源地址 ${remote ?? '(未知)'} 不在允许的网段内（默认只允许局域网/链路本地/loopback）`)
    }
    const hostHeader = req.headers.host
    if (typeof hostHeader !== 'string' || hostHeader === '') {
      return new RmError('rm/bad-request', '缺少 Host 头（浏览器请求不会这样）')
    }
    const allowed = allowedAuthorities(listeningPort, config.bindAddress, tunnel?.publicHost)
    if (!allowed.has(hostHeader.toLowerCase())) {
      return new RmError(
        'rm/bad-request',
        `Host ${hostHeader} 不是本机监听地址；允许的值：${[...allowed].slice(0, 6).join(', ')}…`,
      )
    }
    const origin = req.headers.origin
    if (typeof origin === 'string' && origin !== '' && !isSameAuthorityOrigin(origin, hostHeader)) {
      return new RmError('rm/forbidden', `Origin ${origin} 与 Host ${hostHeader} 不同源`)
    }
    const fetchSite = req.headers['sec-fetch-site']
    if (fetchSite === 'cross-site') {
      return new RmError('rm/forbidden', 'Sec-Fetch-Site: cross-site 被拒绝')
    }
    // 隧道有流量 = 有人在用，刷新空闲计时（否则会边用边被超时掐掉）。
    tunnel?.touch()
    return undefined
  }

  /**
   * 解析设备 cookie 并 touch。
   * @param {import('node:http').IncomingMessage} req - 请求。
   * @returns {{ device: object, secret: string }|undefined} 设备。
   */
  function authenticate(req) {
    const hit = devices.authenticate(req.headers.cookie)
    if (hit === undefined) return undefined
    devices.touch(hit.device, req.socket?.remoteAddress)
    return hit
  }

  /**
   * 需要设备身份的请求：拿不到就按 `mode` 回 401 或跳配对页。
   * @param {import('node:http').IncomingMessage} req - 请求。
   * @param {import('node:http').ServerResponse} res - 响应。
   * @param {'json'|'redirect'} mode - 失败方式。
   * @returns {object|undefined} 设备记录。
   */
  function requireDevice(req, res, mode) {
    const hit = authenticate(req)
    if (hit !== undefined) return hit.device
    audit.audit({ kind: 'deny', detail: 'device-cookie-missing-or-invalid', endpoint: req.url })
    if (mode === 'redirect') {
      if (res.writableEnded || res.destroyed) return undefined
      res.writeHead(302, { location: PAIR_PATH, 'cache-control': 'no-store' })
      res.end()
      return undefined
    }
    json(res, 401, failureBody(new RmError('rm/unauthorized', '设备未配对或凭据已失效，请重新配对')))
    return undefined
  }

  /**
   * 服务一个静态资源（`/m/<name>`）。
   * @param {import('node:http').IncomingMessage} req - 请求。
   * @param {import('node:http').ServerResponse} res - 响应。
   * @param {string} name - 文件名。
   * @param {boolean} [isShell] - 是否是页面壳（用于兜底）。
   * @returns {Promise<void>} 完成。
   */
  async function serveStatic(req, res, name, isShell = false) {
    const found = await statics.get(name)
    const method = (req.method ?? 'GET').toUpperCase()
    const body = found?.bytes ?? (isShell ? Buffer.from(FALLBACK_HTML[name] ?? FALLBACK_HTML['m.html'], 'utf8') : undefined)
    if (body === undefined) {
      json(res, 404, failureBody(new RmError('rm/not-found', `没有这个静态资源：${name}`)))
      return
    }
    const etag = found?.etag ?? '"fallback"'
    const contentType = found?.mime ?? 'text/html; charset=utf-8'
    const ifNoneMatch = req.headers['if-none-match']
    if (typeof ifNoneMatch === 'string' && ifNoneMatch === etag) {
      res.writeHead(304, { etag, 'cache-control': 'no-cache' })
      res.end()
      return
    }
    /** @type {Record<string, string|number>} */
    const headers = {
      'content-type': contentType,
      'content-length': body.length,
      'cache-control': 'no-cache',
      etag,
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'no-referrer',
    }
    if (name === 'sw.js') headers['service-worker-allowed'] = '/m/'
    // 手机端页面不需要被任何第三方框住。
    if (contentType.startsWith('text/html')) {
      headers['x-frame-options'] = 'DENY'
      // `script-src` 放行 inline：`web/pair.html` 是自包含单文件（内联配对表单脚本）。
      // 这里服务的一律是包内自有静态文件、不回显任何请求内容，inline 不引入反射型
      // XSS 面；`default-src 'self'` 仍然挡住外链脚本与资源。
      headers['content-security-policy'] = "default-src 'self'; img-src 'self' data: blob:; "
        + "style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; worker-src 'self'; "
        + "connect-src 'self' ws: wss:; media-src 'self' blob:; base-uri 'none'; form-action 'self'"
    }
    res.writeHead(200, headers)
    if (method === 'HEAD') res.end()
    else res.end(body)
  }

  /**
   * 上游响应 → 手机（逐块转发，只改 header）。
   * @param {import('node:http').ServerResponse} res - 手机响应。
   * @param {import('node:http').IncomingMessage} upstreamRes - 上游响应。
   * @returns {void}
   */
  function pumpUpstream(res, upstreamRes) {
    if (res.writableEnded || res.destroyed) {
      upstreamRes.destroy()
      return
    }
    res.writeHead(upstreamRes.statusCode ?? 502, rewriteResponseHeaders(upstreamRes.headers))
    upstreamRes.on('error', () => {
      try {
        res.destroy()
      } catch {
        // 已断开。
      }
    })
    res.on('close', () => {
      if (!upstreamRes.destroyed) upstreamRes.destroy()
    })
    upstreamRes.pipe(res)
  }

  /**
   * 把上游的非 JSON 错误变成统一错误体。
   * @param {import('node:http').ServerResponse} res - 手机响应。
   * @param {import('node:http').IncomingMessage} upstreamRes - 上游响应。
   * @param {string} endpoint - 端点名（审计用）。
   * @returns {void}
   */
  function failUpstream(res, upstreamRes, endpoint) {
    upstreamRes.resume()
    const status = upstreamRes.statusCode ?? 502
    const message = status === 401
      ? `上游拒绝了插件凭据（${endpoint}），cookie 可能已失效`
      : `上游返回 ${status}（${endpoint}）`
    audit.audit({ kind: 'deny', detail: message, endpoint })
    json(res, status === 401 ? 502 : status, failureBody(new RmError('rm/upstream', message)))
  }

  /**
   * `/m/api/<endpoint>` 的 unary 代理（PROTOCOL §1）。
   * @param {import('node:http').IncomingMessage} req - 请求。
   * @param {import('node:http').ServerResponse} res - 响应。
   * @param {object} device - 设备。
   * @param {string} endpoint - 端点名。
   * @returns {Promise<void>} 完成。
   */
  async function proxyUnary(req, res, device, endpoint) {
    if ((req.method ?? 'GET').toUpperCase() !== 'POST') {
      json(res, 405, failureBody(new RmError('rm/bad-request', '/m/api/* 只接受 POST（文件下载走 GET /m/api/file）')), { allow: 'POST' })
      return
    }
    const verdict = decide({ device, kind: 'unary', endpoint })
    if (verdict.ok !== true) {
      audit.audit({ kind: 'deny', deviceId: device.id, deviceName: device.name, endpoint, detail: verdict.code })
      json(res, statusForError({ code: verdict.code }), failureBody(new RmError(verdict.code, verdict.message)))
      return
    }
    const body = await readJson(req, JSON_BODY_LIMIT)
    const args = isRecord(body.args) ? body.args : undefined
    if (args === undefined) {
      json(res, 400, failureBody(new RmError('rm/bad-request', 'body 必须是 {"args":{…}}（args 为对象）')))
      return
    }
    rememberSession(device, args)
    const envelope = {
      type: 'client-request',
      rpcId: `rm-${Date.now()}-${Math.floor(Math.random() * 1e6)}`,
      method: endpoint,
      payload: { args },
    }
    const payload = Buffer.from(JSON.stringify(envelope), 'utf8')
    const headers = rewriteRequestHeaders(req.headers, {
      authority: upstream.authority(),
      origin: upstream.origin(),
      cookie: upstream.cookieHeader(),
    })
    headers['content-type'] = 'application/json'
    headers['content-length'] = String(payload.length)
    let upstreamRes
    try {
      upstreamRes = await upstream.send({
        path: `/api/${endpoint}`,
        method: 'POST',
        headers,
        body: payload,
      })
    } catch (error) {
      audit.audit({ kind: 'deny', deviceId: device.id, endpoint, detail: String(error?.message ?? error) })
      json(res, 502, failureBody(new RmError('rm/upstream', `转发到上游失败：${String(error?.message ?? error)}`)))
      return
    }
    audit.rpc({ device, ip: device.lastIp, endpoint, status: upstreamRes.statusCode ?? 0, method: 'POST' })
    if ((upstreamRes.statusCode ?? 0) === 401) {
      failUpstream(res, upstreamRes, endpoint)
      return
    }
    pumpUpstream(res, upstreamRes)
  }

  /**
   * `GET /m/api/file?path=`：产物下载/看图。
   * @param {import('node:http').IncomingMessage} req - 请求。
   * @param {import('node:http').ServerResponse} res - 响应。
   * @param {object} device - 设备。
   * @param {URL} url - 已解析 URL。
   * @returns {Promise<void>} 完成。
   */
  async function proxyFile(req, res, device, url) {
    const filePath = url.searchParams.get('path') ?? ''
    if (filePath.trim() === '') {
      json(res, 400, failureBody(new RmError('rm/bad-request', '缺少 path 查询参数（绝对路径）')))
      return
    }
    // 作用域闸门：绝对路径 + 无 `..`/UNC + 敏感项黑名单 + workspace 根 allowlist + realpath 防逃逸。
    // 根拿不到时 fail-closed（no-root），绝不回退 homedir/cwd。
    const roots = await workspaceRoots.get()
    const scope = await checkFilePath(filePath, {
      mode: config.fileAccess.mode,
      roots: roots.roots,
      extraDeny: config.fileAccess.extraDeny,
    })
    if (scope.ok !== true) {
      const detail = `scope:${scope.reason}:${scope.detail}`
      audit.audit({ kind: 'deny', deviceId: device.id, deviceName: device.name, endpoint: 'file', detail })
      const message = FILE_DENY_MESSAGES[scope.reason] ?? '这个路径不允许通过手机下载'
      json(res, statusForError({ code: 'rm/file-denied' }), failureBody(new RmError('rm/file-denied', message)))
      return
    }
    const verdict = decide({ device, kind: 'file' })
    if (verdict.ok !== true) {
      json(res, statusForError({ code: verdict.code }), failureBody(new RmError(verdict.code, verdict.message)))
      return
    }
    const headers = rewriteRequestHeaders(req.headers, {
      authority: upstream.authority(),
      origin: upstream.origin(),
      cookie: upstream.cookieHeader(),
    })
    let upstreamRes
    try {
      upstreamRes = await upstream.send({
        path: `/api/file?path=${encodeURIComponent(filePath)}`,
        method: 'GET',
        headers,
      })
    } catch (error) {
      json(res, 502, failureBody(new RmError('rm/upstream', `转发到上游失败：${String(error?.message ?? error)}`)))
      return
    }
    audit.rpc({ device, ip: device.lastIp, endpoint: 'file', status: upstreamRes.statusCode ?? 0, method: 'GET' })
    if ((upstreamRes.statusCode ?? 0) === 401) {
      failUpstream(res, upstreamRes, 'file')
      return
    }
    pumpUpstream(res, upstreamRes)
  }

  /**
   * `POST /m/api/upload`：发文件/图片（PROTOCOL §1）。
   * @param {import('node:http').IncomingMessage} req - 请求。
   * @param {import('node:http').ServerResponse} res - 响应。
   * @param {object} device - 设备。
   * @param {URL} url - 已解析 URL。
   * @returns {Promise<void>} 完成。
   */
  async function proxyUpload(req, res, device, url) {
    if ((req.method ?? 'GET').toUpperCase() !== 'POST') {
      json(res, 405, failureBody(new RmError('rm/bad-request', '/m/api/upload 只接受 POST')), { allow: 'POST' })
      return
    }
    const verdict = decide({ device, kind: 'upload' })
    if (verdict.ok !== true) {
      audit.audit({ kind: 'deny', deviceId: device.id, endpoint: 'upload', detail: verdict.code })
      json(res, statusForError({ code: verdict.code }), failureBody(new RmError(verdict.code, verdict.message)))
      return
    }
    const bytes = await readBody(req, UPLOAD_BODY_LIMIT)
    const contentType = String(req.headers['content-type'] ?? '')
    /** @type {{ name: string, bytes: Buffer, sessionId: string }} */
    let upload
    if (contentType.toLowerCase().startsWith('multipart/form-data')) {
      const parsed = parseMultipart(bytes, contentType)
      if (parsed.file === undefined) {
        json(res, 400, failureBody(new RmError('rm/bad-request', 'multipart 里没有文件字段')))
        return
      }
      upload = {
        name: parsed.file.name,
        bytes: parsed.file.bytes,
        sessionId: url.searchParams.get('sessionId') ?? parsed.fields.sessionId ?? parsed.fields.sessionid ?? '',
      }
    } else if (contentType.toLowerCase().includes('application/json')) {
      let parsed
      try {
        parsed = JSON.parse(bytes.toString('utf8'))
      } catch {
        json(res, 400, failureBody(new RmError('rm/bad-request', '上传 JSON 不是合法 JSON')))
        return
      }
      if (!isRecord(parsed) || typeof parsed.dataBase64 !== 'string') {
        json(res, 400, failureBody(new RmError('rm/bad-request', '上传 JSON 需要 {name, dataBase64}')))
        return
      }
      upload = {
        name: typeof parsed.name === 'string' && parsed.name !== '' ? parsed.name : 'upload.bin',
        bytes: Buffer.from(parsed.dataBase64, 'base64'),
        sessionId: url.searchParams.get('sessionId')
          ?? (typeof parsed.sessionId === 'string' ? parsed.sessionId : ''),
      }
    } else {
      // 默认按原始字节（application/octet-stream）。
      upload = {
        name: url.searchParams.get('name') ?? 'upload.bin',
        bytes,
        sessionId: url.searchParams.get('sessionId') ?? '',
      }
    }
    if (upload.bytes.length === 0) {
      json(res, 400, failureBody(new RmError('rm/bad-request', '上传内容是空的')))
      return
    }
    if (upload.sessionId.trim() === '') {
      json(res, 400, failureBody(new RmError('rm/bad-request', '缺少 sessionId（查询串或表单字段）')))
      return
    }
    const upstreamPath = `/api/session/uploadFileBinary?sessionId=${encodeURIComponent(upload.sessionId)}`
      + `&name=${encodeURIComponent(upload.name)}`
    const uploadHeaders = rewriteRequestHeaders(req.headers, {
      authority: upstream.authority(),
      origin: upstream.origin(),
      cookie: upstream.cookieHeader(),
    })
    // 上游这个精确路由要求 application/octet-stream（PLAN §3.3.3）。
    uploadHeaders['content-type'] = 'application/octet-stream'
    uploadHeaders['content-length'] = String(upload.bytes.length)
    let upstreamRes
    try {
      upstreamRes = await upstream.send({
        path: upstreamPath,
        method: 'POST',
        headers: uploadHeaders,
        body: upload.bytes,
        // 有 body 的请求不再重试：401 时如实报错，由手机重试。
        retryOn401: false,
      })
    } catch (error) {
      json(res, 502, failureBody(new RmError('rm/upstream', `转发上传失败：${String(error?.message ?? error)}`)))
      return
    }
    const receiptBytes = await readUpstream(upstreamRes, UPLOAD_RECEIPT_LIMIT)
    audit.rpc({ device, ip: device.lastIp, endpoint: 'upload', status: upstreamRes.statusCode ?? 0, method: 'POST' })
    const receipt = (() => {
      try {
        return JSON.parse(receiptBytes.toString('utf8'))
      } catch {
        return undefined
      }
    })()
    if (!isRecord(receipt)) {
      json(res, 502, failureBody(new RmError('rm/upstream', '上游上传接口没有返回 JSON 回执')))
      return
    }
    if (receipt.ok !== true) {
      const message = isRecord(receipt.error) && typeof receipt.error.message === 'string'
        ? receipt.error.message
        : '上游拒绝了这次上传'
      json(res, 502, failureBody(new RmError('rm/upstream', message)))
      return
    }
    const value = isRecord(receipt.value) ? receipt.value : {}
    const receiptId = typeof value.receiptId === 'string'
      ? value.receiptId
      : (typeof value.id === 'string' ? value.id : '')
    json(res, 200, { ok: true, receiptId, name: upload.name, size: upload.bytes.length })
  }

  /**
   * 读完一个上游响应（有上限）。
   * @param {import('node:http').IncomingMessage} upstreamRes - 上游响应。
   * @param {number} limit - 上限。
   * @returns {Promise<Buffer>} body。
   */
  function readUpstream(upstreamRes, limit) {
    return new Promise((resolve) => {
      /** @type {Buffer[]} */
      const chunks = []
      let size = 0
      upstreamRes.on('data', (chunk) => {
        if (size >= limit) return
        const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)
        chunks.push(buffer)
        size += buffer.length
      })
      upstreamRes.on('end', () => resolve(Buffer.concat(chunks)))
      upstreamRes.on('error', () => resolve(Buffer.concat(chunks)))
    })
  }

  /**
   * 记住设备最近看的会话（`/m/state` 回显用）。
   * @param {object} device - 设备记录。
   * @param {Record<string, unknown>} args - unary args。
   * @returns {void}
   */
  function rememberSession(device, args) {
    /** @type {unknown[]} */
    const candidates = [args.sessionId, args._request, args.request]
    for (const candidate of candidates) {
      if (isRecord(candidate) && typeof candidate.sessionId === 'string' && candidate.sessionId !== '') {
        device.lastSessionId = candidate.sessionId
        return
      }
    }
    if (typeof args.sessionId === 'string' && args.sessionId !== '') device.lastSessionId = args.sessionId
  }

  /**
   * 一个 HTTP 请求的完整处理。
   * @param {import('node:http').IncomingMessage} req - 请求。
   * @param {import('node:http').ServerResponse} res - 响应。
   * @returns {Promise<void>} 完成。
   */
  async function handle(req, res) {
    const rejected = guard(req)
    if (rejected !== undefined) {
      audit.debug('guard-reject', { url: req.url, code: rejected.code, message: rejected.message })
      json(res, statusForError(rejected), failureBody(rejected))
      return
    }
    let url
    try {
      url = new URL(req.url ?? '/', 'http://remote-mobile.invalid')
    } catch {
      json(res, 400, failureBody(new RmError('rm/bad-request', '请求 URL 不合法')))
      return
    }
    const method = (req.method ?? 'GET').toUpperCase()
    const pathname = url.pathname

    // ── 无鉴权端点 ────────────────────────────────────────────────
    if (pathname === '/m/ping' && (method === 'GET' || method === 'HEAD')) {
      const paired = devices.authenticate(req.headers.cookie) !== undefined
      const secureContext = isLoopback(req.socket?.remoteAddress)
      json(res, 200, {
        ok: true,
        v: PLUGIN_VERSION,
        secureContext,
        upstreamOk: upstream.cookieOk,
        paired,
      })
      return
    }

    if (pathname === '/m/pair') {
      if (method === 'GET' || method === 'HEAD') {
        // 页面自己消费 `?code=`/`?c=`（与 mobile-web 约定：服务端不消费）。
        await serveStatic(req, res, 'pair.html', true)
        return
      }
      if (method === 'POST') {
        await handlePairPost(req, res)
        return
      }
      json(res, 405, failureBody(new RmError('rm/bad-request', '/m/pair 只接受 GET/POST')), { allow: 'GET, POST' })
      return
    }

    // ── 插件自有的固定资源（在反代之前拦下）───────────────────────
    //
    // `/m/**` 整站反代之后，插件自己的图标也会被转发到上游而 404/302，
    // 于是配对页的 logo 显示成破图。这两个名字是插件占用的，属于保留路径：
    // 先由插件提供，剩下的才交给上游。
    //
    // 只放行白名单里的名字（不是整个 `/m/*`），避免把上游的资源误拦。
    if (method === 'GET' || method === 'HEAD') {
      const RESERVED_STATIC = ['icon.svg', 'pair.html']
      const name = pathname.startsWith('/m/') ? pathname.slice('/m/'.length) : ''
      if (name !== '' && RESERVED_STATIC.includes(name)) {
        await serveStatic(req, res, name)
        return
      }
    }

    // ── `/m/**` 整站反代（唯一形态）────────────────────────────────
    //
    // 手机拿到的就是**完整 DSH Web UI**：工作区分组、插件设置、Agent 运行时
    // 排队提示等全部自动具备，上游加新功能手机端自动跟着走。
    //
    // 上面已经处理掉两个「插件自己应答」的前缀，其余全部转发：
    //   `/m/ping`  健康检查（无鉴权，配对页要先用）
    //   `/m/pair`  配对页与配对提交（这是设备身份的入口，不能被上游盖掉）
    //
    // 鉴权：整站是个人工作区，未经配对的请求一律 302 到 `/m/pair`。
    if (isUnderPrefix(pathname, '/m')) {
      // 尾斜杠是**功能正确性**要求，不是美观：
      // 上游 index.html 会注入 `<base href="./">`，资源全是相对路径。
      // 若地址栏停在 `/m`（无斜杠），`./assets/x.js` 会解析成 `/assets/x.js`
      // （跳出前缀），于是整站 404。这里先规整到 `/m/` 再转发。
      if (pathname === '/m' && (method === 'GET' || method === 'HEAD')) {
        const target = `/m/${url.search}`
        res.writeHead(302, { location: target, 'cache-control': 'no-store' })
        res.end()
        return
      }
      const device = requireDevice(req, res, 'redirect')
      if (device === undefined) return
      await proxySiteRequest({
        req,
        res,
        upstream,
        prefix: '/m',
        bodyLimit: SITE_BODY_LIMIT,
        log,
      })
      return
    }

    // ── 根路径 → /m 跳转 ────────────────────────────────────────
    //
    // 隧道给的是 `https://<域名>/`，用户（和分享链接）几乎总是直接打开根路径。
    // 回一句 404 JSON 会让人以为"隧道坏了"，而实际只是少了个 /m。
    // 这里做一次明确的重定向，顺便在 body 里写清去哪儿。
    if (pathname === '/' && (method === 'GET' || method === 'HEAD')) {
      res.writeHead(302, {
        location: `/m${url.search}`,
        'cache-control': 'no-store',
        'content-type': 'text/plain; charset=utf-8',
      })
      res.end('手机端入口在 /m\n')
      return
    }

    // ── 其它一律 404（绝不转发 SPA/静态/插件资源）─────────────────
    json(res, 404, failureBody(new RmError('rm/not-found', `手机端没有这个路径：${pathname}`)))
  }

  /**
   * `POST /m/pair`：JSON 与 urlencoded 双支持（mobile-web 的页面有原生表单退化路径）。
   * @param {import('node:http').IncomingMessage} req - 请求。
   * @param {import('node:http').ServerResponse} res - 响应。
   * @returns {Promise<void>} 完成。
   */
  async function handlePairPost(req, res) {
    const contentType = String(req.headers['content-type'] ?? '').toLowerCase()
    const raw = await readBody(req, SMALL_BODY_LIMIT)
    const form = new URLSearchParams(raw.toString('utf8'))
    let code
    let name
    if (contentType.includes('application/json')) {
      let parsed
      try {
        parsed = JSON.parse(raw.toString('utf8') || '{}')
      } catch {
        json(res, 400, failureBody(new RmError('rm/bad-request', '配对请求不是合法 JSON')))
        return
      }
      if (!isRecord(parsed)) {
        json(res, 400, failureBody(new RmError('rm/bad-request', '配对请求必须是 JSON 对象')))
        return
      }
      code = parsed.code
      name = parsed.name
    } else {
      code = form.get('code') ?? undefined
      name = form.get('name') ?? undefined
    }
    try {
      const created = await pairing.attempt({
        code,
        name,
        ua: typeof req.headers['user-agent'] === 'string' ? req.headers['user-agent'] : '',
        ip: req.socket?.remoteAddress,
      })
      const wantsJson = contentType.includes('application/json')
      if (wantsJson) {
        // §1：JSON 分支的 body 里也要带 `location`（手机端/验收都按它跳转），
        // 不能只写在响应头里——header 只对表单 303 有意义。
        json(
          res,
          200,
          {
            ok: true,
            device: { id: created.device.id, name: created.device.name },
            location: '/m',
          },
          { 'set-cookie': created.setCookie },
        )
      } else {
        res.writeHead(303, { location: '/m', 'set-cookie': created.setCookie, 'cache-control': 'no-store' })
        res.end()
      }
    } catch (error) {
      const status = error?.httpStatus ?? statusForError(error)
      if (!contentType.includes('application/json')) {
        text(res, status, `${(error?.message ?? '配对失败')}\n\n<a href="/m/pair">返回配对页</a>`)
        return
      }
      json(res, status, failureBody(error))
    }
  }

  /**
   * upgrade 分发：只认 `/api/remote.mux`。
   * @param {import('node:http').IncomingMessage} req - 请求。
   * @param {import('node:net').Socket} socket - socket。
   * @param {Buffer} head - 残留字节。
   * @returns {Promise<void>} 完成。
   */
  async function handleUpgrade(req, socket, head) {
    /** @type {Record<string, string>} */
    const rejectHeaders = { connection: 'close', 'content-type': 'text/plain; charset=utf-8' }
    /**
     * 在 upgrade 连接上写一个裸 HTTP 错误响应并断开。
     * @param {number} status - 状态码。
     * @param {string} body - 正文。
     * @returns {void}
     */
    function reject(status, body) {
      try {
        socket.end(
          `HTTP/1.1 ${status} ${http.STATUS_CODES[status] ?? 'Error'}\r\n`
          + `${Object.entries(rejectHeaders).map(([key, value]) => `${key}: ${value}`).join('\r\n')}\r\n`
          + `content-length: ${Buffer.byteLength(body, 'utf8')}\r\n\r\n${body}`,
        )
      } catch {
        // 已断开。
      }
    }

    const rejected = guard(req)
    if (rejected !== undefined) {
      reject(statusForError(rejected), rejected.message)
      return
    }
    let pathname
    try {
      pathname = new URL(req.url ?? '/', 'http://remote-mobile.invalid').pathname
    } catch {
      pathname = ''
    }
    // WebSocket 是完整 Web UI 的生命线（会话流、增量更新都走它）。
    //
    // 接受两种路径：
    //   `/api/remote.mux`     —— 旧移动页直连（保留兼容）
    //   `/m/api/remote.mux`   —— 整站反代形态下，浏览器按 `/m` 前缀拼出来的地址
    //
    // 转发时必须把前缀剥掉，否则上游收到 `/m/api/remote.mux` 会 404。
    const WS_PATH = '/api/remote.mux'
    const wsUpstreamPath = pathname === WS_PATH
      ? WS_PATH
      : (pathname === `/m${WS_PATH}` ? WS_PATH : undefined)
    if (wsUpstreamPath === undefined) {
      reject(404, `手机端没有这个 WebSocket 路径：${pathname}`)
      return
    }
    if (killSwitch === true) {
      reject(503, '手机同步已被 kill switch 关闭，请在 PC 面板重新开启')
      return
    }
    const hit = devices.authenticate(req.headers.cookie)
    if (hit === undefined) {
      audit.audit({ kind: 'deny', detail: 'ws-unauthorized', endpoint: 'remote.mux' })
      reject(401, '设备未配对或凭据已失效，请重新配对')
      return
    }
    const device = hit.device
    devices.touch(device, req.socket?.remoteAddress)
    // 确保上游 cookie 就绪（首次连接时可能还没交换过）。
    try {
      await upstream.ensure()
    } catch {
      // ensure() 内部已记录，下面用 endpoint 判断。
    }
    const target = upstream.endpoint()
    if (typeof target.cookie !== 'string' || target.cookie === '') {
      reject(502, '插件还没拿到上游凭据（cookie 交换失败），请在 PC 面板点「自检」查看原因')
      return
    }
    bindDeviceSocket(device.id, socket)
    const handleWs = { deviceId: device.id }
    wsHandles.add(handleWs)
    proxyWebSocket({
      req,
      socket,
      head,
      target,
      authorizeOpen: (endpoint) => decide({ device, kind: 'ws-open', endpoint }),
      upstreamPath: wsUpstreamPath,
      audit: (event, fields) => {
        if (event === 'ws-open') {
          audit.audit({ kind: 'ws-open', deviceId: device.id, deviceName: device.name, endpoint: 'remote.mux' })
        } else {
          audit.debug(event, { deviceId: device.id, ...(fields ?? {}) })
        }
      },
      log,
      onClose: (reason) => {
        wsHandles.delete(handleWs)
        audit.debug('ws-close', { deviceId: device.id, reason })
      },
    })
  }

  /**
   * 起监听器：按 `port` 起尝试 `PORT_SCAN_SPAN` 个端口，再不行用 0（OS 分配）。
   * @returns {Promise<{ port: number, urls: string[] }>} 实际端口与 URL 列表。
   */
  async function start() {
    if (server !== undefined) return { port: listeningPort, urls: buildUrls(listeningPort, '/m') }
    const candidates = []
    if (config.port > 0) {
      for (let offset = 0; offset < PORT_SCAN_SPAN; offset += 1) {
        const candidate = config.port + offset
        if (candidate >= 1 && candidate <= 65_535) candidates.push(candidate)
      }
    }
    candidates.push(0)

    let lastError
    for (const candidate of candidates) {
      const candidateServer = http.createServer((req, res) => {
        Promise.resolve(handle(req, res)).catch((error) => {
          const message = String(error?.message ?? error)
          audit.debug('route-crash', {
            url: req.url,
            method: req.method,
            message,
            stack: typeof error?.stack === 'string' ? error.stack.slice(0, 4000) : undefined,
          })
          try {
            json(res, 500, failureBody(new RmError('rm/internal', `路由处理异常：${message}`)))
          } catch {
            // 响应已结束。
          }
        })
      })
      // 长连接优先：这两个 0 是 /api/remote.mux 能一直活着的前提。
      candidateServer.requestTimeout = 0
      candidateServer.headersTimeout = 0
      candidateServer.timeout = 0
      candidateServer.keepAliveTimeout = 65_000
      candidateServer.on('connection', (socket) => {
        sockets.add(socket)
        socket.once('close', () => sockets.delete(socket))
      })
      candidateServer.on('upgrade', (req, socket, head) => {
        Promise.resolve(handleUpgrade(req, socket, head)).catch((error) => {
          audit.debug('upgrade-crash', { url: req.url, message: String(error?.message ?? error) })
          try {
            socket.destroy()
          } catch {
            // 已断开。
          }
        })
      })
      try {
        await new Promise((resolve, reject) => {
          const onError = (error) => {
            candidateServer.removeListener('listening', onListening)
            reject(error)
          }
          const onListening = () => {
            candidateServer.removeListener('error', onError)
            resolve(undefined)
          }
          candidateServer.once('error', onError)
          candidateServer.once('listening', onListening)
          candidateServer.listen(candidate, config.bindAddress)
        })
      } catch (error) {
        lastError = error
        try {
          candidateServer.close()
        } catch {
          // 还没监听成功。
        }
        if (error?.code === 'EADDRINUSE' || error?.code === 'EACCES') {
          audit.debug('listen-retry', { port: candidate, code: error.code })
          continue
        }
        throw new RmError('rm/internal', `监听 ${config.bindAddress} 失败：${String(error?.message ?? error)}`)
      }
      server = candidateServer
      const address = server.address()
      listeningPort = typeof address === 'object' && address !== null ? address.port : 0
      const urls = buildUrls(listeningPort, '/m')
      audit.audit({ kind: 'enabled', detail: `listen ${config.bindAddress}:${listeningPort}` })
      log(
        'info',
        `remote-mobile: 已监听 ${config.bindAddress}:${listeningPort}（手机访问 ${urls[0] ?? '(没有可用 LAN 地址)'}）`,
      )
      return { port: listeningPort, urls }
    }
    throw new RmError(
      'rm/internal',
      `端口 ${config.port}..${config.port + PORT_SCAN_SPAN - 1} 与随机端口都监听失败：`
      + `${String(lastError?.message ?? lastError)}`,
    )
  }

  /**
   * 关监听器（可选销毁全部 socket）。
   * @param {{ resumeApprovals?: boolean }} [options] - 选项。
   * @returns {Promise<{ closed: number }>} 关闭结果。
   */
  async function stop(options = {}) {
    const closed = destroyAllSockets()
    wsHandles.clear()
    deviceSockets.clear()
    if (server !== undefined) {
      const current = server
      server = undefined
      await new Promise((resolve) => {
        try {
          current.close(() => resolve(undefined))
        } catch {
          resolve(undefined)
        }
      })
      try {
        current.closeAllConnections?.()
      } catch {
        // 旧版 Node 没有这个方法，destroyAllSockets 已经兜住。
      }
    }
    // 端口归零：面板 `status.port` 必须如实反映「已关闭」，否则会显示一个
    // 早就不存在的旧端口，用户照着它访问只会超时。
    listeningPort = 0
    if (options.resumeApprovals !== false) approvals.settleAll('listener-stopped')
    if (closed > 0) log('info', `remote-mobile: 监听器已关闭，断开 ${closed} 条连接`)
    return { closed }
  }

  return {
    start,
    stop,

    /** 实际监听端口（未监听为 0）。 */
    get port() {
      return server === undefined ? 0 : listeningPort
    },

    /** 是否正在监听。 */
    get running() {
      return server !== undefined
    },

    /** kill switch 状态。 */
    get killSwitch() {
      return killSwitch
    },

    /** 手机可用 URL 列表。 */
    urls() {
      return server === undefined ? [] : buildUrls(listeningPort, '/m')
    },

    /** 局域网地址（面板展示用）。 */
    lanIps() {
      return listLanAddresses().map((entry) => ({
        address: entry.address,
        family: entry.family,
        iface: entry.iface,
        url: `http://${urlHost(entry.address)}:${listeningPort || config.port}/m`,
      }))
    },

    /** 断开某台设备的在途连接（撤销/只读切换用）。 */
    closeDeviceSockets,

    /** 断开全部设备的在途连接（`devices.revokeAll` 用）。 */
    closeAllDeviceSockets,

    /**
     * 置 kill switch：true 时立刻关监听器并断开所有连接，之后拒绝新请求。
     * （`enabled` 语义由 index.js 决定，这里只管 socket 与状态位。）
     * @param {boolean} value - 是否打开 kill switch。
     * @returns {Promise<{ closed: number }>} 关闭结果。
     */
    async setKillSwitch(value) {
      killSwitch = value === true
      if (killSwitch !== true) return { closed: 0 }
      const result = await stop()
      return result
    },

    /** 诊断信息。 */
    stats() {
      return {
        running: server !== undefined,
        port: listeningPort,
        sockets: sockets.size,
        ws: wsHandles.size,
        devicesWithSockets: deviceSockets.size,
        killSwitch,
      }
    },
  }
}

/**
 * 是否是 loopback 对端（`/m/ping` 的 `secureContext` 判定）。
 * @param {string|undefined} address - 对端地址。
 * @returns {boolean} 结论。
 */
function isLoopback(address) {
  if (typeof address !== 'string') return false
  const normalized = address.startsWith('::ffff:') ? address.slice(7) : address
  return normalized === '::1' || normalized === '127.0.0.1' || normalized.startsWith('127.')
}

/** 供测试/文档引用：`path` 在 `package.json` 的 `files` 里，静态目录就是包内 `web/`。 */
export const STATIC_DIR_NAME = 'web'

/** 包根相对 `web/` 的位置（静态服务初始化用）。 */
export const WEB_DIR = path.join('web')
