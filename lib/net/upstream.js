/**
 * 上游（DSH 自己的 `ctx.webServer`）适配层：cookie 铸造 / 请求头改写 / 401 重交换。
 *
 * 三件事（PROTOCOL §0 与 PLAN §3.2.2 / §3.1.5）：
 *
 * 1. **cookie 交换**：`ctx.connection.authenticatedUrl(origin + '/')` 拿到带 token 的
 *    URL → `GET /?token=…`（不跟随重定向）→ 抽 `Set-Cookie` 里的
 *    `dsh-auth-<base64url(sha256(authority))>=v1.…`。cookie 只存在插件内存。
 * 2. **请求头改写**：手机的头一律重写——`Host/Origin` 改成上游 authority，`Cookie`
 *    注入上游 cookie，`Sec-Fetch-*`/`X-Forwarded-*` 一律删掉（DSH 不采信它们）。
 * 3. **401 自动重交换一次**：token 可能随 Host 重启变化，cookie 也可能过期。
 *
 * ⚠️ `getOrigin()` 在 `webServer` listen 之前会抛错，端口每次启动都可能变
 * （启动器写死 `--port 0`）。所以本模块**从不缓存 origin**，每次现取；任何地方
 * 都不许硬编码 13291。
 *
 * @module dsh-plugin-remote-mobile/upstream
 */

import crypto from 'node:crypto'
import http from 'node:http'

import { RmError } from '../config.js'

/** 上游一元请求的超时（毫秒）。流式响应（`/api/file`）用 `streamTimeoutMs`。 */
const REQUEST_TIMEOUT_MS = 30_000

/** 流式下载/上传到上游的超时；0 表示不主动掐（由手机侧断开决定）。 */
const STREAM_TIMEOUT_MS = 0

/**
 * 逐跳 header（RFC 7230 §6.1）：既不转发给上游，也不回给手机。
 */
export const HOP_BY_HOP = Object.freeze([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
])

/**
 * 手机 → 上游必须删除的 header（PROTOCOL §0 的边界铁律）。
 *
 * `host` / `origin` / `cookie` 会被重新写入；`authorization` 是 DSH 不认的；
 * `sec-fetch-*` 会让上游把跨站请求判成 `cross-site`；`x-forwarded-*` 明确不采信。
 */
const REQUEST_STRIP = new Set([
  'host',
  'origin',
  'cookie',
  'authorization',
  'expect',
  // 手机 body 的长度与插件重写后的 body 长度不同，必须由调用方显式给。
  'content-length',
  ...HOP_BY_HOP,
])

/**
 * 上游 → 手机必须删除的 header：`Set-Cookie`（上游凭据不能交给手机）、
 * `Strict-Transport-Security`（我们是明文 http）。
 */
const RESPONSE_STRIP = new Set(['set-cookie', 'strict-transport-security', ...HOP_BY_HOP])

/**
 * 上游 cookie 名：`dsh-auth-` + base64url(sha256(authority))（PLAN §3.2.2）。
 * @param {string} authority - 上游 authority，如 `127.0.0.1:13291`。
 * @returns {string} cookie 名。
 */
export function cookieNameFor(authority) {
  const digest = crypto.createHash('sha256').update(String(authority), 'utf8').digest()
  return `dsh-auth-${digest.toString('base64url')}`
}

/**
 * 从 `set-cookie` 头里抽 `dsh-auth-*` 的 `name=value`。
 * @param {string[]|undefined} setCookie - `res.headers['set-cookie']`。
 * @returns {{ name: string, value: string }|undefined} cookie 对。
 */
export function pickAuthCookie(setCookie) {
  if (!Array.isArray(setCookie)) return undefined
  for (const entry of setCookie) {
    if (typeof entry !== 'string') continue
    const first = entry.split(';', 1)[0]
    const index = first.indexOf('=')
    if (index <= 0) continue
    const name = first.slice(0, index).trim()
    if (!name.startsWith('dsh-auth-')) continue
    return { name, value: first.slice(index + 1).trim() }
  }
  return undefined
}

/**
 * 手机请求头 → 上游请求头（纯函数，便于表驱动测试）。
 *
 * @param {Record<string, unknown>} input - 手机请求的 header。
 * @param {object} rewrite - 改写规则。
 * @param {string} rewrite.authority - 上游 authority（写进 `Host`）。
 * @param {string} rewrite.origin - 上游 origin（写进 `Origin`）。
 * @param {string} [rewrite.cookie] - 上游 cookie 的 `name=value`。
 * @param {boolean} [rewrite.keepOrigin] - 是否保留 `Origin`（默认 true）。
 * @returns {Record<string, string>} 上游请求头。
 */
export function rewriteRequestHeaders(input, { authority, origin, cookie, keepOrigin = true }) {
  /** @type {Record<string, string>} */
  const output = {}
  for (const [rawName, rawValue] of Object.entries(input ?? {})) {
    const name = rawName.toLowerCase()
    if (REQUEST_STRIP.has(name)) continue
    if (name.startsWith('sec-fetch-')) continue
    if (name.startsWith('x-forwarded-')) continue
    if (rawValue === undefined) continue
    output[name] = Array.isArray(rawValue) ? rawValue.join(', ') : String(rawValue)
  }
  output.host = authority
  if (keepOrigin) output.origin = origin
  if (typeof cookie === 'string' && cookie !== '') output.cookie = cookie
  // 上游用的是 loopback 明文，不需要 keep-alive 语义；显式关掉更省 socket。
  output.connection = 'close'
  return output
}

/**
 * 上游响应头 → 手机响应头（纯函数）。
 * @param {Record<string, unknown>} input - 上游 header。
 * @returns {Record<string, string>} 给手机的头。
 */
export function rewriteResponseHeaders(input) {
  /** @type {Record<string, string>} */
  const output = {}
  for (const [rawName, rawValue] of Object.entries(input ?? {})) {
    const name = rawName.toLowerCase()
    if (RESPONSE_STRIP.has(name)) continue
    if (rawValue === undefined) continue
    output[name] = Array.isArray(rawValue) ? rawValue.join(', ') : String(rawValue)
  }
  return output
}

/**
 * 发一个 HTTP 请求到上游（不跟随重定向，响应体留给调用方 pipe）。
 *
 * @param {object} options - 参数。
 * @param {{ hostname: string, port: number, protocol: string }} options.upstream - 上游地址。
 * @param {string} options.path - 路径 + 查询串。
 * @param {string} [options.method] - 方法。
 * @param {Record<string, string>} options.headers - header。
 * @param {Buffer|undefined} [options.body] - 请求体（有就一次写完）。
 * @param {number} [options.timeoutMs] - 超时。
 * @returns {Promise<import('node:http').IncomingMessage>} 上游响应。
 */
function rawRequest({ upstream, path, method = 'GET', headers, body, timeoutMs = REQUEST_TIMEOUT_MS }) {
  return new Promise((resolve, reject) => {
    const req = http.request({
      hostname: upstream.hostname,
      port: upstream.port,
      method,
      path,
      headers,
      // 每条请求各用一条连接：上游是 loopback 明文，省掉 agent 的 socket 生命周期管理。
      agent: false,
    })
    req.setTimeout(timeoutMs, () => {
      req.destroy(new RmError('rm/upstream', `上游请求超时（${timeoutMs}ms）`))
    })
    req.on('error', (error) => {
      reject(error instanceof RmError ? error : new RmError('rm/upstream', `上游请求失败：${String(error?.message ?? error)}`))
    })
    req.on('response', (res) => resolve(res))
    if (body !== undefined) req.end(body)
    else req.end()
  })
}

/**
 * 建上游适配器。
 *
 * @param {object} options - 依赖。
 * @param {import('../config.js').ResolvedConfig} options.config - 已解析配置。
 * @param {(level: 'debug'|'info'|'warn'|'error', message: string) => void} options.log - 日志出口。
 * @param {ReturnType<import('../audit.js').createAudit>} options.audit - 审计器（仅 debug）。
 * @param {() => string} options.getOrigin - `ctx.webServer.getOrigin()`（每次现取）。
 * @param {(url: string) => string} options.getAuthenticatedUrl - `ctx.connection.authenticatedUrl`。
 * @returns {object} 上游适配器。
 */
export function createUpstream({ config, log, audit, getOrigin, getAuthenticatedUrl }) {
  /** @type {{ name: string, value: string }|undefined} */
  let cookie
  /** 上游 origin（`http://127.0.0.1:<port>`），每次请求现取以避免端口变化。 */
  let originText = ''
  /** @type {Promise<void>|undefined} 单飞交换。 */
  let exchangePromise
  /** 最近一次交换是否成功（`/m/ping` 与面板自检用）。 */
  let cookieOk = false
  /** 最近一次交换的错误文本（诊断用）。 */
  let lastError = ''

  /**
   * 解析当前上游地址。
   * @returns {{ origin: string, authority: string, hostname: string, port: number, protocol: string }} 地址。
   */
  function target() {
    let raw
    try {
      raw = getOrigin()
    } catch (error) {
      throw new RmError('rm/upstream', `拿不到上游地址（webServer 可能还没 listen）：${String(error?.message ?? error)}`)
    }
    if (typeof raw !== 'string' || raw === '') throw new RmError('rm/upstream', 'webServer.getOrigin() 返回空值')
    originText = raw.replace(/\/+$/, '')
    let url
    try {
      url = new URL(originText)
    } catch {
      throw new RmError('rm/upstream', `webServer.getOrigin() 返回的不是合法 URL：${raw}`)
    }
    const defaultPort = url.protocol === 'https:' ? 443 : 80
    return {
      origin: url.origin,
      authority: url.host,
      hostname: url.hostname,
      port: url.port === '' ? defaultPort : Number(url.port),
      protocol: url.protocol,
    }
  }

  /**
   * 做一次 cookie 交换（`GET /?token=…`，不跟随重定向）。
   * @returns {Promise<void>} 完成。
   */
  async function exchange() {
    const upstream = target()
    let tokenUrl
    try {
      tokenUrl = new URL(getAuthenticatedUrl(`${upstream.origin}/`))
    } catch (error) {
      throw new RmError('rm/upstream', `authenticatedUrl() 失败：${String(error?.message ?? error)}`)
    }
    const expectedName = cookieNameFor(upstream.authority)
    const headers = {
      host: upstream.authority,
      connection: 'close',
      'user-agent': 'dsh-plugin-remote-mobile',
    }
    const res = await rawRequest({
      upstream,
      path: `${tokenUrl.pathname}${tokenUrl.search}`,
      method: 'GET',
      headers,
    })
    // 丢弃 body：交换只需要 Set-Cookie。
    const status = res.statusCode ?? 0
    res.resume()
    const found = pickAuthCookie(res.headers['set-cookie'])
    if (found === undefined) {
      cookieOk = false
      lastError = `上游返回 ${status} 但没有 dsh-auth-* cookie`
      throw new RmError('rm/upstream', `cookie 交换失败：${lastError}`)
    }
    if (found.name !== expectedName) {
      // 名字对不上说明 authority 算错了（Host 头与 getOrigin 不一致），
      // 这种 cookie 之后每次都会被 401，必须立刻暴露。
      cookieOk = false
      lastError = `cookie 名不匹配：期望 ${expectedName}，上游给了 ${found.name}`
      throw new RmError('rm/upstream', lastError)
    }
    cookie = found
    cookieOk = true
    lastError = ''
    audit.debug('cookie-exchanged', { upstream: upstream.origin, status })
    log('info', `remote-mobile: 上游 cookie 已就绪（${upstream.origin}）`)
  }

  /**
   * 确保有可用 cookie；单飞，失败只记录不抛（真正的错在请求里暴露）。
   * @param {boolean} [force] - 强制重新交换。
   * @returns {Promise<boolean>} 是否可用。
   */
  async function ensureCookie(force = false) {
    if (!force && cookie !== undefined) return true
    if (exchangePromise === undefined) {
      exchangePromise = exchange()
        .catch((error) => {
          cookieOk = false
          lastError = String(error?.message ?? error)
          log('warn', `remote-mobile: cookie 交换失败：${lastError}`)
          audit.debug('cookie-exchange-failed', { message: lastError })
        })
        .finally(() => {
          exchangePromise = undefined
        })
    }
    await exchangePromise
    return cookie !== undefined
  }

  /**
   * 上游 cookie 的 `name=value`（WS 握手与请求头注入共用）。
   * @returns {string|undefined} cookie 字符串。
   */
  function cookieHeader() {
    return cookie === undefined ? undefined : `${cookie.name}=${cookie.value}`
  }

  /**
   * 发请求到上游，401 时**重交换一次再重试**（PROTOCOL §0）。
   *
   * @param {object} options - 参数。
   * @param {string} options.path - 路径 + 查询串。
   * @param {string} [options.method] - 方法。
   * @param {Record<string, string>} [options.headers] - 已经改写好的上游 header。
   * @param {Buffer} [options.body] - 请求体；有 body 时才能安全重试。
   * @param {boolean} [options.retryOn401] - 是否允许 401 重试（默认 true）。
   * @param {number} [options.timeoutMs] - 超时。
   * @returns {Promise<import('node:http').IncomingMessage>} 上游响应（调用方负责消费/销毁）。
   */
  async function send({ path, method = 'GET', headers = {}, body, retryOn401 = true, timeoutMs = REQUEST_TIMEOUT_MS }) {
    const upstream = target()
    await ensureCookie()
    const withCookie = (base) => {
      const next = { ...base }
      const value = cookieHeader()
      if (value !== undefined) next.cookie = value
      return next
    }
    let res = await rawRequest({ upstream, path, method, headers: withCookie(headers), body, timeoutMs })
    if (res.statusCode !== 401 || retryOn401 !== true) return res
    // 401：可能 token 变了或 cookie 过期，重交换一次再重试（只一次）。
    audit.debug('upstream-401-retry', { path, method })
    res.destroy()
    const refreshed = await ensureCookie(true)
    if (refreshed !== true) {
      // 拿不到新 cookie 就把这次失败如实抛出去。
      throw new RmError('rm/upstream', `上游 401 且 cookie 重交换失败：${lastError}`)
    }
    res = await rawRequest({ upstream, path, method, headers: withCookie(headers), body, timeoutMs })
    return res
  }

  return {
    /** 当前上游 origin（可能为空字符串，表示还没取过）。 */
    get origin() {
      return originText
    },

    /** 当前上游 authority。 */
    authority() {
      return target().authority
    },

    /**
     * 上游直连参数（WS 握手用：`net.connect` 需要 hostname/port，cookie 要拼进头）。
     * @returns {{ hostname: string, port: number, authority: string, origin: string, cookie?: string }} 参数。
     */
    endpoint() {
      const upstream = target()
      return {
        hostname: upstream.hostname,
        port: upstream.port,
        authority: upstream.authority,
        origin: upstream.origin,
        ...(cookieHeader() === undefined ? {} : { cookie: cookieHeader() }),
      }
    },

    /** 上游 origin。 */
    origin() {
      return target().origin
    },

    cookieHeader,
    send,
    cookieName: () => (cookie === undefined ? undefined : cookie.name),
    get cookieOk() {
      return cookieOk
    },
    get lastError() {
      return lastError
    },

    /**
     * 启动时预热：交换一次 cookie（失败只告警，不阻塞插件加载）。
     * @returns {Promise<boolean>} 是否成功。
     */
    async ensure() {
      return ensureCookie(cookie === undefined)
    },

    /**
     * 自检（PC 面板「自检」按钮，PROTOCOL §2 的 `selftest`）。
     *
     * 用一个最小的 `session/list` 请求确认：上游可达 + cookie 有效。
     * @returns {Promise<{ upstream: string, cookieOk: boolean, upstreamOk: boolean, ms: number, error?: string }>} 结果。
     */
    async probe() {
      const started = Date.now()
      /** @type {string} */
      let upstreamText = ''
      try {
        const upstream = target()
        upstreamText = upstream.origin
        await ensureCookie(true)
        const body = Buffer.from(JSON.stringify({
          type: 'client-request',
          rpcId: `remote-mobile-probe-${Date.now()}`,
          method: 'session/list',
          payload: { args: { _request: {} } },
        }), 'utf8')
        const res = await send({
          path: '/api/session/list',
          method: 'POST',
          headers: {
            host: upstream.authority,
            origin: upstream.origin,
            'content-type': 'application/json',
            'content-length': String(body.length),
            connection: 'close',
          },
          body,
          timeoutMs: 8_000,
        })
        const status = res.statusCode ?? 0
        res.resume()
        return {
          upstream: upstreamText,
          cookieOk,
          upstreamOk: status === 200,
          ms: Date.now() - started,
          ...(status === 200 ? {} : { error: `上游 /api/session/list 返回 ${status}` }),
        }
      } catch (error) {
        return {
          upstream: upstreamText,
          cookieOk,
          upstreamOk: false,
          ms: Date.now() - started,
          error: String(error?.message ?? error),
        }
      }
    },

    /** 供测试/诊断使用：清掉内存里的 cookie。 */
    clearCookie() {
      cookie = undefined
      cookieOk = false
    },
  }
}

/**
 * 流式转发用：把手机请求体 pipe 给上游时用不到缓冲区，但仍然要限长。
 * 这里只导出常量，实际判断在监听器里。
 */
export const UPSTREAM_STREAM_TIMEOUT_MS = STREAM_TIMEOUT_MS
