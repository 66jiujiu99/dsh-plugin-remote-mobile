/**
 * `/m/*` 整站反代：把 DSH Web 端整站搬到手机前缀下。
 *
 * 设计目标（用户明确要求「直接照 Web 端做」）：
 *   - 手机访问 `/m/` → 上游 `/`，拿到的是**完整的 DSH Web UI**，
 *     因此工作区分组、插件设置、Agent 运行时排队提示等功能**自动具备**，
 *     上游加新功能时手机端也跟着走，不需要维护第二套界面。
 *   - 鉴权不放松：仍然要求设备 cookie（配对过），由调用方在进来之前校验。
 *
 * 三个必须处理的技术点：
 *
 * 1. **前缀剥离**：手机 `/m/foo` → 上游 `/foo`。
 *    不做的话上游收到 `/m/foo` 会 404。
 *
 * 2. **重定向改写**：上游 3xx 的 `Location` 是上游视角（`/login`），
 *    手机需要回到前缀下（`/m/login`）。绝对 URL 只改同源的那些。
 *
 * 3. **cookie 隔离**：
 *    - 上游 `Set-Cookie`（`dsh-auth-*`）**绝不能**交给手机，那是 PC 的凭据；
 *    - 手机的设备 cookie 也**绝不能**发给上游。
 *    这两条是安全边界，不是优化。
 *
 * 另外：上游要求 `Host` 与自己的 authority 一致（否则 401），
 * 所以无论手机用什么域名访问，转发时都改写成上游 authority。
 *
 * @module dsh-plugin-remote-mobile/proxy-site
 */

import http from 'node:http'

/** 需要剥掉的逐跳头（RFC 7230 §6.1）：这些只对单跳连接有意义。 */
const HOP_BY_HOP = Object.freeze([
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
 * 请求方向还要额外剥掉的头。
 *
 * - `host`：必须改写成上游 authority，否则上游按 Host 判定 401。
 * - `cookie`：手机的设备 cookie 不能泄漏给上游（上游只认它自己的 `dsh-auth-*`）。
 * - `authorization`：同理，手机的凭据不该出现在上游请求里。
 * - `content-length`：body 可能被改写，长度由我们自己给。
 * - `accept-encoding`：保留会让上游返回 gzip/br，我们只做字节搬运不解析，
 *   虽然能原样转回去，但一旦要改写 HTML 就必须先解压。这里统一要求 identity，
 *   换取「想改就能改」的自由；对 localhost 上游几乎没有带宽代价。
 */
const REQUEST_EXTRA_STRIP = Object.freeze([
  'host',
  'cookie',
  'authorization',
  'content-length',
  'accept-encoding',
])

/**
 * 响应方向还要额外剥掉的头。
 *
 * - `set-cookie`：上游凭据绝不能下发到手机（安全边界）。
 * - `content-security-policy` 与 `x-frame-options`：上游按自身 origin 签发，
 *   在 `/m/` 前缀下会误伤（尤其 frame-ancestors / form-action）。
 * - `strict-transport-security`：经隧道时由隧道层负责，这里下发会锁死 http 调试。
 */
const RESPONSE_EXTRA_STRIP = Object.freeze([
  'set-cookie',
  'content-security-policy',
  'content-security-policy-report-only',
  'x-frame-options',
  'strict-transport-security',
])

/**
 * 把这些头合并成一个「要剥掉的名字」集合。
 * @param {readonly string[]} extra - 额外的名字。
 * @returns {Set<string>} 合并后的集合。
 */
function stripSet(extra) {
  const set = new Set(HOP_BY_HOP)
  for (const name of extra) set.add(name)
  return set
}

const STRIP_REQUEST = stripSet(REQUEST_EXTRA_STRIP)
const STRIP_RESPONSE = stripSet(RESPONSE_EXTRA_STRIP)

/**
 * 判断一个路径是否属于本站前缀。
 * @param {string} pathname - 已解析的路径。
 * @param {string} prefix - 前缀，如 `/m`。
 * @returns {boolean} 是否属于。
 */
export function isUnderPrefix(pathname, prefix) {
  if (typeof pathname !== 'string') return false
  return pathname === prefix || pathname.startsWith(`${prefix}/`)
}

/**
 * 剥掉前缀：`/m` → `/`，`/m/a/b?x=1` → `/a/b?x=1`。
 *
 * 注意保留查询串：上游的路由（例如 `?sessionId=`）依赖它。
 *
 * @param {string} rawUrl - 客户端原始 `req.url`（含查询串）。
 * @param {string} prefix - 前缀，如 `/m`。
 * @returns {string} 上游路径。
 */
export function stripPrefix(rawUrl, prefix) {
  const text = typeof rawUrl === 'string' && rawUrl !== '' ? rawUrl : '/'
  if (!text.startsWith(prefix)) return text
  const rest = text.slice(prefix.length)
  if (rest === '') return '/'
  if (rest.startsWith('?')) return `/${rest}`
  // 前缀后必须紧跟 `/`（`/mx` 不该被当成 `/m` 下的路径）。
  if (!rest.startsWith('/')) return text
  return rest
}

/**
 * 改写 `Location`：把上游视角的重定向改回手机前缀下。
 *
 * 三种情况：
 *   1. 站内相对路径（`/foo`）→ 加前缀（`/m/foo`）。
 *   2. 已经带前缀（`/m/foo`）→ 原样（避免二次叠加）。
 *   3. 绝对 URL → 仅当同源时改写路径；跨域绝对 URL 原样保留。
 *
 * @param {string} location - 上游给的 `Location`。
 * @param {string} prefix - 站点前缀。
 * @param {string} upstreamOrigin - 上游 origin，如 `http://127.0.0.1:1234`。
 * @returns {string} 改写后的 `Location`。
 */
export function rewriteLocation(location, prefix, upstreamOrigin) {
  if (typeof location !== 'string' || location === '') return location
  // 绝对 URL：只改同源。
  if (/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(location)) {
    let parsed
    try {
      parsed = new URL(location)
    } catch {
      return location
    }
    let upstream
    try {
      upstream = new URL(upstreamOrigin)
    } catch {
      return location
    }
    if (parsed.origin !== upstream.origin) return location
    const pathPart = `${parsed.pathname}${parsed.search}${parsed.hash}`
    return `${prefix}${pathPart.startsWith(prefix) ? pathPart.slice(prefix.length) : pathPart.startsWith('/') ? pathPart : `/${pathPart}`}`
  }
  // 协议相对（`//host/path`）：同源时同样改写。
  if (location.startsWith('//')) {
    let upstream
    try {
      upstream = new URL(upstreamOrigin)
    } catch {
      return location
    }
    return `//${upstream.host}${rewriteLocation(`${upstream.protocol}${location}`, prefix, upstreamOrigin)}`
  }
  // 纯站内路径。
  if (location.startsWith('/')) {
    if (location === prefix || location.startsWith(`${prefix}/`)) return location
    return `${prefix}${location}`
  }
  // 相对路径（`foo`、`../bar`）：浏览器会按当前 URL 解析，前缀天然保留。
  return location
}

/**
 * 构造发给上游的请求头。
 *
 * @param {Record<string, unknown>} input - 手机请求头。
 * @param {object} options - 改写规则。
 * @param {string} options.authority - 上游 authority（写进 `Host`）。
 * @param {string} options.origin - 上游 origin（写进 `Origin`）。
 * @param {string} [options.cookie] - 上游 cookie 的 `name=value`。
 * @param {Buffer|undefined} [options.body] - 请求体（用于给 content-length）。
 * @returns {Record<string, string|string[]>} 上游请求头。
 */
export function buildUpstreamHeaders(input, { authority, origin, cookie, body }) {
  /** @type {Record<string, string|string[]>} */
  const output = {}
  for (const [rawName, rawValue] of Object.entries(input ?? {})) {
    const name = rawName.toLowerCase()
    if (STRIP_REQUEST.has(name)) continue
    if (name.startsWith('sec-fetch-')) continue
    if (name.startsWith('x-forwarded-')) continue
    if (rawValue === undefined) continue
    output[name] = Array.isArray(rawValue) ? rawValue.map(String) : String(rawValue)
  }
  output.host = authority
  output.origin = origin
  if (typeof cookie === 'string' && cookie !== '') output.cookie = cookie
  output.connection = 'close'
  if (body !== undefined) output['content-length'] = String(body.length)
  return output
}

/**
 * 构造回给手机的响应头。
 *
 * @param {Record<string, unknown>} input - 上游响应头。
 * @param {object} [options] - 改写规则。
 * @param {string} [options.prefix] - 站点前缀（用于改写 `Location`）。
 * @param {string} [options.upstreamOrigin] - 上游 origin（用于判断同源）。
 * @returns {Record<string, string|string[]>} 给手机的响应头。
 */
export function buildDownstreamHeaders(input, { prefix, upstreamOrigin } = {}) {
  /** @type {Record<string, string|string[]>} */
  const output = {}
  for (const [rawName, rawValue] of Object.entries(input ?? {})) {
    const name = rawName.toLowerCase()
    if (STRIP_RESPONSE.has(name)) continue
    if (rawValue === undefined) continue
    if (name === 'location' && typeof prefix === 'string' && typeof upstreamOrigin === 'string') {
      const single = Array.isArray(rawValue) ? String(rawValue[0]) : String(rawValue)
      output.location = rewriteLocation(single, prefix, upstreamOrigin)
      continue
    }
    output[name] = Array.isArray(rawValue) ? rawValue.map(String) : String(rawValue)
  }
  return output
}

/**
 * 读干一个请求体（有上限）。
 *
 * @param {import('node:http').IncomingMessage} req - 手机请求。
 * @param {number} limit - 字节上限。
 * @returns {Promise<Buffer>} 请求体。
 */
export function readRequestBody(req, limit) {
  return new Promise((resolve, reject) => {
    /** @type {Buffer[]} */
    const chunks = []
    let total = 0
    req.on('data', (chunk) => {
      total += chunk.length
      if (total > limit) {
        reject(new Error(`请求体超过上限（${limit} 字节）`))
        req.destroy()
        return
      }
      chunks.push(chunk)
    })
    req.on('end', () => resolve(Buffer.concat(chunks)))
    req.on('error', reject)
  })
}

/**
 * 把一次手机请求整站转发到上游。
 *
 * 流式转发：上游响应一到达就写头，随后逐块 pipe，不整块缓冲
 * （DSH 的会话列表、SSE、大截图都走这条路径）。
 *
 * @param {object} options - 参数。
 * @param {import('node:http').IncomingMessage} options.req - 手机请求。
 * @param {import('node:http').ServerResponse} options.res - 手机响应。
 * @param {object} options.upstream - `createUpstream()` 返回值。
 * @param {string} options.prefix - 站点前缀，如 `/m`。
 * @param {number} options.bodyLimit - 请求体上限。
 * @param {(level: string, message: string) => void} [options.log] - 日志。
 * @returns {Promise<void>} 完成（响应已写完或已断开）。
 */
export async function proxySiteRequest({ req, res, upstream, prefix, bodyLimit, log }) {
  const method = (req.method ?? 'GET').toUpperCase()
  const upstreamPath = stripPrefix(req.url ?? '/', prefix)

  // GET/HEAD 不带 body；其余方法读进来（上游用的是 loopback，body 一般不巨大，
  // 上传走的是独立的 /m/api/upload 端点，不经过这里）。
  let body
  if (method !== 'GET' && method !== 'HEAD') {
    try {
      body = await readRequestBody(req, bodyLimit)
    } catch (error) {
      res.writeHead(413, { 'content-type': 'text/plain; charset=utf-8', connection: 'close' })
      res.end(`remote-mobile: ${String(error?.message ?? error)}`)
      return
    }
  }

  let upstreamRes
  try {
    upstreamRes = await upstream.send({
      path: upstreamPath,
      method,
      headers: buildUpstreamHeaders(req.headers, {
        authority: upstream.authority(),
        origin: upstream.origin(),
        cookie: upstream.cookieHeader(),
        body,
      }),
      body,
    })
  } catch (error) {
    log?.('warn', `remote-mobile: 整站反代失败 ${method} ${upstreamPath}: ${String(error?.message ?? error)}`)
    if (!res.writableEnded && !res.destroyed) {
      res.writeHead(502, { 'content-type': 'text/plain; charset=utf-8', connection: 'close' })
      res.end(`remote-mobile: 转发到上游失败：${String(error?.message ?? error)}`)
    }
    return
  }

  if (res.writableEnded || res.destroyed) {
    upstreamRes.destroy()
    return
  }

  res.writeHead(
    upstreamRes.statusCode ?? 502,
    buildDownstreamHeaders(upstreamRes.headers, { prefix, upstreamOrigin: upstream.origin() }),
  )

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
