/**
 * PC 面板 RPC：`POST /plugin/remote-mobile/rpc`（PROTOCOL §2）。
 *
 * 挂在 `ctx.webServer` 上，**先** `ctx.connection.requestRejection(req)` 拒绝外部来源——
 * 这个端点只给本机 SPA 用，任何从局域网打进来的请求都必须被鉴权层挡掉。
 *
 * 响应统一 `{ok:true, data}` / `{ok:false, error:{code,message}}`，HTTP 200
 * （只有鉴权失败回 401/403）。
 *
 * @module dsh-plugin-remote-mobile/admin
 */

import { RmError, failureBody, statusForError } from '../config.js'

/** 端点路径。 */
export const RPC_PATH = '/plugin/remote-mobile/rpc'

/** RPC body 上限。 */
const RPC_BODY_LIMIT = 1024 * 1024

/** 每个 JSON 响应都带上。 */
const NO_STORE = Object.freeze({
  'cache-control': 'no-store',
  'x-content-type-options': 'nosniff',
})

/** 全部支持的 op（PROTOCOL §2 的表）。 */
export const RPC_OPS = Object.freeze([
  'status',
  'set.enabled',
  'pair.create',
  'pair.cancel',
  'devices.list',
  'devices.rename',
  'devices.revoke',
  'devices.revokeAll',
  'devices.readonly',
  'kill',
  'audit.head',
  'selftest',
])

/**
 * 是否是普通对象。
 * @param {unknown} value - 任意值。
 * @returns {boolean} 结论。
 */
function isRecord(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

/**
 * 写 JSON 响应。
 * @param {import('node:http').ServerResponse} res - 响应。
 * @param {number} status - 状态码。
 * @param {unknown} body - 内容。
 * @returns {void}
 */
function json(res, status, body) {
  if (res.writableEnded || res.destroyed) return
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', ...NO_STORE })
  res.end(JSON.stringify(body))
}

/**
 * 读 body（有上限）。
 * @param {import('node:http').IncomingMessage} req - 请求。
 * @returns {Promise<Record<string, unknown>>} 解析结果。
 */
function readJson(req) {
  return new Promise((resolve, reject) => {
    /** @type {Buffer[]} */
    const chunks = []
    let size = 0
    let settled = false
    req.on('data', (chunk) => {
      if (settled) return
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)
      size += buffer.length
      if (size > RPC_BODY_LIMIT) {
        settled = true
        req.pause()
        reject(new RmError('rm/too-large', `RPC body 超过 ${RPC_BODY_LIMIT} 字节`))
        return
      }
      chunks.push(buffer)
    })
    req.on('end', () => {
      if (settled) return
      settled = true
      const text = Buffer.concat(chunks).toString('utf8')
      if (text.trim() === '') {
        resolve({})
        return
      }
      let parsed
      try {
        parsed = JSON.parse(text)
      } catch (error) {
        reject(new RmError('rm/bad-request', `RPC body 不是合法 JSON：${String(error?.message ?? error).slice(0, 160)}`))
        return
      }
      if (!isRecord(parsed)) {
        reject(new RmError('rm/bad-request', 'RPC body 必须是 JSON 对象'))
        return
      }
      resolve(parsed)
    })
    req.on('error', (error) => {
      if (settled) return
      settled = true
      reject(new RmError('rm/bad-request', `读取 RPC body 失败：${String(error?.message ?? error)}`))
    })
  })
}

/**
 * 读一个必填字符串字段。
 * @param {Record<string, unknown>} payload - payload。
 * @param {string} key - 键名。
 * @param {number} [max] - 最大长度。
 * @returns {string} 值。
 */
function needString(payload, key, max = 200) {
  const value = payload[key]
  if (typeof value !== 'string' || value.trim() === '') {
    throw new RmError('rm/bad-request', `payload.${key} 必须是非空字符串`)
  }
  const trimmed = value.trim()
  if (trimmed.length > max) throw new RmError('rm/bad-request', `payload.${key} 超过 ${max} 字符`)
  return trimmed
}

/**
 * 挂上 PC 面板 RPC。
 *
 * @param {object} ctx - 携带 `webServer` 的 Cordis 上下文（`ctx.inject(['webServer'], …)` 的子作用域）。
 * @param {object} deps - 依赖。
 * @param {object} deps.connection - `ctx.connection`（用于 `requestRejection`）。
 * @param {object} deps.devices - 设备表。
 * @param {object} deps.pairing - 配对服务。
 * @param {object} deps.approvals - 审批队列。
 * @param {() => object|undefined} deps.getUpstream - 上游适配器取值器。
 * @param {ReturnType<import('../audit.js').createAudit>} deps.audit - 审计器。
 * @param {object} deps.runtime - 运行时控制（index.js 提供）。
 * @param {() => object} deps.runtime.status - 组装 status。
 * @param {(enabled: boolean) => Promise<object>} deps.runtime.setEnabled - 开关监听器。
 * @param {() => Promise<{ closed: number }>} deps.runtime.kill - kill switch。
 * @param {(deviceId: string) => number} deps.runtime.closeDeviceSockets - 断开某设备连接。
 * @param {(code: string, ttlSec?: number) => object} deps.runtime.pairUrls - 生成配对 URL。
 * @param {(level: 'debug'|'info'|'warn'|'error', message: string) => void} deps.log - 日志。
 * @returns {() => void} 注销器。
 */
export function registerRoutes(ctx, deps) {
  const webServer = ctx.get('webServer')
  if (webServer === undefined || typeof webServer.register !== 'function') {
    throw new Error('remote-mobile: webServer 服务不可用，无法注册 PC 面板 RPC')
  }

  /** op → 实现。 */
  const handlers = {
    async status() {
      return deps.runtime.status()
    },

    async 'set.enabled'(payload) {
      const value = payload.enabled
      if (typeof value !== 'boolean') {
        throw new RmError('rm/bad-request', 'payload.enabled 必须是布尔值')
      }
      return deps.runtime.setEnabled(value)
    },

    async 'pair.create'(payload) {
      const ttlSec = payload.ttlSec
      if (ttlSec !== undefined && (typeof ttlSec !== 'number' || !Number.isFinite(ttlSec) || ttlSec < 10 || ttlSec > 900)) {
        throw new RmError('rm/bad-request', 'payload.ttlSec 必须是 10..900 的整数')
      }
      // ttlSec 必须真的传下去：校验过却不用，等于给面板一个假的有效期。
      const code = deps.pairing.create(ttlSec)
      const urls = deps.runtime.pairUrls(code.code)
      return { code: code.code, expiresAt: code.expiresAt, ttlSec: code.ttlSec, urls }
    },

    async 'pair.cancel'() {
      return deps.pairing.cancel()
    },

    async 'devices.list'() {
      return { devices: deps.devices.list() }
    },

    async 'devices.rename'(payload) {
      const id = needString(payload, 'id', 64)
      const name = needString(payload, 'name', 60)
      await deps.devices.rename(id, name)
      return { ok: true }
    },

    async 'devices.revoke'(payload) {
      const id = needString(payload, 'id', 64)
      await deps.devices.revoke(id)
      const revokedSockets = deps.runtime.closeDeviceSockets(id)
      return { ok: true, revokedSockets }
    },

    async 'devices.revokeAll'(payload) {
      // 不可恢复：先撤设备表，再断开全部在途连接（让已连手机立刻失效）。
      const revoked = await deps.devices.revokeAll()
      const closedSockets = deps.runtime.closeAllDeviceSockets()
      deps.audit.audit({ kind: 'devices-revoke-all', detail: `revoked ${revoked} device(s), closed ${closedSockets} socket(s)` })
      // PROTOCOL §2：`devices.revokeAll` → `{ok, revoked}`（socket 数只进审计）。
      return { ok: true, revoked }
    },

    async 'devices.readonly'(payload) {
      const id = needString(payload, 'id', 64)
      if (typeof payload.readonly !== 'boolean') {
        throw new RmError('rm/bad-request', 'payload.readonly 必须是布尔值')
      }
      await deps.devices.setReadonly(id, payload.readonly)
      // 只读切换立即生效：只读时断开该设备在途的流连接，逼它重新按新策略连。
      const revokedSockets = payload.readonly === true ? deps.runtime.closeDeviceSockets(id) : 0
      return { ok: true, revokedSockets }
    },

    async kill() {
      const result = await deps.runtime.kill()
      return { ok: true, closed: result.closed }
    },

    async 'audit.head'(payload) {
      const n = payload.n
      if (n !== undefined && (typeof n !== 'number' || !Number.isFinite(n) || n < 1)) {
        throw new RmError('rm/bad-request', 'payload.n 必须是正整数')
      }
      const lines = await deps.audit.head(typeof n === 'number' ? n : 100)
      return { lines }
    },

    async selftest() {
      const upstream = deps.getUpstream()
      if (upstream === undefined) {
        throw new RmError('rm/upstream', '上游适配器还没就绪（webServer 尚未挂载）')
      }
      return upstream.probe()
    },
  }

  const dispose = webServer.register({
    kind: 'exact',
    path: RPC_PATH,
    handler: (req, res) => {
      void (async () => {
        // ── 1. 桌面连接鉴权（fail-closed）──────────────────────────
        let rejection
        try {
          const connection = deps.connection ?? ctx.get?.('connection')
          if (connection === undefined || typeof connection.requestRejection !== 'function') {
            throw new Error('connection 服务不可用')
          }
          rejection = connection.requestRejection({ headers: req.headers })
        } catch (error) {
          deps.audit.debug('rpc-auth-unavailable', { message: String(error?.message ?? error) })
          json(res, 503, failureBody(new RmError('rm/internal', '桌面连接鉴权不可用，拒绝请求')))
          return
        }
        if (rejection !== undefined) {
          deps.audit.debug('rpc-rejected', { status: rejection, url: req.url })
          json(res, rejection, failureBody(new RmError('rm/unauthorized', '请求未通过桌面连接鉴权（只允许本机 SPA 调用）')))
          return
        }

        // ── 2. 方法与 body ─────────────────────────────────────────
        if ((req.method ?? 'GET').toUpperCase() !== 'POST') {
          json(res, 405, failureBody(new RmError('rm/bad-request', 'RPC 只接受 POST')))
          return
        }
        let body
        try {
          body = await readJson(req)
        } catch (error) {
          json(res, statusForError(error), failureBody(error))
          return
        }
        const op = typeof body.op === 'string' ? body.op.trim() : ''
        const handler = handlers[op]
        if (op === '' || handler === undefined) {
          json(res, 200, failureBody(new RmError(
            'rm/bad-request',
            `未知 op ${JSON.stringify(op)}；支持：${RPC_OPS.join(', ')}`,
          )))
          return
        }
        const payload = isRecord(body.payload) ? body.payload : {}
        try {
          const data = await handler(payload)
          json(res, 200, { ok: true, data })
        } catch (error) {
          const status = error?.httpStatus ?? statusForError(error)
          deps.audit.debug('rpc-error', {
            op,
            status,
            message: String(error?.message ?? error),
            stack: error?.code === undefined && typeof error?.stack === 'string' ? error.stack.slice(0, 2000) : undefined,
          })
          // 业务错误回 200（PROTOCOL §2：HTTP 200 除非鉴权失败）。
          json(res, status === 401 || status === 403 ? status : 200, failureBody(error))
        }
      })().catch((error) => {
        deps.audit.debug('rpc-crash', {
          url: req.url,
          message: String(error?.message ?? error),
          stack: typeof error?.stack === 'string' ? error.stack.slice(0, 4000) : undefined,
        })
        try {
          json(res, 500, failureBody(new RmError('rm/internal', `RPC 处理异常：${String(error?.message ?? error)}`)))
        } catch {
          // 响应已结束。
        }
      })
    },
  })

  deps.log('info', `remote-mobile: PC 面板 RPC 已挂载 ${RPC_PATH}`)
  return dispose
}
