/**
 * PC 面板 RPC 的接线（lib/admin/routes.js）。
 *
 * 不启真 Host：用假 `webServer.register` 拿到 handler，再用假 req/res 驱动，
 * 覆盖「鉴权先行 → 方法校验 → op 分发 → 统一响应体」这条链，以及 `kill` /
 * `devices.revoke` 与运行时回调的衔接。
 */

import assert from 'node:assert/strict'
import { Readable } from 'node:stream'
import test from 'node:test'

import { registerRoutes, RPC_PATH } from '../lib/admin/routes.js'

/**
 * 造一个最小的假 req。
 * @param {object} options - 参数。
 * @returns {object} req。
 */
function fakeRequest({ method = 'POST', body = '', headers = {} } = {}) {
  const stream = Readable.from(body === '' ? [] : [Buffer.from(body, 'utf8')])
  const req = /** @type {any} */ (stream)
  req.method = method
  req.url = RPC_PATH
  req.headers = headers
  return req
}

/**
 * 造一个最小的假 res。
 * @returns {object} res（带 status/headers/body 快照）。
 */
function fakeResponse() {
  return {
    status: 0,
    headers: {},
    body: '',
    writableEnded: false,
    destroyed: false,
    writeHead(status, headers) {
      this.status = status
      this.headers = { ...headers }
    },
    end(body) {
      this.body = typeof body === 'string' ? body : body?.toString?.('utf8') ?? ''
      this.writableEnded = true
    },
  }
}

/**
 * 建一套假依赖并注册路由。
 * @param {object} [overrides] - 覆盖项。
 * @returns {object} 测试句柄。
 */
function setup(overrides = {}) {
  /** @type {Function|undefined} */
  let handler
  const ctx = {
    get(name) {
      if (name !== 'webServer') return undefined
      return {
        register(options) {
          handler = options.handler
          return () => {
            handler = undefined
          }
        },
      }
    },
  }
  const calls = {
    setEnabled: [],
    kill: 0,
    closeDeviceSockets: [],
    closeAllDeviceSockets: 0,
    renames: [],
    revoked: [],
    revokeAll: 0,
    readonly: [],
    probed: 0,
    pairCreated: 0,
    pairTtlSec: [],
  }
  const devices = {
    list: () => [{ id: 'd1', name: '手机', online: true, readonly: false }],
    rename: async (id, name) => { calls.renames.push([id, name]) },
    revoke: async (id) => { calls.revoked.push(id) },
    revokeAll: async () => { calls.revokeAll += 1; return 2 },
    setReadonly: async (id, value) => { calls.readonly.push([id, value]) },
  }
  const deps = {
    connection: {
      requestRejection: () => overrides.rejection,
    },
    devices,
    pairing: {
      create: (ttlSec) => {
        calls.pairCreated += 1
        calls.pairTtlSec.push(ttlSec)
        return { code: '123456', expiresAt: 42, ttlSec: ttlSec ?? 60 }
      },
      cancel: () => ({ ok: true }),
    },
    approvals: { pending: () => 0 },
    getUpstream: () => ({ probe: async () => { calls.probed += 1; return { upstream: 'x', cookieOk: true, upstreamOk: true, ms: 1 } } }),
    audit: { debug() {}, audit() {}, head: async (n) => [`{"kind":"pair","n":${n}}`] },
    runtime: {
      status: () => ({ enabled: true, port: 17890, urls: [], lanIps: [], devices: [], pendingApprovals: 0, killSwitch: false }),
      setEnabled: async (value) => { calls.setEnabled.push(value); return { enabled: value, port: 17890, urls: [] } },
      kill: async () => { calls.kill += 1; return { closed: 3 } },
      closeDeviceSockets: (id) => { calls.closeDeviceSockets.push(id); return 2 },
      closeAllDeviceSockets: () => { calls.closeAllDeviceSockets += 1; return 4 },
      pairUrls: (code) => [`http://192.168.1.5:17890/m/pair?c=${code}`],
    },
    log: () => {},
    ...overrides.deps,
  }
  registerRoutes(ctx, deps)
  assert.notEqual(handler, undefined, 'registerRoutes 应该注册到 webServer')

  /**
   * 调一次 RPC。
   * @param {object} options - 请求。
   * @returns {Promise<{ status: number, json: any }>} 结果。
   */
  async function call({ method = 'POST', body, headers = {} } = {}) {
    const req = fakeRequest({ method, body: body === undefined ? '' : JSON.stringify(body), headers })
    const res = fakeResponse()
    handler(req, res)
    // handler 内部是 fire-and-forget 的 async，等到 res 结束。
    for (let index = 0; index < 200 && !res.writableEnded; index += 1) {
      await new Promise((resolve) => setTimeout(resolve, 5))
    }
    let parsed
    try {
      parsed = JSON.parse(res.body)
    } catch {
      parsed = undefined
    }
    return { status: res.status, json: parsed }
  }

  return { call, calls }
}

test('鉴权先行：requestRejection 返回状态时直接拒绝，不执行 op', async () => {
  const { call, calls } = setup({
    rejection: 403,
    deps: undefined,
  })
  const result = await call({ body: { op: 'kill' } })
  assert.equal(result.status, 403)
  assert.equal(result.json.ok, false)
  assert.equal(result.json.error.code, 'rm/unauthorized')
  assert.equal(calls.kill, 0)
})

test('非 POST → 405；未知 op → 200 + rm/bad-request', async () => {
  const { call } = setup()
  const getRes = await call({ method: 'GET' })
  assert.equal(getRes.status, 405)
  const unknown = await call({ body: { op: 'nope' } })
  assert.equal(unknown.status, 200)
  assert.equal(unknown.json.ok, false)
  assert.equal(unknown.json.error.code, 'rm/bad-request')
  assert.match(unknown.json.error.message, /status/)
})

test('status / selftest / audit.head 走通', async () => {
  const { call, calls } = setup()
  const status = await call({ body: { op: 'status' } })
  assert.equal(status.status, 200)
  assert.equal(status.json.ok, true)
  assert.equal(status.json.data.port, 17890)

  const selftest = await call({ body: { op: 'selftest' } })
  assert.equal(selftest.json.data.upstreamOk, true)
  assert.equal(calls.probed, 1)

  const audit = await call({ body: { op: 'audit.head', payload: { n: 7 } } })
  assert.equal(audit.json.data.lines.length, 1)
  assert.match(audit.json.data.lines[0], /"n":7/)
})

test('set.enabled 校验布尔并调用运行时', async () => {
  const { call, calls } = setup()
  const bad = await call({ body: { op: 'set.enabled', payload: { enabled: 'yes' } } })
  assert.equal(bad.json.ok, false)
  assert.equal(bad.json.error.code, 'rm/bad-request')
  const good = await call({ body: { op: 'set.enabled', payload: { enabled: true } } })
  assert.equal(good.json.data.enabled, true)
  assert.deepEqual(calls.setEnabled, [true])
})

test('pair.create 返回 code/expiresAt/urls；payload 校验', async () => {
  const { call, calls } = setup()
  const created = await call({ body: { op: 'pair.create' } })
  assert.equal(created.json.data.code, '123456')
  assert.equal(created.json.data.expiresAt, 42)
  assert.match(created.json.data.urls[0], /\/m\/pair\?c=123456$/)
  assert.equal(created.json.data.ttlSec, 60)
  assert.equal(calls.pairCreated, 1)
  assert.deepEqual(calls.pairTtlSec, [undefined])

  // 自定义有效期必须真的传到 pairing（曾经被校验后丢弃，恒 60s）。
  const custom = await call({ body: { op: 'pair.create', payload: { ttlSec: 10 } } })
  assert.equal(custom.json.ok, true)
  assert.equal(custom.json.data.ttlSec, 10)
  assert.deepEqual(calls.pairTtlSec, [undefined, 10])

  const bad = await call({ body: { op: 'pair.create', payload: { ttlSec: 5 } } })
  assert.equal(bad.json.ok, false)
  assert.equal(bad.json.error.code, 'rm/bad-request')
})

test('devices.revoke / devices.readonly 会断开该设备连接', async () => {
  const { call, calls } = setup()
  const revoked = await call({ body: { op: 'devices.revoke', payload: { id: 'd1' } } })
  assert.equal(revoked.json.data.revokedSockets, 2)
  assert.deepEqual(calls.revoked, ['d1'])
  assert.deepEqual(calls.closeDeviceSockets, ['d1'])

  const readonly = await call({ body: { op: 'devices.readonly', payload: { id: 'd1', readonly: true } } })
  assert.equal(readonly.json.ok, true)
  assert.deepEqual(calls.readonly, [['d1', true]])
  // 只读切换也要断开在途流（否则旧连接还按旧策略跑）。
  assert.deepEqual(calls.closeDeviceSockets, ['d1', 'd1'])

  const rename = await call({ body: { op: 'devices.rename', payload: { id: 'd1', name: '  新名字  ' } } })
  assert.equal(rename.json.ok, true)
  assert.deepEqual(calls.renames, [['d1', '新名字']])

  const missing = await call({ body: { op: 'devices.rename', payload: { id: '' } } })
  assert.equal(missing.json.error.code, 'rm/bad-request')
})

test('kill 返回 {ok, closed} 且只调用一次运行时', async () => {
  const { call, calls } = setup()
  const result = await call({ body: { op: 'kill' } })
  assert.equal(result.status, 200)
  assert.equal(result.json.data.ok, true)
  assert.equal(result.json.data.closed, 3)
  assert.equal(calls.kill, 1)
})

test('业务错误回 200（HTTP 只在鉴权失败时非 200），但 op 抛 RmError 时带 code', async () => {
  const { call } = setup({
    deps: {
      runtime: {
        status: () => ({}),
        setEnabled: async () => ({ enabled: true, port: 1, urls: [] }),
        kill: async () => ({ closed: 0 }),
        closeDeviceSockets: () => 0,
        pairUrls: () => [],
      },
      devices: {
        list: () => [],
        rename: async () => {},
        revoke: async () => {
          const error = new Error('设备不存在或已撤销')
          error.code = 'rm/not-found'
          throw error
        },
        setReadonly: async () => {},
      },
    },
  })
  const result = await call({ body: { op: 'devices.revoke', payload: { id: 'ghost' } } })
  assert.equal(result.status, 200)
  assert.equal(result.json.ok, false)
  assert.equal(result.json.error.code, 'rm/not-found')
})

test('devices.revokeAll 撤销全部设备并断开全部连接', async () => {
  const { call, calls } = setup()
  const result = await call({ body: { op: 'devices.revokeAll' } })
  assert.equal(result.status, 200)
  assert.equal(result.json.ok, true)
  assert.equal(result.json.data.revoked, 2)
  assert.deepEqual(Object.keys(result.json.data).sort(), ['ok', 'revoked'])
  assert.equal(calls.revokeAll, 1)
  assert.equal(calls.closeAllDeviceSockets, 1)
})
