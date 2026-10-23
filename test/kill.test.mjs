/**
 * kill 语义集成测试（真 listener + 真 devices + 真 RPC 路由，假 ctx / 假上游）。
 *
 * 钉住三条产品事实（Lead 拍板，PROTOCOL §2）：
 *   1. `kill` 之后**设备表长度不变**（kill 不撤销设备，撤销是 `devices.revokeAll`）；
 *   2. `kill` 之后监听端口关闭、在途 socket 被 **destroy**（不是等对端 close）、
 *      旧端口立刻 ECONNREFUSED；
 *   3. 再 `set.enabled true` 能重新起来，且旧设备 cookie **仍然有效**（不用重新配对）。
 *
 * 用临时 `DSH_HOME` 隔离，绝不碰真实 `~/.dsh`。
 */

import assert from 'node:assert/strict'
import http from 'node:http'
import net from 'node:net'
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import { Readable } from 'node:stream'
import test from 'node:test'

import { apply } from '../index.js'
import { DEVICE_COOKIE, hashSecret } from '../lib/auth/devices.js'
import { cookieNameFor } from '../lib/net/upstream.js'

/** RPC 路径（与 lib/admin/routes.js 的 `RPC_PATH` 一致）。 */
const RPC_PATH = '/plugin/remote-mobile/rpc'

/** 设备 id / secret（写进 devices.json 的固定值）。 */
const DEVICE_ID = '0123456789abcdef'
const DEVICE_SECRET = 'f'.repeat(32)

/**
 * 等到条件成立（轮询，避免假定时器）。
 * @param {() => boolean|Promise<boolean>} predicate - 条件。
 * @param {number} [timeoutMs] - 超时。
 * @param {string} [what] - 失败说明。
 * @returns {Promise<void>} 完成。
 */
async function waitFor(predicate, timeoutMs = 5000, what = '条件') {
  const deadline = Date.now() + timeoutMs
  for (;;) {
    if (await predicate()) return
    if (Date.now() > deadline) throw new Error(`等待超时：${what}`)
    await new Promise((resolve) => setTimeout(resolve, 25))
  }
}

/**
 * 起一个假上游：`GET /?token=...` 回 `Set-Cookie: dsh-auth-<hash>`，其余 200。
 * @returns {Promise<{ origin: string, close: () => Promise<void> }>} 上游信息。
 */
async function startFakeUpstream() {
  /** @type {import('node:http').Server} */
  let server
  server = http.createServer((req, res) => {
    const authority = `127.0.0.1:${server.address().port}`
    // 名字必须与 authority 对得上，否则 upstream 会判定「cookie 名不匹配」。
    res.writeHead(200, { 'set-cookie': `${cookieNameFor(authority)}=fake; Path=/; HttpOnly` })
    res.end('ok')
  })
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  return {
    origin: `http://127.0.0.1:${server.address().port}`,
    close: () => new Promise((resolve) => server.close(() => resolve(undefined))),
  }
}

/**
 * 假 Cordis ctx：只为装配所需的最小面（effect / inject / get / logger / on）。
 * @param {string} origin - 假上游 origin。
 * @returns {{ ctx: object, routes: Map<string, Function>, disposeAll: () => Promise<void> }} 环境。
 */
function makeCtx(origin) {
  /** @type {Map<string, Function>} */
  const routes = new Map()
  /** @type {Array<Function>} */
  const disposers = []
  const webServer = {
    getOrigin: () => origin,
    register(options) {
      routes.set(options.path, options.handler)
      const dispose = () => {
        routes.delete(options.path)
      }
      return dispose
    },
  }
  const connection = {
    requestRejection: () => undefined,
    authenticatedUrl: (url) => `${url}?token=fake-token`,
  }
  const ctx = {
    logger: { debug() {}, info() {}, warn() {}, error() {} },
    effect(fn) {
      const dispose = fn()
      if (typeof dispose === 'function') disposers.push(dispose)
      return dispose
    },
    inject(_names, fn) {
      fn(ctx)
    },
    on() {
      return () => {}
    },
    get(name) {
      if (name === 'webServer') return webServer
      if (name === 'connection') return connection
      return undefined
    },
  }
  return {
    ctx,
    routes,
    disposeAll: async () => {
      for (const dispose of disposers.reverse()) {
        try {
          dispose()
        } catch {
          // 卸载期异常不关心。
        }
      }
      // 给 listener.stop() 的 close 回调一点时间。
      await new Promise((resolve) => setTimeout(resolve, 50))
    },
  }
}

/**
 * 调一次面板 RPC。
 * @param {Map<string, Function>} routes - 路由表。
 * @param {string} op - 操作名。
 * @param {unknown} [payload] - 参数。
 * @returns {Promise<{ status: number, json: any }>} 结果。
 */
function rpc(routes, op, payload) {
  const handler = routes.get(RPC_PATH)
  assert.notEqual(handler, undefined, 'RPC 路由应该已注册')
  return new Promise((resolve, reject) => {
    const req = Readable.from([Buffer.from(JSON.stringify({ op, payload }))])
    req.method = 'POST'
    req.url = RPC_PATH
    req.headers = { host: '127.0.0.1:1' }
    const out = { status: 0, json: undefined }
    const timer = setTimeout(() => reject(new Error(`RPC ${op} 超时`)), 5000)
    timer.unref?.()
    const res = {
      writableEnded: false,
      destroyed: false,
      writeHead(status) {
        out.status = status
      },
      end(chunk) {
        if (chunk) {
          try {
            out.json = JSON.parse(String(chunk))
          } catch {
            out.json = String(chunk)
          }
        }
        this.writableEnded = true
        clearTimeout(timer)
        resolve(out)
      },
    }
    Promise.resolve(handler(req, res)).catch((error) => {
      clearTimeout(timer)
      reject(error)
    })
  })
}

/**
 * 发一个 HTTP GET。
 * @param {number} port - 端口。
 * @param {string} pathname - 路径。
 * @param {Record<string,string>} [headers] - 额外头。
 * @returns {Promise<{ status: number, body: string }>} 响应。
 */
function get(port, pathname, headers = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({
      host: '127.0.0.1',
      port,
      path: pathname,
      method: 'GET',
      headers: { host: `127.0.0.1:${port}`, ...headers },
      timeout: 4000,
    }, (res) => {
      /** @type {Buffer[]} */
      const chunks = []
      res.on('data', (chunk) => chunks.push(Buffer.from(chunk)))
      res.on('end', () => resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString('utf8') }))
    })
    req.on('timeout', () => req.destroy(new Error('HTTP 超时')))
    req.on('error', reject)
    req.end()
  })
}

/**
 * 发一个 HTTP POST。
 * @param {number} port - 端口。
 * @param {string} pathname - 路径。
 * @param {{ headers?: Record<string,string>, body?: string }} [options] - 请求。
 * @returns {Promise<{ status: number, headers: object, body: string }>} 响应。
 */
function post(port, pathname, { headers = {}, body = '' } = {}) {
  return new Promise((resolve, reject) => {
    const payload = Buffer.from(body, 'utf8')
    const req = http.request({
      host: '127.0.0.1',
      port,
      path: pathname,
      method: 'POST',
      headers: {
        host: `127.0.0.1:${port}`,
        'content-length': String(payload.length),
        ...headers,
      },
      timeout: 4000,
    }, (res) => {
      /** @type {Buffer[]} */
      const chunks = []
      res.on('data', (chunk) => chunks.push(Buffer.from(chunk)))
      res.on('end', () => resolve({
        status: res.statusCode ?? 0,
        headers: res.headers,
        body: Buffer.concat(chunks).toString('utf8'),
      }))
    })
    req.on('timeout', () => req.destroy(new Error('HTTP 超时')))
    req.on('error', reject)
    req.end(payload)
  })
}

/**
 * 建立一个 TCP 连接（模拟手机的在途 socket）。
 * @param {number} port - 端口。
 * @returns {Promise<net.Socket>} 连接。
 */
function tcpConnect(port) {
  return new Promise((resolve, reject) => {
    const socket = net.connect({ host: '127.0.0.1', port })
    socket.once('connect', () => {
      socket.removeListener('error', reject)
      resolve(socket)
    })
    socket.once('error', reject)
  })
}

/**
 * 等 socket close。
 * @param {net.Socket} socket - socket。
 * @param {number} [timeoutMs] - 超时。
 * @returns {Promise<boolean>} 是否在超时前关闭。
 */
function socketClosed(socket, timeoutMs = 2000) {
  if (socket.destroyed) return Promise.resolve(true)
  return new Promise((resolve) => {
    const timer = setTimeout(() => resolve(false), timeoutMs)
    socket.once('close', () => {
      clearTimeout(timer)
      resolve(true)
    })
  })
}

test('kill：设备表保留 + socket 被 destroy + 端口关闭 + set.enabled 重开且旧 cookie 仍有效', async () => {
  const home = await mkdtemp(path.join(os.tmpdir(), 'rm-kill-'))
  process.env.DSH_HOME = home
  const upstream = await startFakeUpstream()
  const { ctx, routes, disposeAll } = makeCtx(upstream.origin)
  /** @type {net.Socket[]} */
  const sockets = []
  try {
    // 预置一台「已配对且未过期」的设备（绕过配对流程，聚焦 kill 语义）。
    await mkdir(path.join(home, 'remote-mobile'), { recursive: true })
    await writeFile(
      path.join(home, 'remote-mobile', 'devices.json'),
      `${JSON.stringify({
        v: 1,
        devices: [{
          id: DEVICE_ID,
          name: '测试手机',
          ua: 'iPhone',
          createdAt: Date.now() - 60_000,
          lastSeenAt: Date.now() - 1_000,
          lastIp: '192.168.1.9',
          readonly: false,
          secretHash: hashSecret(DEVICE_SECRET),
        }],
      })}\n`,
      { encoding: 'utf8', mode: 0o600 },
    )

    apply(ctx, {
      enabled: true,
      bindAddress: '127.0.0.1',
      port: 0,
      audit: { enabled: false },
      approvalRouting: 'off',
    })

    // 1) 等监听器起来。
    let port = 0
    await waitFor(async () => {
      const result = await rpc(routes, 'status')
      port = result.json?.data?.port ?? 0
      return port > 0
    }, 8000, '监听器启动')
    const firstPort = port

    // 设备表：1 台。
    let listed = await rpc(routes, 'devices.list')
    assert.equal(listed.json.data.devices.length, 1)

    // 一条在途连接（kill 必须把它 destroy 掉，而不是温柔 close）。
    const socket = await tcpConnect(firstPort)
    sockets.push(socket)

    // 2) kill。
    const killed = await rpc(routes, 'kill')
    assert.equal(killed.status, 200)
    assert.equal(killed.json.ok, true)
    assert.equal(typeof killed.json.data.closed, 'number')
    assert.equal(killed.json.data.revoked, undefined, 'kill 不再返回 revoked（不撤销设备）')

    const afterKill = await rpc(routes, 'status')
    assert.equal(afterKill.json.data.port, 0, 'kill 后端口应归零')
    assert.equal(afterKill.json.data.killSwitch, true)
    assert.equal(afterKill.json.data.enabled, true, 'enabled 仍是用户意图')

    // 3) 设备表长度不变。
    listed = await rpc(routes, 'devices.list')
    assert.equal(listed.json.data.devices.length, 1, 'kill 之后设备表长度必须不变')

    // 4) socket 被 destroy、旧端口拒绝新连接。
    assert.equal(await socketClosed(socket), true, 'kill 应 destroy 在途 socket')
    await assert.rejects(tcpConnect(firstPort))

    // 5) set.enabled true 能重新起来。
    const restarted = await rpc(routes, 'set.enabled', { enabled: true })
    assert.equal(restarted.json.ok, true)
    const secondPort = restarted.json.data.port
    assert.ok(secondPort > 0, 'set.enabled(true) 应该重新监听')

    const pong = await get(secondPort, '/m/ping')
    assert.equal(pong.status, 200)

    // 6) 旧设备 cookie 仍然有效（kill 没撤销它）。
    //
    // `/m/state` 是旧移动页的端点，已随移动页一起移除；现在 `/m/*` 是整站反代，
    // 所以这个请求应该被转发到上游（假上游一律回 "ok"）。
    // 这里验证的正是「cookie 通过鉴权 → 请求被转发出去」，而不是不再 302 到配对页。
    const state = await get(secondPort, '/m/anything', {
      cookie: `${DEVICE_COOKIE}=${DEVICE_ID}.${DEVICE_SECRET}`,
    })
    assert.equal(state.status, 200, 'kill 后重开，旧设备 cookie 应该仍然可用（请求被转发到上游）')
    assert.equal(state.body, 'ok', '应转发到上游；若这里 302 说明 cookie 没通过鉴权')

    // 反证：没有 cookie 时应该被挡回配对页，而不是拿到上游内容。
    // （`get()` 不返回 headers，所以只断言状态码；302 只会来自 requireDevice 的 redirect 分支。）
    const unpaired = await get(secondPort, '/m/anything')
    assert.equal(unpaired.status, 302, '未配对访问 /m/* 应 302 到配对页')

    listed = await rpc(routes, 'devices.list')
    assert.equal(listed.json.data.devices.length, 1)

    // 7) §1：JSON 配对分支 → 200 + `{ok,device,location}` + Set-Cookie（location 必须在 body 里）。
    const code = await rpc(routes, 'pair.create', { ttlSec: 30 })
    const pairRes = await post(secondPort, '/m/pair', {
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ code: code.json.data.code, name: 'JSON 手机' }),
    })
    assert.equal(pairRes.status, 200, pairRes.body)
    const paired = JSON.parse(pairRes.body)
    assert.equal(paired.ok, true)
    assert.equal(paired.location, '/m', '§1：JSON 分支 body 必须带 location')
    assert.equal(paired.device.name, 'JSON 手机')
    assert.match(String(pairRes.headers['set-cookie']), /^dshm_d=/)
  } finally {
    for (const socket of sockets) {
      try {
        socket.destroy()
      } catch {
        // 已断开。
      }
    }
    await disposeAll()
    await upstream.close()
    delete process.env.DSH_HOME
    await rm(home, { recursive: true, force: true })
  }
})
