/**
 * 隧道 RPC 接线测试：驱动**真实 index.js**，而不是我手工复刻的函数。
 *
 * 为什么需要这个：`_probe/panel-runtime.mjs` 里我是把 `startTunnel/stopTunnel/
 * tunnelStatus` 三个函数**照抄**了一遍来测的——那只能证明"我抄的版本对"，
 * 证明不了 index.js 里真实那份接对了（op 名注册、依赖注入、错误码映射）。
 *
 * 这个测试走真实路径：
 *   RPC 路由表 → lib/admin/routes.js 的 handler → index.js 的 runtime 函数 → tunnel 模块
 *
 * 用假 cloudflared（真 exe）+ 临时 DSH_HOME，绝不碰真实环境。
 */

import assert from 'node:assert/strict'
import http from 'node:http'
import { spawnSync } from 'node:child_process'
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import { Readable } from 'node:stream'
import test from 'node:test'

import { apply } from '../index.js'

const RPC_PATH = '/plugin/remote-mobile/rpc'

/**
 * 编译一个假 cloudflared exe（会打一行域名然后挂住）。
 * @param {string} dir - 临时目录。
 * @param {string} line - 打到 stderr 的内容。
 * @returns {Promise<string>} exe 路径。
 */
async function makeFakeExe(dir, line) {
  const source = path.join(dir, 'fake.cs')
  const exe = path.join(dir, 'cloudflared.exe')
  const literal = (value) => `"${String(value).replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`
  await writeFile(source, [
    'using System;',
    'using System.Threading;',
    'class P { static void Main(string[] a) {',
    `  Console.Error.WriteLine(${literal(line)});`,
    '  Thread.Sleep(600000);',
    '} }',
  ].join('\n'), 'utf8')
  const built = spawnSync(
    'C:/Windows/Microsoft.NET/Framework64/v4.0.30319/csc.exe',
    ['-nologo', `-out:${exe}`, source],
    { encoding: 'utf8' },
  )
  if (built.status !== 0) throw new Error(`csc 失败：${built.stdout}${built.stderr}`)
  return exe
}

/**
 * 假上游（只回固定 JSON）。
 * @returns {Promise<{ origin: string, close: () => Promise<void> }>} 上游。
 */
async function startFakeUpstream() {
  const server = http.createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' })
    res.end(JSON.stringify({ ok: true, path: req.url }))
  })
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  return {
    origin: `http://127.0.0.1:${server.address().port}`,
    close: () => new Promise((resolve) => server.close(() => resolve(undefined))),
  }
}

/**
 * 假 Cordis ctx（与 kill.test.mjs 同构，只给装配所需的最小面）。
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
      return () => routes.delete(options.path)
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
    inject(_names, fn) { fn(ctx) },
    on() { return () => {} },
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
    const timer = setTimeout(() => reject(new Error(`RPC ${op} 超时`)), 30_000)
    timer.unref?.()
    const res = {
      writableEnded: false,
      destroyed: false,
      writeHead(status) { out.status = status },
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
 * 等到条件成立。
 * @param {() => boolean|Promise<boolean>} predicate - 条件。
 * @param {number} [timeoutMs] - 超时。
 * @param {string} [what] - 失败说明。
 * @returns {Promise<void>} 完成。
 */
async function waitFor(predicate, timeoutMs = 10_000, what = '条件') {
  const deadline = Date.now() + timeoutMs
  for (;;) {
    if (await predicate()) return
    if (Date.now() > deadline) throw new Error(`等待超时：${what}`)
    await new Promise((resolve) => setTimeout(resolve, 50))
  }
}

test('RPC 接线：tunnel.start / tunnel.status / tunnel.stop 走真实 index.js', async () => {
  const home = await mkdtemp(path.join(os.tmpdir(), 'rm-rpc-tunnel-'))
  const exeDir = await mkdtemp(path.join(os.tmpdir(), 'rm-rpc-exe-'))
  process.env.DSH_HOME = home
  const upstream = await startFakeUpstream()
  const { ctx, routes, disposeAll } = makeCtx(upstream.origin)
  try {
    const fake = await makeFakeExe(exeDir, 'INF |  https://rpc-wired-test.trycloudflare.com  |')

    // 把假 cloudflared 放进插件的 tools 目录是"污染安装目录"，不合适。
    // 改用 tunnel.binaryPath 显式指定——这也是真实用户的一种用法。
    apply(ctx, {
      enabled: true,
      bindAddress: '127.0.0.1',
      port: 0,
      audit: { enabled: false },
      approvalRouting: 'off',
      tunnel: {
        provider: 'quick',
        binaryPath: fake,
        idleTimeoutSec: 0,
        startTimeoutSec: 30,
      },
    })

    // 1) 等监听器起来（隧道需要端口）。
    let port = 0
    await waitFor(async () => {
      const result = await rpc(routes, 'status')
      port = result.json?.data?.port ?? 0
      return port > 0
    }, 10_000, '监听器启动')

    // 2) tunnel.status 在未开时应返回 idle，且结构符合面板期望。
    const idle = await rpc(routes, 'tunnel.status')
    assert.equal(idle.json.ok, true, JSON.stringify(idle.json))
    assert.equal(idle.json.data.provider, 'quick')
    assert.equal(idle.json.data.tunnel.phase, 'idle')

    // 3) tunnel.start 必须真的走到 index.js 的 startTunnel 并返回公网地址。
    const started = await rpc(routes, 'tunnel.start')
    assert.equal(started.json.ok, true, JSON.stringify(started.json))
    const url = started.json.data.url
    assert.equal(url, 'https://rpc-wired-test.trycloudflare.com')

    // 4) status 跟着变成 running（面板"公网可达"的数据来源）。
    const running = await rpc(routes, 'tunnel.status')
    assert.equal(running.json.data.tunnel.phase, 'running')
    assert.equal(running.json.data.tunnel.publicUrl, url)

    // 5) 隧道域名必须已经进了 Host 白名单——否则公网访问会被 400。
    //    这是"接线对但用不了"的典型故障，必须断言。
    const viaTunnel = await new Promise((resolve, reject) => {
      const req = http.request({
        host: '127.0.0.1',
        port,
        path: '/m/whatever',
        method: 'GET',
        headers: { host: 'rpc-wired-test.trycloudflare.com' },
        timeout: 5000,
      }, (res) => {
        res.resume()
        res.on('end', () => resolve(res.statusCode))
      })
      req.on('timeout', () => req.destroy(new Error('timeout')))
      req.on('error', reject)
      req.end()
    })
    // 未配对 → 302 到配对页；关键是不能是 400（那说明 Host 栅栏还在拒）。
    assert.equal(viaTunnel, 302, `隧道 Host 头不该被拒（实际 ${viaTunnel}）`)

    // 6) tunnel.stop 关闭并回到 idle。
    const stopped = await rpc(routes, 'tunnel.stop')
    assert.equal(stopped.json.ok, true)
    const afterStop = await rpc(routes, 'tunnel.status')
    assert.equal(afterStop.json.data.tunnel.phase, 'idle')

    // 7) 幂等：再关一次也不报错。
    const stoppedAgain = await rpc(routes, 'tunnel.stop')
    assert.equal(stoppedAgain.json.ok, true)
  } finally {
    await disposeAll()
    await upstream.close()
    delete process.env.DSH_HOME
    await new Promise((resolve) => setTimeout(resolve, 300))
    await rm(home, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }).catch(() => {})
    await rm(exeDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }).catch(() => {})
  }
})

test('RPC 接线：监听未开时 tunnel.start 给出可行动的错误', async () => {
  const home = await mkdtemp(path.join(os.tmpdir(), 'rm-rpc-tunnel-'))
  const exeDir = await mkdtemp(path.join(os.tmpdir(), 'rm-rpc-exe-'))
  process.env.DSH_HOME = home
  const upstream = await startFakeUpstream()
  const { ctx, routes, disposeAll } = makeCtx(upstream.origin)
  try {
    const fake = await makeFakeExe(exeDir, 'INF |  https://should-not-start.trycloudflare.com  |')
    apply(ctx, {
      enabled: false, // 关键：不监听
      bindAddress: '127.0.0.1',
      port: 0,
      audit: { enabled: false },
      approvalRouting: 'off',
      tunnel: { provider: 'quick', binaryPath: fake, idleTimeoutSec: 0, startTimeoutSec: 30 },
    })
    await new Promise((resolve) => setTimeout(resolve, 200))

    const result = await rpc(routes, 'tunnel.start')
    assert.equal(result.json.ok, false, JSON.stringify(result.json))
    // 必须是"先开监听"这个可行动的提示，而不是笼统失败。
    assert.equal(result.json.error.code, 'rm/tunnel-no-listener')
    assert.match(result.json.error.message, /手机同步|监听/)
  } finally {
    await disposeAll()
    await upstream.close()
    delete process.env.DSH_HOME
    await new Promise((resolve) => setTimeout(resolve, 300))
    await rm(home, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }).catch(() => {})
    await rm(exeDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }).catch(() => {})
  }
})

test('RPC 接线：provider=none 时 tunnel.start 明确拒绝', async () => {
  const home = await mkdtemp(path.join(os.tmpdir(), 'rm-rpc-tunnel-'))
  process.env.DSH_HOME = home
  const upstream = await startFakeUpstream()
  const { ctx, routes, disposeAll } = makeCtx(upstream.origin)
  try {
    apply(ctx, {
      enabled: true,
      bindAddress: '127.0.0.1',
      port: 0,
      audit: { enabled: false },
      approvalRouting: 'off',
      tunnel: { provider: 'none' },
    })
    await waitFor(async () => {
      const result = await rpc(routes, 'status')
      return (result.json?.data?.port ?? 0) > 0
    }, 10_000, '监听器启动')

    const result = await rpc(routes, 'tunnel.start')
    assert.equal(result.json.ok, false, JSON.stringify(result.json))
    assert.equal(result.json.error.code, 'rm/tunnel-disabled')
  } finally {
    await disposeAll()
    await upstream.close()
    delete process.env.DSH_HOME
    await new Promise((resolve) => setTimeout(resolve, 300))
    await rm(home, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }).catch(() => {})
  }
})
