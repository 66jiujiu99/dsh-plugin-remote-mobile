/**
 * 回归测试：`/m/**` 整站反代必须经过策略检查。
 *
 * ## 这条测试为什么存在
 *
 * 2026-10-24 的安全审计发现了一个**我们自己写出来的高危漏洞**：
 *
 *   `/m/**` 反代只校验设备 cookie，**从不调用 `decide()`**。
 *   而反代会把 `/m/vault/api` 剥前缀成 `/vault/api`，还把 Host 改写成
 *   `127.0.0.1:<port>` —— 恰好通过上游凭证保险库的 loopback 校验。
 *
 *   后果：任何配对设备（**包括只读设备**）都能直接读写删凭证。
 *
 * 另外黑名单本身也漏了 `vault/`（保险库管理面挂在 `/vault/api`，
 * 原来只有 `credentials/` 匹配不上）。
 *
 * 这个测试同时钉住两件事：
 *   1. 黑名单路径经反代被拒；
 *   2. 只读设备的写请求被拒；
 *   3. 正常 UI 路径**不被误杀**（否则手机就没法用了）。
 */

import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import { Readable } from 'node:stream'
import test from 'node:test'

import { resolveConfig } from '../lib/config.js'
import { createAudit } from '../lib/audit.js'
import { createDevices } from '../lib/auth/devices.js'
import { createPairing } from '../lib/auth/pairing.js'
import { createListener } from '../lib/net/listener.js'
import { PERMANENT_DENY } from '../lib/policy/policy.js'

/** 审批桩。 */
function approvalsStub() {
  return { poll: async () => ({ items: [], nextSeq: 0 }), pending: () => 0, decide: () => ({ ok: true }), setActive() {}, settleAll() {} }
}

/** 上游桩：回显它收到的路径，便于断言"转发到哪"。 */
function upstreamStub() {
  return {
    cookieOk: true,
    ensure: async () => true,
    endpoint: () => ({ cookie: 'x=1' }),
    authority: () => '127.0.0.1:1',
    origin: () => 'http://127.0.0.1:1',
    cookieHeader: () => 'x=1',
    send: async ({ path: upstreamPath }) => Object.assign(
      Readable.from([Buffer.from(JSON.stringify({ upstreamPath }), 'utf8')]),
      { statusCode: 200, headers: { 'content-type': 'application/json' }, destroy() {} },
    ),
  }
}

/**
 * 起一个真实的 listener（真 devices/pairing/audit，假上游）。
 * @param {object} dir - 临时目录。
 * @param {string} home - DSH_HOME。
 * @returns {Promise<object>} 环境。
 */
async function boot(dir, home) {
  process.env.DSH_HOME = home
  const config = resolveConfig({
    enabled: false,
    port: 0,
    pairCodeTtlSec: 300,
    audit: { enabled: false },
  })
  const log = () => {}
  const audit = createAudit({ config, log })
  const devices = createDevices({ config, audit, log })
  await devices.ready()
  const pairing = createPairing({ config, devices, audit })

  const listener = createListener({
    config,
    devices,
    pairing,
    approvals: approvalsStub(),
    upstream: upstreamStub(),
    statics: { get: async () => undefined },
    audit,
    log,
    tunnel: undefined,
  })
  const { port } = await listener.start()
  return { listener, devices, pairing, port, config }
}

/**
 * 发一个带设备 cookie 的请求。
 * @param {number} port - 端口。
 * @param {string} pathname - 路径。
 * @param {object} [options] - 选项。
 * @returns {Promise<{ status: number, body: string, headers: object }>} 响应。
 */
async function request(port, pathname, options = {}) {
  const http = await import('node:http')
  return new Promise((resolve, reject) => {
    const req = http.request({
      host: '127.0.0.1',
      port,
      path: pathname,
      method: options.method ?? 'GET',
      headers: { host: `127.0.0.1:${port}`, ...(options.headers ?? {}) },
      timeout: 5000,
    }, (res) => {
      let body = ''
      res.setEncoding('utf8')
      res.on('data', (c) => { body += c })
      res.on('end', () => resolve({ status: res.statusCode, body, headers: res.headers }))
    })
    req.on('timeout', () => req.destroy(new Error('timeout')))
    req.on('error', reject)
    if (options.body !== undefined) req.end(options.body)
    else req.end()
  })
}

/**
 * 配一台设备并返回它的 cookie。
 * @param {object} env - boot() 返回的环境。
 * @param {boolean} readonly - 是否只读设备。
 * @returns {Promise<string>} cookie 头。
 */
async function pairDevice(env, readonly) {
  const { code } = env.pairing.create(300)
  const paired = await env.pairing.attempt({ code, name: readonly ? '只读手机' : '测试手机', ip: '127.0.0.1' })
  if (readonly === true) {
    await env.devices.setReadonly(paired.device.id, true)
  }
  return paired.setCookie.split(';')[0]
}

test('反代黑名单：凭证管理面经 /m 必须被拒（读写设备也一样）', async () => {
  const home = await mkdtemp(path.join(os.tmpdir(), 'rm-policy-home-'))
  const dir = await mkdtemp(path.join(os.tmpdir(), 'rm-policy-'))
  try {
    const env = await boot(dir, home)
    const cookie = await pairDevice(env, false)
    try {
      // 保险库管理面：GET 也应被拒（读 meta 也算泄露）。
      for (const [method, target] of [
        ['GET', '/m/vault/api'],
        ['POST', '/m/vault/api'],
        ['GET', '/m/api/vault/state'],
        ['POST', '/m/credentials/set'],
        ['POST', '/m/pluginManager/installBundle'],
        ['POST', '/m/terminal/run'],
        ['GET', '/m/settings/get'],
        ['POST', '/m/fileUploads/upload'],
        ['POST', '/m/directoryPicker/pick'],
        ['POST', '/m/open-in-app/open'],
        ['POST', '/m/dynamicCordisRunner/runHostHalf'],
      ]) {
        const res = await request(env.port, target, {
          method,
          headers: { cookie, 'content-type': 'application/json' },
          body: method === 'GET' ? undefined : '{}',
        })
        assert.equal(res.status, 403, `${method} ${target} 应 403，实际 ${res.status}`)
        assert.match(res.body, /rm\/forbidden|永久禁用/)
      }
    } finally {
      await env.listener.stop({ resumeApprovals: false })
    }
  } finally {
    delete process.env.DSH_HOME
    await new Promise((r) => setTimeout(r, 150))
    await rm(home, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }).catch(() => {})
    await rm(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }).catch(() => {})
  }
})

test('反代：正常 UI 路径不被误杀（否则手机没法用）', async () => {
  const home = await mkdtemp(path.join(os.tmpdir(), 'rm-policy-home-'))
  const dir = await mkdtemp(path.join(os.tmpdir(), 'rm-policy-'))
  try {
    const env = await boot(dir, home)
    const cookie = await pairDevice(env, false)
    try {
      // 这些是手机正常使用必须放行的。
      for (const target of [
        '/m/',
        '/m/assets/index-abc.js',
        '/m/api/session/list',
        '/m/api/remote.mux',
        '/m/api/workspace/list',
      ]) {
        const res = await request(env.port, target, { headers: { cookie } })
        assert.notEqual(res.status, 403, `${target} 不该被策略拒（实际 ${res.status}）`)
      }
    } finally {
      await env.listener.stop({ resumeApprovals: false })
    }
  } finally {
    delete process.env.DSH_HOME
    await new Promise((r) => setTimeout(r, 150))
    await rm(home, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }).catch(() => {})
    await rm(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }).catch(() => {})
  }
})

test('反代：只读设备的写请求被拒，读请求放行', async () => {
  const home = await mkdtemp(path.join(os.tmpdir(), 'rm-policy-home-'))
  const dir = await mkdtemp(path.join(os.tmpdir(), 'rm-policy-'))
  try {
    const env = await boot(dir, home)
    const cookie = await pairDevice(env, true)
    try {
      // 读：放行。
      const read = await request(env.port, '/m/api/session/list', { headers: { cookie } })
      assert.notEqual(read.status, 403, `只读设备读接口应放行（实际 ${read.status}）`)

      // 写：拒绝。
      for (const target of ['/m/api/session/create', '/m/api/session/prompt', '/m/api/workspace/create']) {
        const res = await request(env.port, target, {
          method: 'POST',
          headers: { cookie, 'content-type': 'application/json' },
          body: '{}',
        })
        assert.equal(res.status, 403, `只读设备写 ${target} 应 403，实际 ${res.status}`)
        assert.match(res.body, /只读|rm\/readonly/)
      }
    } finally {
      await env.listener.stop({ resumeApprovals: false })
    }
  } finally {
    delete process.env.DSH_HOME
    await new Promise((r) => setTimeout(r, 150))
    await rm(home, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }).catch(() => {})
    await rm(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }).catch(() => {})
  }
})

test('黑名单本身包含关键管理面（防止被改回去）', () => {
  for (const needed of ['vault/', 'terminal/', 'credentials/', 'plugin/', 'settings/', 'fileUploads/', 'directoryPicker/', 'open-in-app/', 'dynamicCordisRunner/']) {
    assert.ok(
      PERMANENT_DENY.includes(needed),
      `PERMANENT_DENY 必须包含 ${needed}（审计发现漏过 vault/）`,
    )
  }
})
