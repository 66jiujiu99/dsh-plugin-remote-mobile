/**
 * 集成测试：真实 listener + 真实 tunnel + 假上游。
 *
 * 单元测试只能证明各模块自己没问题；这个测试证明**接起来之后**的关键行为：
 *   1. 隧道域名**必须**被 Host 栅栏放行（不放行的话公网访问全是 400）。
 *   2. 隧道关闭后，那个域名必须立刻不再被放行。
 *   3. 隧道放行不会顺带放宽别的域名（安全边界不能因为开隧道而变松）。
 *   4. 配对码 8 位、大小写/空格容错、同 IP 限流真的生效。
 *
 * 用临时 `DSH_HOME` 隔离，绝不碰真实 `~/.dsh`。
 */

import assert from 'node:assert/strict'
import http from 'node:http'
import { spawnSync } from 'node:child_process'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'

import { resolveConfig } from '../lib/config.js'
import { createAudit } from '../lib/audit.js'
import { createDevices } from '../lib/auth/devices.js'
import { createPairing } from '../lib/auth/pairing.js'
import { allowedAuthorities } from '../lib/net/lan.js'
import { createListener } from '../lib/net/listener.js'
import { createTunnel } from '../lib/net/tunnel.js'

/**
 * 编译一个假 cloudflared exe（真 cloudflared 也是 exe，这样最贴近真实）。
 * @param {string} dir - 临时目录。
 * @param {string} line - 打到 stderr 的一行。
 * @param {boolean} [hold] - 是否挂住不退。
 * @returns {Promise<string>} exe 路径。
 */
async function makeFakeExe(dir, line, hold = true) {
  const source = path.join(dir, 'fake.cs')
  const exe = path.join(dir, 'cloudflared.exe')
  const literal = (value) => `"${String(value).replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`
  await writeFile(source, [
    'using System;',
    'using System.Threading;',
    'class P { static void Main(string[] a) {',
    `  Console.Error.WriteLine(${literal(line)});`,
    hold ? '  Thread.Sleep(600000);' : '  Environment.Exit(0);',
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

/** 上游桩：`send` 直接回一个可控的响应，避免依赖 cookie 交换。 */
function makeUpstreamStub(body) {
  return {
    cookieOk: true,
    ensure: async () => true,
    endpoint: () => ({ cookie: 'dsh-auth-x=1' }),
    authority: () => '127.0.0.1:1',
    origin: () => 'http://127.0.0.1:1',
    cookieHeader: () => 'dsh-auth-x=1',
    send: async () => {
      const { Readable } = require('node:stream')
      return Object.assign(Readable.from([Buffer.from(body, 'utf8')]), {
        statusCode: 200,
        headers: { 'content-type': 'text/plain; charset=utf-8' },
        destroy() {},
      })
    },
  }
}

/** 审批队列桩。 */
function makeApprovalsStub() {
  return {
    poll: async () => ({ items: [], nextSeq: 0 }),
    pending: () => 0,
    decide: () => ({ ok: true }),
    setActive() {},
    settleAll() {},
  }
}

/** 静态资源桩（本测试不需要真文件）。 */
function makeStaticsStub() {
  return {
    get: async () => undefined,
  }
}

/**
 * 发一个带指定 Host 头的 GET。
 * @param {number} port - 端口。
 * @param {string} pathname - 路径。
 * @param {string} hostHeader - Host 头。
 * @returns {Promise<{ status: number, location?: string }>} 响应摘要。
 */
function getWithHost(port, pathname, hostHeader) {
  return new Promise((resolve, reject) => {
    const req = http.request({
      host: '127.0.0.1',
      port,
      path: pathname,
      method: 'GET',
      headers: { host: hostHeader },
      timeout: 5000,
    }, (res) => {
      res.resume()
      res.on('end', () => resolve({ status: res.statusCode, location: res.headers.location }))
    })
    req.on('timeout', () => req.destroy(new Error('timeout')))
    req.on('error', reject)
    req.end()
  })
}

test('集成：隧道域名被 Host 栅栏放行，关闭后立即失效', async () => {
  const home = await mkdtemp(path.join(os.tmpdir(), 'rm-int-home-'))
  const dir = await mkdtemp(path.join(os.tmpdir(), 'rm-int-'))
  const previousHome = process.env.DSH_HOME
  process.env.DSH_HOME = home
  let listener
  let tunnel
  try {
    const fake = await makeFakeExe(dir, 'INF |  https://brave-river-test999.trycloudflare.com  |')
    const config = resolveConfig({
      enabled: false,
      port: 0,
      tunnel: { provider: 'quick', binaryPath: fake, idleTimeoutSec: 0, startTimeoutSec: 60 },
    })
    const log = () => {}
    const audit = createAudit({ config, log })
    const devices = createDevices({ config, audit, log })
    await devices.ready()

    tunnel = createTunnel({ config, log, audit, toolsDir: dir, getPort: () => listener?.port ?? 0 })
    listener = createListener({
      config,
      devices,
      pairing: createPairing({ config, devices, audit }),
      approvals: makeApprovalsStub(),
      upstream: makeUpstreamStub('upstream-ok'),
      statics: makeStaticsStub(),
      audit,
      log,
      tunnel,
    })
    const { port } = await listener.start()
    assert.ok(port > 0)

    // 1) 隧道没开：域名不在白名单。
    assert.equal(allowedAuthorities(port, config.bindAddress, undefined).has('brave-river-test999.trycloudflare.com'), false)

    // 2) 开隧道 → 域名进白名单。
    const opened = await tunnel.start()
    assert.equal(opened.url, 'https://brave-river-test999.trycloudflare.com')
    assert.equal(
      allowedAuthorities(port, config.bindAddress, tunnel.publicHost).has('brave-river-test999.trycloudflare.com'),
      true,
      '隧道域名必须被放行，否则公网访问全是 400',
    )

    // 3) 用隧道 Host 头打真实 listener：应越过 Host 栅栏 → 未配对时 302 到配对页。
    const viaTunnel = await getWithHost(port, '/m/anything', 'brave-river-test999.trycloudflare.com')
    assert.equal(viaTunnel.status, 302, `隧道 Host 头不该被 Host 栅栏拒（实际 ${viaTunnel.status}）`)
    assert.equal(viaTunnel.location, '/m/pair')

    // 4) 关隧道 → 域名立刻不再被放行。
    await tunnel.close('test')
    assert.equal(allowedAuthorities(port, config.bindAddress, tunnel.publicHost).has('brave-river-test999.trycloudflare.com'), false)
  } finally {
    if (listener !== undefined) await listener.stop({ resumeApprovals: false }).catch(() => {})
    if (tunnel !== undefined) await tunnel.close('cleanup').catch(() => {})
    if (previousHome === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previousHome
    await rm(home, { recursive: true, force: true })
    await rm(dir, { recursive: true, force: true })
  }
})

test('集成：未知 Host 头仍被拒（开隧道不放宽别的域名）', async () => {
  const home = await mkdtemp(path.join(os.tmpdir(), 'rm-int-home-'))
  const dir = await mkdtemp(path.join(os.tmpdir(), 'rm-int-'))
  const previousHome = process.env.DSH_HOME
  process.env.DSH_HOME = home
  let listener
  try {
    const fake = await makeFakeExe(dir, 'INF |  https://brave-river-test999.trycloudflare.com  |')
    const config = resolveConfig({ enabled: false, port: 0, tunnel: { provider: 'quick', binaryPath: fake } })
    const log = () => {}
    const audit = createAudit({ config, log })
    const devices = createDevices({ config, audit, log })
    await devices.ready()
    const tunnel = createTunnel({ config, log, audit, toolsDir: dir, getPort: () => listener?.port ?? 0 })

    listener = createListener({
      config,
      devices,
      pairing: createPairing({ config, devices, audit }),
      approvals: makeApprovalsStub(),
      upstream: makeUpstreamStub('ok'),
      statics: makeStaticsStub(),
      audit,
      log,
      tunnel,
    })
    const { port } = await listener.start()

    // 开隧道之后，一个完全无关的域名仍然必须被拒。
    await tunnel.start()
    const rejected = await getWithHost(port, '/m/x', 'evil.example.com')
    assert.equal(rejected.status, 400, '无关域名必须被 Host 栅栏拒掉')
    await tunnel.close('test')
  } finally {
    if (listener !== undefined) await listener.stop({ resumeApprovals: false }).catch(() => {})
    if (previousHome === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previousHome
    await rm(home, { recursive: true, force: true })
    await rm(dir, { recursive: true, force: true })
  }
})

test('集成：配对码 8 位、大小写与空格容错、同 IP 限流生效', async () => {
  const home = await mkdtemp(path.join(os.tmpdir(), 'rm-int-home-'))
  const previousHome = process.env.DSH_HOME
  process.env.DSH_HOME = home
  try {
    const config = resolveConfig({ enabled: false, pairCodeTtlSec: 60, pairMaxAttempts: 5 })
    const log = () => {}
    const audit = createAudit({ config, log })
    const devices = createDevices({ config, audit, log })
    await devices.ready()
    const pairing = createPairing({ config, devices, audit })

    const { code } = pairing.create()
    assert.match(code, /^[2-9A-HJ-NP-Z]{8}$/, `配对码格式不对：${code}`)

    // 大小写 + 空格容错（手机输入法会自动首字母大写）。
    const paired = await pairing.attempt({ code: ` ${code.toLowerCase()} `, name: '测试手机', ip: '10.1.2.3' })
    assert.match(paired.setCookie, /dshm_d=/)

    // 同一 IP 高频请求 → 被限流（RATE_MAX = 10 / 分钟）。
    pairing.create()
    let limited = false
    for (let attempt = 0; attempt < 15; attempt += 1) {
      try {
        await pairing.attempt({ code: 'ZZZZZZZZ', ip: '10.9.9.9' })
      } catch (error) {
        if (error.code === 'rm/pair-locked' && /过于频繁/.test(error.message)) {
          limited = true
          break
        }
      }
    }
    assert.equal(limited, true, '同一 IP 高频配对请求必须被限流')
  } finally {
    if (previousHome === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previousHome
    // 审计/设备写盘是异步的：给它们一点时间落盘，避免 rmdir 撞上 ENOTEMPTY。
    await new Promise((resolve) => setTimeout(resolve, 200))
    await rm(home, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 })
  }
})
