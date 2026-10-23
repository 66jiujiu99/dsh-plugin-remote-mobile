/**
 * 真实链路端到端：真 cloudflared 隧道 → 真 listener → 真 Host 栅栏 → 真上游。
 *
 * 与 tunnel-e2e.mjs 的区别：
 *   - tunnel-e2e 只验证「隧道能通」（本地服务是个裸 http server）。
 *   - 这个验证**产品代码的完整链路**：请求经过 listener 的 Host 栅栏、
 *     设备鉴权、前缀剥离，最后落到上游。这才是用户实际会走的路。
 *
 * 用法：
 *   ELECTRON_RUN_AS_NODE=1 "C:\Data\APP\dsh\DeepSeek Harness.exe" _probe\full-chain.mjs
 */

import http from 'node:http'
import { request as httpsRequest } from 'node:https'
import { mkdtemp, rm } from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'

import { resolveConfig } from '../lib/config.js'
import { createAudit } from '../lib/audit.js'
import { createDevices } from '../lib/auth/devices.js'
import { createPairing } from '../lib/auth/pairing.js'
import { createListener } from '../lib/net/listener.js'
import { createTunnel } from '../lib/net/tunnel.js'

const CLOUDFLARED = 'C:/Data/deepseek/tools/cloudflared.exe'

const checks = []
function check(name, ok, detail) {
  checks.push({ name, ok, detail })
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? ` — ${detail}` : ''}`)
}

/** 假上游：回显收到了什么，用于验证前缀剥离与头改写。 */
function startUpstream() {
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      res.writeHead(200, { 'content-type': 'application/json; charset=utf-8' })
      res.end(JSON.stringify({ upstreamPath: req.url, host: req.headers.host }))
    })
    server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port }))
  })
}

/**
 * 经 https 取一个 URL。
 * @param {string} url - 地址。
 * @param {Record<string,string>} [headers] - 额外头。
 * @param {number} [timeoutMs] - 超时。
 * @returns {Promise<{ status: number, body: string, headers: object }>} 响应。
 */
function fetchHttps(url, headers = {}, timeoutMs = 20_000) {
  return new Promise((resolve, reject) => {
    const req = httpsRequest(url, { method: 'GET', headers, timeout: timeoutMs }, (res) => {
      let body = ''
      res.setEncoding('utf8')
      res.on('data', (chunk) => { body += chunk })
      res.on('end', () => resolve({ status: res.statusCode ?? 0, body, headers: res.headers }))
    })
    req.on('timeout', () => req.destroy(new Error('timeout')))
    req.on('error', reject)
    req.end()
  })
}

/**
 * 带重试地取（Cloudflare 边缘铺开需要时间）。
 * @param {string} url - 地址。
 * @param {Record<string,string>} headers - 头。
 * @returns {Promise<{ status: number, body: string, headers: object }|undefined>} 响应。
 */
async function fetchWithRetry(url, headers = {}) {
  const deadline = Date.now() + 120_000
  let last = ''
  while (Date.now() < deadline) {
    try {
      return await fetchHttps(url, headers)
    } catch (error) {
      last = String(error?.message ?? error)
      await new Promise((r) => setTimeout(r, 3000))
    }
  }
  console.log(`  （重试耗尽，最后错误：${last}）`)
  return undefined
}

async function main() {
  const home = await mkdtemp(path.join(os.tmpdir(), 'rm-full-home-'))
  const previousHome = process.env.DSH_HOME
  process.env.DSH_HOME = home

  const upstream = await startUpstream()
  let listener
  let tunnel

  try {
    console.log(`假上游：127.0.0.1:${upstream.port}`)

    const config = resolveConfig({
      enabled: false,
      port: 0,
      tunnel: { provider: 'quick', binaryPath: CLOUDFLARED, idleTimeoutSec: 0, startTimeoutSec: 120 },
    })
    const log = (level, message) => console.log(`  [${level}] ${message}`)
    const audit = createAudit({ config, log })
    const devices = createDevices({ config, audit, log })
    await devices.ready()
    const pairing = createPairing({ config, devices, audit })

    tunnel = createTunnel({ config, log, audit, toolsDir: path.dirname(CLOUDFLARED), getPort: () => listener?.port ?? 0 })

    // 上游适配器：把 listener 的请求真正转发到假上游（模拟真实 upstream.send）。
    const upstreamAdapter = {
      cookieOk: true,
      ensure: async () => true,
      endpoint: () => ({ cookie: 'dsh-auth-x=1' }),
      authority: () => `127.0.0.1:${upstream.port}`,
      origin: () => `http://127.0.0.1:${upstream.port}`,
      cookieHeader: () => 'dsh-auth-x=1',
      send: async ({ path: upstreamPath, method, headers }) => new Promise((resolve, reject) => {
        const req = http.request({
          hostname: '127.0.0.1',
          port: upstream.port,
          path: upstreamPath,
          method,
          headers,
          agent: false,
        }, resolve)
        req.on('error', reject)
        req.end()
      }),
    }

    listener = createListener({
      config,
      devices,
      pairing,
      approvals: { poll: async () => ({ items: [], nextSeq: 0 }), pending: () => 0, decide: () => ({ ok: true }), setActive() {}, settleAll() {} },
      upstream: upstreamAdapter,
      statics: { get: async () => undefined },
      audit,
      log,
      tunnel,
    })
    const { port } = await listener.start()
    console.log(`listener：${port}`)

    // ── 1) 未配对：经公网访问应被 302 到配对页（证明 Host 栅栏放行 + 鉴权生效）
    console.log('\n开隧道 ...')
    const opened = await tunnel.start()
    console.log(`隧道：${opened.url}`)
    check('拿到公网地址', /^https:\/\/[a-z0-9-]+\.trycloudflare\.com$/.test(opened.url), opened.url)

    console.log('经公网访问（未配对状态）...')
    const anonymous = await fetchWithRetry(`${opened.url}/m/anything`)
    if (anonymous === undefined) {
      check('公网可访问', false, '重试耗尽')
    } else {
      check('公网可访问且未被 Host 栅栏拒', anonymous.status !== 400, `status=${anonymous.status}`)
      check('未配对时跳转配对页', anonymous.status === 302, `status=${anonymous.status} location=${anonymous.headers.location ?? '(无)'}`)
    }

    // ── 2) 配对拿 cookie
    const { code } = pairing.create(120)
    console.log(`\n配对码：${code}`)
    const paired = await pairing.attempt({ code, name: 'e2e 手机', ip: '127.0.0.1' })
    const cookie = paired.setCookie.split(';')[0]
    check('配对成功并拿到设备 cookie', /dshm_d=/.test(cookie))

    // ── 3) 带上设备 cookie 经公网访问：应真正落到上游，且前缀被剥掉
    console.log('带配对 cookie 经公网访问 /m/some/deep/path?x=1 ...')
    const authed = await fetchWithRetry(`${opened.url}/m/some/deep/path?x=1`, { cookie })
    if (authed === undefined) {
      check('鉴权后公网访问', false, '重试耗尽')
    } else {
      check('鉴权后公网访问成功', authed.status === 200, `status=${authed.status} body=${authed.body.slice(0, 120)}`)
      let parsed
      try {
        parsed = JSON.parse(authed.body)
      } catch {
        parsed = undefined
      }
      check(
        '/m 前缀被正确剥离',
        parsed !== undefined && parsed.upstreamPath === '/some/deep/path?x=1',
        parsed !== undefined ? `上游收到 ${parsed.upstreamPath}` : '响应不是 JSON',
      )
      check(
        '上游看到的 Host 被改写成本机 authority',
        parsed !== undefined && String(parsed.host).startsWith('127.0.0.1:'),
        parsed !== undefined ? `host=${parsed.host}` : 'n/a',
      )
    }

    // ── 4) 隧道状态与关闭
    check('隧道状态 running', tunnel.status().phase === 'running', JSON.stringify(tunnel.status()))
    const publicHostBefore = tunnel.publicHost
    await tunnel.close('e2e')
    check('关闭后 publicHost 清空', tunnel.publicHost === undefined, publicHostBefore ?? '')
  } finally {
    if (listener !== undefined) await listener.stop({ resumeApprovals: false }).catch(() => {})
    if (tunnel !== undefined) await tunnel.close('cleanup').catch(() => {})
    upstream.server.close()
    if (previousHome === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previousHome
    await new Promise((r) => setTimeout(r, 300))
    await rm(home, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }).catch(() => {})
  }

  const failed = checks.filter((item) => !item.ok)
  console.log(`\n结果：${checks.length - failed.length}/${checks.length} 通过`)
  process.exit(failed.length === 0 ? 0 : 1)
}

main().catch((error) => {
  console.error('探针异常：', error)
  process.exit(1)
})
