/**
 * 面板可视验证：起一个隔离的 listener + 隧道，让 agent 浏览器去访问。
 *
 * 目的：证明手机上真的能看到「配对页 → 完整 UI」，而不只是探针里断言状态码。
 *
 * 这个脚本会一直跑（等浏览器访问），按 Ctrl+C 或等它超时退出。
 *
 * 用法：
 *   ELECTRON_RUN_AS_NODE=1 "C:\Data\APP\dsh\DeepSeek Harness.exe" _probe\panel-visual.mjs
 */

import http from 'node:http'
import { mkdtemp } from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'

import { resolveConfig } from '../lib/config.js'
import { createAudit } from '../lib/audit.js'
import { createDevices } from '../lib/auth/devices.js'
import { createPairing } from '../lib/auth/pairing.js'
import { createListener } from '../lib/net/listener.js'
import { createTunnel } from '../lib/net/tunnel.js'
import { createStatic } from '../lib/static.js'
import { fileURLToPath } from 'node:url'

const CLOUDFLARED = 'C:/Data/deepseek/tools/cloudflared.exe'

/** 假上游：返回一个极简 HTML，够看「配对后进了页面」即可。 */
function startUpstream() {
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' })
      res.end(`<!doctype html><html><head><meta charset="utf-8"><base href="./"><title>假 DSH</title></head>
<body style="font:16px system-ui;padding:24px">
  <h1>假 DSH Web UI</h1>
  <p>路径：<code>${req.url}</code></p>
  <p>Host 头：<code>${req.headers.host}</code></p>
  <p style="color:#080">如果看到这行，说明配对成功、前缀剥离正确、请求真的转发到了上游。</p>
</body></html>`)
    })
    server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port }))
  })
}

async function main() {
  const home = await mkdtemp(path.join(os.tmpdir(), 'rm-visual-home-'))
  process.env.DSH_HOME = home
  const upstream = await startUpstream()

  const config = resolveConfig({
    enabled: false,
    port: 0,
    pairCodeTtlSec: 900,
    tunnel: { provider: 'quick', binaryPath: CLOUDFLARED, idleTimeoutSec: 0, startTimeoutSec: 120 },
  })
  const log = (level, message) => console.log(`  [${level}] ${message}`)
  const audit = createAudit({ config, log })
  const devices = createDevices({ config, audit, log })
  await devices.ready()
  const pairing = createPairing({ config, devices, audit })

  // 必须用真的 createStatic：桩会退回到 listener.js 里内联的 FALLBACK_HTML，
  // 于是验的是兜底页而不是产品真正提供的 web/pair.html（我第一版就踩了这个坑）。
  const statics = createStatic({
    dir: fileURLToPath(new URL('../web/', import.meta.url)),
    iconFallback: fileURLToPath(new URL('../icon.svg', import.meta.url)),
    log,
  })

  let listener
  const tunnel = createTunnel({ config, log, audit, toolsDir: path.dirname(CLOUDFLARED), getPort: () => listener?.port ?? 0 })
  listener = createListener({
    config,
    devices,
    pairing,
    approvals: { poll: async () => ({ items: [], nextSeq: 0 }), pending: () => 0, decide: () => ({ ok: true }), setActive() {}, settleAll() {} },
    upstream: {
      cookieOk: true, ensure: async () => true,
      endpoint: () => ({ cookie: 'x=1' }), authority: () => `127.0.0.1:${upstream.port}`,
      origin: () => `http://127.0.0.1:${upstream.port}`, cookieHeader: () => 'x=1',
      send: async ({ path: upstreamPath, method, headers }) => new Promise((resolve, reject) => {
        const req = http.request({ hostname: '127.0.0.1', port: upstream.port, path: upstreamPath, method, headers, agent: false }, resolve)
        req.on('error', reject)
        req.end()
      }),
    },
    statics,
    audit, log, tunnel,
  })

  const { port, urls } = await listener.start()
  const started = await tunnel.start()
  const { code } = pairing.create(900)

  console.log('')
  console.log('════════════════════════════════════════════════════')
  console.log('  本地地址：' + (urls[0] ?? `http://127.0.0.1:${port}/m`))
  console.log('  公网地址：' + started.url + '/m')
  console.log('  配对码  ：' + code)
  console.log('════════════════════════════════════════════════════')
  console.log('  等浏览器访问中（10 分钟超时）...')
  console.log('')

  // 保持存活，等浏览器来访问。
  const exit = async (reason) => {
    console.log(`\n退出（${reason}）`)
    await listener.stop({ resumeApprovals: false }).catch(() => {})
    await tunnel.close('visual-done').catch(() => {})
    upstream.server.close()
    process.exit(0)
  }
  process.on('SIGINT', () => { void exit('SIGINT') })
  process.on('SIGTERM', () => { void exit('SIGTERM') })
  setTimeout(() => { void exit('10 分钟超时') }, 600_000)
}

main().catch((error) => {
  console.error('探针异常：', error)
  process.exit(1)
})
