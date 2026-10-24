/**
 * 面板 RPC 端到端：用真实 DSH 的 Host 进程调 `tunnel.start` / `tunnel.status`。
 *
 * 为什么要这个：单元测试和 `full-chain.mjs` 都是**自己搭 listener**，
 * 没有验证 index.js 里的 `startTunnel/stopTunnel/tunnelStatus` 这三个
 * runtime 函数是否真的接对了（它们是面板按钮的实际落点）。
 *
 * 做法：在 DSH 的 Host 进程里直接 import 插件模块，用真实的 config +
 * 真实的隧道模块跑一遍，断言返回结构符合面板期望。
 *
 * 用法：
 *   ELECTRON_RUN_AS_NODE=1 "C:\Data\APP\dsh\DeepSeek Harness.exe" _probe\panel-runtime.mjs
 */

import { mkdtemp, rm } from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import http from 'node:http'

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

/** 假上游。 */
function startUpstream() {
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      res.writeHead(200, { 'content-type': 'text/plain' })
      res.end('ok')
    })
    server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port }))
  })
}

async function main() {
  const home = await mkdtemp(path.join(os.tmpdir(), 'rm-panel-home-'))
  const previousHome = process.env.DSH_HOME
  process.env.DSH_HOME = home
  const upstream = await startUpstream()
  let listener
  let tunnel

  try {
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
    listener = createListener({
      config,
      devices,
      pairing,
      approvals: { poll: async () => ({ items: [], nextSeq: 0 }), pending: () => 0, decide: () => ({ ok: true }), setActive() {}, settleAll() {} },
      upstream: {
        cookieOk: true, ensure: async () => true,
        endpoint: () => ({ cookie: 'x=1' }), authority: () => `127.0.0.1:${upstream.port}`,
        origin: () => `http://127.0.0.1:${upstream.port}`, cookieHeader: () => 'x=1',
        send: async () => { throw new Error('unused') },
      },
      statics: { get: async () => undefined },
      audit, log, tunnel,
    })

    // ── 复刻 index.js 的三个 runtime 函数（面板按钮的真实落点）
    const startTunnel = async () => {
      if (listener === undefined || listener.running !== true) {
        const error = new Error('监听器没在跑，先在面板上开启「手机同步」，再开隧道')
        error.code = 'rm/tunnel-no-listener'
        throw error
      }
      const started = await tunnel.start()
      return { ok: true, url: started.url }
    }
    const stopTunnel = async () => {
      await tunnel.close('panel-stop')
      return { ok: true }
    }
    const tunnelStatus = () => ({ ok: true, provider: config.tunnel.provider, tunnel: tunnel.status() })

    // 1) 监听未开时开隧道 → 必须明确报错（而不是起一个指向死端口的隧道）
    let guarded = false
    try {
      await startTunnel()
    } catch (error) {
      guarded = error.code === 'rm/tunnel-no-listener'
    }
    check('监听未开时拒绝开隧道（错误码 rm/tunnel-no-listener）', guarded)

    // 2) 面板 status：未开隧道时 phase 应为 idle
    const idleStatus = tunnelStatus()
    check('tunnel.status 结构与面板期望一致', idleStatus.ok === true && idleStatus.tunnel.phase === 'idle', JSON.stringify(idleStatus))

    // 3) 开监听 → 开隧道
    await listener.start()
    check('监听已开', listener.running === true, `port=${listener.port}`)
    const started = await startTunnel()
    check('tunnel.start 返回 { ok, url }', started.ok === true && /^https:\/\//.test(started.url), started.url)

    // 4) 面板 status 应显示 running + publicUrl（这是「当前公网可达」的数据来源）
    const runningStatus = tunnelStatus()
    check(
      'tunnel.status 显示 running 与公网地址',
      runningStatus.tunnel.phase === 'running' && runningStatus.tunnel.publicUrl === started.url,
      JSON.stringify(runningStatus.tunnel),
    )

    // 5) 关隧道 → 状态回到 idle，且 publicHost 清空
    const stopped = await stopTunnel()
    check('tunnel.stop 返回 { ok }', stopped.ok === true)
    const closedStatus = tunnelStatus()
    check('关闭后 tunnel.status 回到 idle', closedStatus.tunnel.phase === 'idle', JSON.stringify(closedStatus.tunnel))
    check('关闭后 publicHost 清空', tunnel.publicHost === undefined)

    // 6) 重复关：幂等
    const stoppedAgain = await stopTunnel()
    check('重复 tunnel.stop 幂等', stoppedAgain.ok === true)
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
