/**
 * 真实隧道端到端探针：起真 cloudflared，抓真域名，用真 HTTP 访问。
 *
 * 这个脚本**独立于 DSH**（不加载插件），只验证两件事：
 *   1. 我们的 SUPERVISOR + 域名解析在真实 cloudflared 上工作。
 *   2. 抓到的域名真的能从外部（经 Cloudflare 边缘）访问到本地服务。
 *
 * 用法：
 *   ELECTRON_RUN_AS_NODE=1 "C:\Data\APP\dsh\DeepSeek Harness.exe" _probe/tunnel-e2e.mjs
 */

import http from 'node:http'
import { existsSync } from 'node:fs'

import { createTunnel } from '../lib/net/tunnel.js'

const CLOUDFLARED = 'C:/Data/deepseek/tools/cloudflared.exe'

/** 起一个最小的本地服务器，充当"手机同步的监听器"。 */
function startLocal() {
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' })
      res.end(`local-ok:${req.url}`)
    })
    server.listen(0, '127.0.0.1', () => {
      resolve({ server, port: server.address().port })
    })
  })
}

/**
 * 用原生 https 取一个 URL。
 * @param {string} url - 目标。
 * @param {number} timeoutMs - 超时。
 * @returns {Promise<{ status: number, body: string }>} 结果。
 */
async function fetchUrl(url, timeoutMs = 20_000) {
  const { request } = await import('node:https')
  return new Promise((resolve, reject) => {
    const req = request(url, { method: 'GET', timeout: timeoutMs }, (res) => {
      let body = ''
      res.setEncoding('utf8')
      res.on('data', (chunk) => {
        body += chunk
      })
      res.on('end', () => resolve({ status: res.statusCode ?? 0, body }))
    })
    req.on('timeout', () => req.destroy(new Error('timeout')))
    req.on('error', reject)
    req.end()
  })
}

const checks = []
function check(name, ok, detail) {
  checks.push({ name, ok, detail })
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? ` — ${detail}` : ''}`)
}

async function main() {
  if (!existsSync(CLOUDFLARED)) {
    console.error(`找不到 ${CLOUDFLARED}`)
    process.exit(1)
  }

  const { server, port } = await startLocal()
  console.log(`本地服务已起：127.0.0.1:${port}`)

  const audit = { audit() {}, debug() {} }
  const tunnel = createTunnel({
    config: {
      tunnel: {
        provider: 'quick',
        binaryPath: CLOUDFLARED,
        idleTimeoutSec: 0,
        startTimeoutSec: 120,
      },
    },
    log: (level, message) => console.log(`  [${level}] ${message}`),
    audit,
    getPort: () => port,
  })

  try {
    console.log('启动隧道（真实 Cloudflare，可能要 10-60 秒）...')
    const started = await tunnel.start()
    check('拿到了 trycloudflare 域名', /^https:\/\/[a-z0-9-]+\.trycloudflare\.com$/.test(started.url), started.url)
    check('publicHost 与域名一致', tunnel.publicHost === new URL(started.url).host, tunnel.publicHost)
    console.log(`  公网地址：${started.url}`)

    // Cloudflare 边缘可能要几秒到几十秒才把 DNS 与路由铺开。
    console.log('等待边缘生效并访问（最多 90 秒）...')
    let fetched
    let lastError = ''
    const deadline = Date.now() + 90_000
    while (Date.now() < deadline) {
      try {
        fetched = await fetchUrl(`${started.url}/probe`, 15_000)
        break
      } catch (error) {
        lastError = String(error?.message ?? error)
        await new Promise((r) => setTimeout(r, 3000))
      }
    }
    if (fetched === undefined) {
      check('经公网访问到本地服务', false, lastError)
    } else {
      check('经公网访问到本地服务', fetched.status === 200 && fetched.body.includes('local-ok'), `status=${fetched.status} body=${fetched.body.slice(0, 60)}`)
    }

    check('状态为 running', tunnel.status().phase === 'running', JSON.stringify(tunnel.status()))
  } finally {
    await tunnel.close('e2e-done')
    check('关闭后 publicHost 清空', tunnel.publicHost === undefined)
    check('关闭后状态回到 idle', tunnel.status().phase === 'idle')
    server.close()
  }

  const failed = checks.filter((item) => !item.ok)
  console.log(`\n结果：${checks.length - failed.length}/${checks.length} 通过`)
  process.exit(failed.length === 0 ? 0 : 1)
}

main().catch((error) => {
  console.error('探针异常：', error)
  process.exit(1)
})
