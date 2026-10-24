/**
 * 用**真实运行中插件**的配置，验证隧道能否启动。
 *
 * 不碰运行中的 DSH：只读 profile 配置，自己起一份 listener + tunnel，
 * 走与生产完全相同的代码路径。如果这个能通，说明"点了按钮没反应"
 * 只在 UI 层（Client），不在 Host。
 */

import { readFileSync } from 'node:fs'
import http from 'node:http'
import { mkdtemp, rm } from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import { resolveConfig } from '../lib/config.js'
import { createAudit } from '../lib/audit.js'
import { createDevices } from '../lib/auth/devices.js'
import { createPairing } from '../lib/auth/pairing.js'
import { createListener } from '../lib/net/listener.js'
import { createTunnel } from '../lib/net/tunnel.js'
import { createStatic } from '../lib/static.js'

const here = path.dirname(fileURLToPath(import.meta.url))
const pluginRoot = path.join(here, '..')

/** 从一个 profile 的 cordis.yml 里抠出 remote-mobile 那一行的 config。 */
function readProfileConfig() {
  // APPDATA 是 ...\AppData\Roaming，.dsh 在用户主目录下，不是它的兄弟。
  const home = process.env.DSH_HOME ?? path.join(os.homedir(), '.dsh')
  const candidates = [
    path.join(home, 'profiles', 'desktop', 'cordis.yml'),
    path.join(os.homedir(), '.dsh', 'profiles', 'desktop', 'cordis.yml'),
  ]
  let text
  let used
  for (const file of candidates) {
    try {
      text = readFileSync(file, 'utf8')
      used = file
      break
    } catch {
      // 试下一个。
    }
  }
  if (text === undefined) return undefined
  console.log(`（读取：${used}）`)
  const lines = text.split(/\r?\n/)
  const start = lines.findIndex((line) => line.includes('name: dsh-plugin-remote-mobile'))
  if (start < 0) return undefined
  // 从 `config:` 行开始，收集缩进更深的块。
  let cfgLine = -1
  for (let i = start; i < Math.min(start + 4, lines.length); i += 1) {
    if (/^\s*config:\s*$/.test(lines[i])) { cfgLine = i; break }
  }
  if (cfgLine < 0) return undefined
  const indent = lines[cfgLine].search(/\S/)
  const body = []
  for (let i = cfgLine + 1; i < lines.length; i += 1) {
    const line = lines[i]
    if (line.trim() === '') { body.push(''); continue }
    const lineIndent = line.search(/\S/)
    if (lineIndent <= indent) break
    body.push(line.slice(indent + 2))
  }
  // 极简 YAML 解析：只为读我们自己的扁平/一层嵌套结构。
  const root = {}
  const stack = [{ indent: -1, node: root }]
  for (const raw of body) {
    if (raw.trim() === '' || raw.trim().startsWith('#')) continue
    const lineIndent = raw.search(/\S/)
    const text2 = raw.trim()
    const match = /^([A-Za-z][\w]*):\s*(.*)$/.exec(text2)
    if (!match) continue
    const [, key, valueRaw] = match
    while (stack.length > 1 && stack[stack.length - 1].indent >= lineIndent) stack.pop()
    const parent = stack[stack.length - 1].node
    if (valueRaw === '') {
      const child = {}
      parent[key] = child
      stack.push({ indent: lineIndent, node: child })
      continue
    }
    let value = valueRaw
    if (/^'.*'$/.test(value) || /^".*"$/.test(value)) value = value.slice(1, -1)
    else if (value === 'true') value = true
    else if (value === 'false') value = false
    else if (value === '[]') value = []
    else if (/^-?\d+$/.test(value)) value = Number(value)
    parent[key] = value
  }
  return root
}

const checks = []
function check(name, ok, detail) {
  checks.push({ name, ok, detail })
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? ` — ${detail}` : ''}`)
}

async function main() {
  const profileConfig = readProfileConfig()
  console.log('从 profile 读到的配置：')
  console.log(JSON.stringify(profileConfig, null, 2))
  check('profile 配置可读', profileConfig !== undefined)
  if (profileConfig === undefined) process.exit(1)

  check('enabled 为 true', profileConfig.enabled === true, String(profileConfig.enabled))
  check('tunnel.provider 为 quick', profileConfig.tunnel?.provider === 'quick', String(profileConfig.tunnel?.provider))
  check('tunnel.binaryPath 为空（走自动发现）', !profileConfig.tunnel?.binaryPath, JSON.stringify(profileConfig.tunnel?.binaryPath))

  const home = await mkdtemp(path.join(os.tmpdir(), 'rm-live-home-'))
  const previousHome = process.env.DSH_HOME
  process.env.DSH_HOME = home
  const upstream = http.createServer((req, res) => { res.writeHead(200); res.end('upstream-ok') })
  await new Promise((resolve) => upstream.listen(0, '127.0.0.1', resolve))
  const upstreamPort = upstream.address().port

  let listener
  let tunnel
  try {
    // 用**真实 profile 配置**（除了端口改成 0 避免和正在跑的实例抢 17890）。
    const config = resolveConfig({ ...profileConfig, port: 0, bindAddress: '127.0.0.1' })
    const log = (level, message) => console.log(`  [${level}] ${message}`)
    const audit = createAudit({ config, log })
    const devices = createDevices({ config, audit, log })
    await devices.ready()
    const pairing = createPairing({ config, devices, audit })

    // 关键：toolsDir 用**插件的真实 tools 目录**，验证自动发现能工作。
    tunnel = createTunnel({
      config,
      log,
      audit,
      toolsDir: path.join(pluginRoot, 'tools'),
      getPort: () => listener?.port ?? 0,
    })

    listener = createListener({
      config,
      devices,
      pairing,
      approvals: { poll: async () => ({ items: [], nextSeq: 0 }), pending: () => 0, decide: () => ({ ok: true }), setActive() {}, settleAll() {} },
      upstream: {
        cookieOk: true, ensure: async () => true,
        endpoint: () => ({ cookie: 'x=1' }), authority: () => `127.0.0.1:${upstreamPort}`,
        origin: () => `http://127.0.0.1:${upstreamPort}`, cookieHeader: () => 'x=1',
        send: async () => { throw new Error('unused') },
      },
      statics: createStatic({ dir: path.join(pluginRoot, 'web'), iconFallback: path.join(pluginRoot, 'icon.svg'), log }),
      audit, log, tunnel,
    })
    const { port } = await listener.start()
    check('listener 起来了', port > 0, `port=${port}`)

    // 用真实 profile 的 provider=quick 启动隧道。
    console.log('\n用 profile 配置启动真实隧道 ...')
    const started = await tunnel.start()
    check('隧道启动成功', /^https:\/\/[a-z0-9-]+\.trycloudflare\.com$/.test(started.url), started.url)

    // 验证隧道域名进白名单 + 公网可达。
    const viaTunnel = await new Promise((resolve, reject) => {
      const req = http.request({
        host: '127.0.0.1', port, path: '/m/x', method: 'GET',
        headers: { host: tunnel.publicHost }, timeout: 5000,
      }, (res) => { res.resume(); res.on('end', () => resolve(res.statusCode)) })
      req.on('timeout', () => req.destroy(new Error('timeout')))
      req.on('error', reject)
      req.end()
    })
    check('隧道 Host 头不被拒（不是 400）', viaTunnel !== 400, `status=${viaTunnel}`)
  } finally {
    if (listener !== undefined) await listener.stop({ resumeApprovals: false }).catch(() => {})
    if (tunnel !== undefined) await tunnel.close('probe-done').catch(() => {})
    upstream.close()
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
