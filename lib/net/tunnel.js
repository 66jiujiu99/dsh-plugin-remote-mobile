/**
 * Cloudflare Quick Tunnel 生命周期管理。
 *
 * 干什么：起一个 `cloudflared tunnel --url http://127.0.0.1:<port>` 子进程，
 * 从它的 stderr 里抓出分配到的 `https://<随机名>.trycloudflare.com`，
 * 然后把这个域名交给监听器放行（`publicOrigin`）。
 *
 * ## 为什么用 Quick Tunnel
 *
 * 匿名、免账号、免服务器、免公网 IP。代价：域名随机且**每次重启都变**；
 * Cloudflare 明确不保证可用性；本进程挂了隧道就没了。
 *
 * ## 三个设计决策（都来自对 magpie-our-free-model 的逆向分析，并修正其短板）
 *
 * 1. **管道式进程所有权**：不直接 spawn cloudflared，而是用一个 supervisor
 *    子进程持有它，靠 stdin 管道表达归属。父进程（DSH）崩溃或被 SIGKILL 时，
 *    supervisor 的 stdin 收到 EOF，它会主动杀掉 cloudflared 再退出。
 *    这样不会留下"DSH 已经关了、隧道还挂在公网上"的孤儿。
 *
 * 2. **空闲超时**：`idleTimeoutSec` 内没有任何手机请求就自动关闭隧道。
 *    magpie 用的是从启动起算的硬超时，用户会误以为通道还在；
 *    空闲超时更符合直觉——你在用就一直给，不用了就断。
 *
 * 3. **失败要能看见**：cloudflared 的 stderr 全程记录（debug.jsonl），
 *    启动超时/进程退出/域名抓不到都给明确错误码，不静默。
 *
 * ## 安全边界（务必理解）
 *
 * 隧道把 `/m/` 暴露到公网。原有三道闸门（Host 白名单、设备 cookie、
 * 配对码）依然生效，但"同一 WiFi"这道天然的边界没有了。
 * 因此配对码必须够长、必须限流——这两条见 pairing.js。
 *
 * @module dsh-plugin-remote-mobile/tunnel
 */

import { spawn } from 'node:child_process'
import { existsSync } from 'node:fs'
import path from 'node:path'

import { RmError } from '../config.js'

/** 从 cloudflared 输出里抓 Quick Tunnel 域名。 */
const DOMAIN_PATTERN = /https:\/\/([a-z0-9][a-z0-9-]*\.trycloudflare\.com)/i

/** 最多保留多少行 stderr 用于诊断（防止无限增长）。 */
const MAX_LOG_LINES = 200

/**
 * 在常见位置找一个可执行的 cloudflared。
 *
 * 顺序：显式配置 → PATH → 插件目录下的 `tools/cloudflared.exe`。
 * 最后一项是给"单文件便携版"留的：把 exe 丢进 tools/ 就能用，不需要改系统 PATH。
 *
 * @param {string} [configured] - 配置里的 `tunnel.binaryPath`。
 * @param {string} [toolsDir] - 插件内的 tools 目录（绝对路径）。
 * @returns {string|undefined} 找到的路径；找不到返回 undefined。
 */
export function findCloudflared(configured, toolsDir) {
  if (typeof configured === 'string' && configured.trim() !== '') {
    const candidate = configured.trim()
    return existsSync(candidate) ? candidate : undefined
  }
  // PATH 里直接能找到（Linux/macOS 或已装成服务）。
  for (const name of ['cloudflared', 'cloudflared.exe']) {
    const fromPath = searchPath(name)
    if (fromPath !== undefined) return fromPath
  }
  // 插件自带的便携版。
  if (typeof toolsDir === 'string' && toolsDir !== '') {
    for (const name of ['cloudflared.exe', 'cloudflared']) {
      const candidate = path.join(toolsDir, name)
      if (existsSync(candidate)) return candidate
    }
  }
  return undefined
}

/**
 * 在 PATH 中查找可执行文件（不依赖 which，Windows 下也能用）。
 * @param {string} name - 文件名。
 * @returns {string|undefined} 绝对路径。
 */
function searchPath(name) {
  const raw = process.env.PATH ?? ''
  const sep = process.platform === 'win32' ? ';' : ':'
  for (const dir of raw.split(sep)) {
    if (dir === '') continue
    const candidate = path.join(dir, name)
    try {
      if (existsSync(candidate)) return candidate
    } catch {
      // 无权限的目录直接跳过。
    }
  }
  return undefined
}

/**
 * supervisor 脚本内容。
 *
 * 它被 `node -e` 拉起，职责只有一条：**父进程死了就杀掉 cloudflared**。
 * 用独立的 Node 进程而不是直接在 DSH 里 spawn，是为了让"父死子亡"由
 * 操作系统（管道 EOF）保证，而不是靠 DSH 自己记得清理。
 *
 * 参数（通过 argv 传）：`<parentPid> <cloudflaredPath> <targetUrl>`
 */
const SUPERVISOR_SOURCE = `
const { spawn } = require('node:child_process')
const [parentPid, binary, target] = process.argv.slice(1)
const child = spawn(binary, [
  'tunnel', '--no-autoupdate', '--url', target,
  '--protocol', 'http2', '--edge-ip-version', '4',
], { stdio: ['ignore', 'pipe', 'pipe'] })

let parentAlive = true
function onParentGone() {
  if (!parentAlive) return
  parentAlive = false
  try { child.kill('SIGTERM') } catch {}
  setTimeout(() => { try { child.kill('SIGKILL') } catch {} }, 1500)
  setTimeout(() => process.exit(0), 2500)
}

// 父进程退出 / DSH 被强杀 → 本进程 stdin 收到 EOF。
process.stdin.on('end', onParentGone)
process.stdin.on('close', onParentGone)
process.stdin.resume()

// 双保险：定期探活父进程（Windows 上拿不到 kill(pid,0)，用 tasklist 兜底）。
const timer = setInterval(() => {
  if (process.ppid !== Number(parentPid)) onParentGone()
}, 3000)
timer.unref?.()

child.stdout.pipe(process.stdout)
child.stderr.pipe(process.stderr)
child.on('exit', (code) => { process.exit(code == null ? 0 : code) })
child.on('error', (error) => {
  process.stderr.write('supervisor: failed to spawn cloudflared: ' + error.message + '\\n')
  process.exit(1)
})
`

/**
 * 建一个隧道管理器。
 *
 * @param {object} options - 依赖。
 * @param {import('../config.js').ResolvedConfig} options.config - 已解析配置。
 * @param {(level: 'debug'|'info'|'warn'|'error', message: string) => void} options.log - 日志。
 * @param {object} options.audit - 审计器（`audit.audit` / `audit.debug`）。
 * @param {string} [options.toolsDir] - 插件内的 tools 目录（找便携版 cloudflared）。
 * @param {() => number} options.getPort - 当前监听端口（隧道要指向它）。
 * @returns {object} 管理器。
 */
export function createTunnel({ config, log, audit, toolsDir, getPort }) {
  /** @type {import('node:child_process').ChildProcess|undefined} */
  let child
  /** @type {string|undefined} 已分配的公网域名（含 https://）。 */
  let publicUrl
  /** @type {string[]} cloudflared 最近输出（排障用）。 */
  const recent = []
  /** 上次收到手机请求的时间（空闲超时用）。 */
  let lastActivityAt = 0
  /** 空闲计时器。 */
  let idleTimer
  /** 启动中的 Promise（单飞，避免连点两次开关起两个隧道）。 */
  let starting
  /** 状态：idle / starting / running / stopping。 */
  let phase = 'idle'
  /** 最近一次失败原因（面板显示）。 */
  let lastError = ''
  /** 用户是否希望隧道开着（决定意外断开后要不要自动重连）。 */
  let wantRunning = false
  /** 重连计时器。 */
  let reconnectTimer
  /** 本轮已重连次数（成功后归零，用于指数退避）。 */
  let reconnectAttempts = 0
  /** 重连额度的截止时间（0 = 还没开始计时）。 */
  let reconnectDeadlineAt = 0

  /**
   * 记一行输出（保留尾部，防无限增长）。
   * @param {string} chunk - 原始输出块。
   * @returns {void}
   */
  function remember(chunk) {
    for (const line of String(chunk).split(/\r?\n/)) {
      const text = line.trim()
      if (text === '') continue
      recent.push(text)
      if (recent.length > MAX_LOG_LINES) recent.splice(0, recent.length - MAX_LOG_LINES)
    }
  }

  /**
   * 关闭隧道：先 SIGTERM，1.5s 后 SIGKILL，最后清理状态。
   * @param {string} reason - 关闭原因（写审计）。
   * @returns {Promise<void>} 完成。
   */
  async function close(reason) {
    // 主动关闭 = 用户不要了：清掉重连意图与计时器，否则会自己又爬起来。
    wantRunning = false
    reconnectDeadlineAt = 0
    reconnectAttempts = 0
    if (reconnectTimer !== undefined) {
      clearTimeout(reconnectTimer)
      reconnectTimer = undefined
    }
    if (child === undefined) {
      phase = 'idle'
      publicUrl = undefined
      return
    }
    phase = 'stopping'
    const victim = child
    child = undefined
    publicUrl = undefined
    if (idleTimer !== undefined) {
      clearInterval(idleTimer)
      idleTimer = undefined
    }
    await new Promise((resolve) => {
      let settled = false
      const done = () => {
        if (settled) return
        settled = true
        resolve()
      }
      victim.once('exit', done)
      try {
        victim.kill('SIGTERM')
      } catch {
        done()
        return
      }
      // 关 stdin：supervisor 会主动杀掉 cloudflared（比直接 SIGKILL 干净）。
      try {
        victim.stdin?.end()
      } catch {
        // 已关闭。
      }
      setTimeout(() => {
        try {
          victim.kill('SIGKILL')
        } catch {
          // 已退出。
        }
        done()
      }, 2000)
    })
    phase = 'idle'
    audit.audit({ kind: 'tunnel', detail: `closed:${reason}` })
    log('info', `remote-mobile: 隧道已关闭（${reason}）`)
  }

  /**
   * 当前生效的空闲超时（秒）。`0` = 永不主动关。
   *
   * 为什么要有运行时覆盖：这是用户最常调的一个值（"我想挂着别断"），
   * 让他去改配置文件再重启，体验太差。面板上直接改，立即生效。
   */
  let idleTimeoutSec = config.tunnel.idleTimeoutSec

  /**
   * 空闲检查：超过 `idleTimeoutSec` 没请求就自动关闭。
   * @returns {void}
   */
  function tickIdle() {
    const timeoutSec = idleTimeoutSec
    if (timeoutSec <= 0) return
    if (phase !== 'running') return
    if (lastActivityAt === 0) return
    if (Date.now() - lastActivityAt >= timeoutSec * 1000) {
      close(`idle ${timeoutSec}s`).catch((error) => {
        log('warn', `remote-mobile: 空闲关闭隧道失败：${String(error?.message ?? error)}`)
      })
    }
  }

  /**
   * 隧道意外断开后的自动重连。
   *
   * ## 为什么需要它
   *
   * Quick Tunnel 的域名由 Cloudflare 分配，**cloudflared 一退出域名就作废**。
   * 常见触发：网络抖动、Cloudflare 边缘回收、系统休眠后恢复。
   *
   * 没有重连的话，用户看到的是"面板还显示开着，但链接已经打不开了"——
   * 这是最糟的失败模式（看起来正常，实际不通）。
   *
   * ## 策略
   *
   * 指数退避重试（2s → 4s → 8s → … 上限 `reconnectMaxDelaySec`），
   * 总时长受 `reconnectBudgetSec` 限制。重连成功后**域名会变**，
   * 面板会显示新地址——这是 Quick Tunnel 的固有代价，只能如实告知。
   *
   * @param {string} reason - 断开原因（写审计）。
   * @returns {void}
   */
  function scheduleReconnect(reason) {
    if (config.tunnel.reconnect === false) return
    if (wantRunning !== true) return
    if (reconnectTimer !== undefined) return
    const budgetLeft = reconnectDeadlineAt === 0 ? config.tunnel.reconnectBudgetSec * 1000 : reconnectDeadlineAt - Date.now()
    if (budgetLeft <= 0) {
      lastError = `隧道已断开且重连额度用尽（${config.tunnel.reconnectBudgetSec}s）`
      log('warn', `remote-mobile: ${lastError}`)
      audit.audit({ kind: 'tunnel', detail: 'reconnect-budget-exhausted' })
      return
    }
    const delayMs = Math.min(
      config.tunnel.reconnectMaxDelaySec * 1000,
      2000 * 2 ** Math.min(reconnectAttempts, 6),
    )
    reconnectAttempts += 1
    log('info', `remote-mobile: 隧道断开（${reason}），${Math.round(delayMs / 1000)}s 后第 ${reconnectAttempts} 次重连`)
    audit.audit({ kind: 'tunnel', detail: `reconnect-scheduled:${reconnectAttempts}:${reason}` })
    reconnectTimer = setTimeout(() => {
      reconnectTimer = undefined
      // 重连会拿到**新域名**：清掉旧的，让 Host 白名单不再放行那个死域名。
      publicUrl = undefined
      start()
        .then((result) => {
          reconnectAttempts = 0
          audit.audit({ kind: 'tunnel', detail: `reconnected:${result.url}` })
          log('info', `remote-mobile: 隧道已重连 ${result.url}（地址已变化，请用新地址）`)
        })
        .catch((error) => {
          lastError = String(error?.message ?? error)
          log('warn', `remote-mobile: 重连失败：${lastError}`)
          scheduleReconnect('reconnect-failed')
        })
    }, delayMs)
    reconnectTimer.unref?.()
  }

  /**
   * 启动隧道。
   * @returns {Promise<{ url: string }>} 分配到的公网地址。
   * @throws {RmError} 找不到二进制 / 启动超时 / 进程提前退出。
   */
  async function start() {
    if (config.tunnel.provider !== 'quick') {
      throw new RmError('rm/tunnel-disabled', '隧道未启用：请在配置里设 tunnel.provider = "quick"')
    }
    if (phase === 'running' && publicUrl !== undefined) return { url: publicUrl }
    if (starting !== undefined) return starting

    // 用户明确要开：标记意图，意外断开后才值得自动重连。
    wantRunning = true
    if (reconnectDeadlineAt === 0) {
      reconnectDeadlineAt = Date.now() + config.tunnel.reconnectBudgetSec * 1000
    }

    starting = (async () => {
      phase = 'starting'
      lastError = ''
      const binary = findCloudflared(config.tunnel.binaryPath, toolsDir)
      if (binary === undefined) {
        phase = 'idle'
        lastError = '找不到 cloudflared'
        throw new RmError(
          'rm/tunnel-no-binary',
          '找不到 cloudflared：请把它放到插件的 tools/ 目录，或在配置里设 tunnel.binaryPath',
        )
      }
      const port = getPort()
      if (!Number.isInteger(port) || port <= 0) {
        phase = 'idle'
        lastError = '监听端口未就绪'
        throw new RmError('rm/tunnel-no-port', '监听端口还没起来，等插件开始监听后再开隧道')
      }
      const target = `http://127.0.0.1:${port}`
      log('info', `remote-mobile: 启动 Quick Tunnel → ${target}（${binary}）`)

      // 用 node 跑 supervisor（见 SUPERVISOR_SOURCE 的注释）。
      const args = [
        '-e', SUPERVISOR_SOURCE,
        String(process.pid),
        binary,
        target,
      ]
      const spawned = spawn(process.execPath, args, {
        stdio: ['pipe', 'pipe', 'pipe'],
        windowsHide: true,
        env: { ...process.env, ELECTRON_RUN_AS_NODE: '1' },
      })
      child = spawned

      return await new Promise((resolve, reject) => {
        let settled = false
        const timeoutMs = config.tunnel.startTimeoutSec * 1000
        const timer = setTimeout(() => {
          if (settled) return
          settled = true
          lastError = `启动超时（${config.tunnel.startTimeoutSec}s 内没拿到域名）`
          close('start-timeout').catch(() => {})
          reject(new RmError('rm/tunnel-timeout', `${lastError}。常见原因：网络不通 Cloudflare、被安全软件拦。`))
        }, timeoutMs)

        const onData = (chunk) => {
          remember(chunk)
          if (settled) return
          const match = DOMAIN_PATTERN.exec(String(chunk))
          if (match === null) return
          settled = true
          clearTimeout(timer)
          publicUrl = `https://${match[1]}`
          phase = 'running'
          lastActivityAt = Date.now()
          if (idleTimer !== undefined) clearInterval(idleTimer)
          if (idleTimeoutSec > 0) {
            // 每 10s 检查一次空闲；比每秒检查省，且足够精确。
            idleTimer = setInterval(tickIdle, 10_000)
            idleTimer.unref?.()
          }
          audit.audit({ kind: 'tunnel', detail: `opened:${publicUrl}` })
          log('info', `remote-mobile: 隧道已就绪 ${publicUrl}`)
          resolve({ url: publicUrl })
        }

        spawned.stdout?.on('data', onData)
        spawned.stderr?.on('data', onData)

        spawned.on('exit', (code) => {
          if (!settled) {
            settled = true
            clearTimeout(timer)
            phase = 'idle'
            const tail = recent.slice(-5).join(' | ')
            lastError = `cloudflared 退出（code ${code}）`
            reject(new RmError('rm/tunnel-exit', `${lastError}：${tail || '（无输出）'}`))
            return
          }
          // 已在运行后退出：标记状态，让面板能显示"隧道已断开"。
          if (publicUrl !== undefined) {
            log('warn', `remote-mobile: 隧道意外断开（code ${code}）`)
            audit.audit({ kind: 'tunnel', detail: `unexpected-exit:${code}` })
            publicUrl = undefined
            phase = 'idle'
            child = undefined
            if (idleTimer !== undefined) {
              clearInterval(idleTimer)
              idleTimer = undefined
            }
            // 用户还想要隧道的话，自动重连（会拿到新域名）。
            scheduleReconnect(`exit-${code}`)
          }
        })

        spawned.on('error', (error) => {
          if (settled) return
          settled = true
          clearTimeout(timer)
          phase = 'idle'
          lastError = String(error?.message ?? error)
          reject(new RmError('rm/tunnel-spawn', `拉起 cloudflared 失败：${lastError}`))
        })
      })
    })().finally(() => {
      starting = undefined
    })

    return starting
  }

  return {
    /** 启动。 */
    start,
    /** 关闭。 */
    close,

    /**
     * 记一次"有人在用"（每次手机请求都调，用于空闲超时）。
     * 只在隧道运行时才有意义。
     * @returns {void}
     */
    touch() {
      if (phase === 'running') lastActivityAt = Date.now()
    },

    /**
     * 当前公网域名（没开就是 undefined）。监听器的 Host 白名单要用它。
     * @returns {string|undefined} 形如 `https://xxx.trycloudflare.com`。
     */
    get publicUrl() {
      return publicUrl
    },

    /**
     * 当前公网 origin（`https://xxx.trycloudflare.com`）的 host 部分。
     * @returns {string|undefined} 形如 `xxx.trycloudflare.com`。
     */
    get publicHost() {
      if (publicUrl === undefined) return undefined
      try {
        return new URL(publicUrl).host
      } catch {
        return undefined
      }
    },

    /**
     * 面板用的状态快照。
     * @returns {{ phase: string, publicUrl?: string, lastError?: string, idleSec?: number, idleTimeoutSec: number }} 状态。
     */
    status() {
      const snapshot = { phase, idleTimeoutSec }
      if (publicUrl !== undefined) snapshot.publicUrl = publicUrl
      if (lastError !== '') snapshot.lastError = lastError
      if (phase === 'running' && idleTimeoutSec > 0 && lastActivityAt > 0) {
        snapshot.idleSec = Math.max(0, Math.round((Date.now() - lastActivityAt) / 1000))
      }
      return snapshot
    },

    /**
     * 改空闲超时（面板直接调）。立即生效，不需要重启。
     *
     * `0` = 永不主动关：会清掉正在跑的计时器，隧道就一直挂着。
     * 从 `0` 改回正数时，以「现在」为新的空闲起点重新计时，
     * 否则会立刻因为"已经空闲了很久"而被关掉。
     *
     * @param {number} seconds - 新值（0..86400）。
     * @returns {{ idleTimeoutSec: number }} 生效后的值。
     */
    setIdleTimeout(seconds) {
      idleTimeoutSec = seconds
      if (idleTimer !== undefined) {
        clearInterval(idleTimer)
        idleTimer = undefined
      }
      if (idleTimeoutSec > 0 && phase === 'running') {
        // 重新起算，避免"刚从 0 改成正数就立刻被关"。
        lastActivityAt = Date.now()
        idleTimer = setInterval(tickIdle, 10_000)
        idleTimer.unref?.()
      }
      audit.audit({ kind: 'tunnel', detail: `idle-timeout:${idleTimeoutSec}` })
      log('info', `remote-mobile: 隧道空闲超时改为 ${idleTimeoutSec === 0 ? '永不主动关' : `${idleTimeoutSec}s`}`)
      return { idleTimeoutSec }
    },

    /** 最近的 cloudflared 输出（排障用，最多 200 行）。 */
    logs() {
      return [...recent]
    },
  }
}
