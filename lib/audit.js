/**
 * 审计与调试落盘：`<dataDir>/audit.jsonl`、`<dataDir>/debug.jsonl`。
 *
 * 契约（PLAN §3.5.6）：一行一条 metadata，**不记 payload**（会话正文不落这里）；
 * `rpc` 类事件按「设备 + endpoint」5 秒采样，避免长列表把磁盘刷满。
 *
 * 写文件永远不阻塞调用方，也永远不让请求失败：所有失败只降级成一条
 * `log('warn', …)`（同一条消息 30 秒内只喊一次，避免磁盘满时刷屏）。
 *
 * @module dsh-plugin-remote-mobile/audit
 */

import { appendFile, mkdir, readFile, rename, rm, stat } from 'node:fs/promises'
import path from 'node:path'

import { dataDir } from './config.js'

/** 同一条告警的最小重复间隔，毫秒。 */
const WARN_THROTTLE_MS = 30_000

/** `rpc` 事件的采样窗口：同一设备同一 endpoint 5 秒内最多 1 条。 */
const RPC_SAMPLE_MS = 5_000

/** `audit.head` 单次最多返回多少行（防止面板一次拉爆）。 */
const MAX_HEAD_LINES = 500

/**
 * 建一个审计器。
 *
 * @param {object} options - 依赖。
 * @param {import('./config.js').ResolvedConfig} options.config - 已解析配置。
 * @param {(level: 'debug'|'info'|'warn'|'error', message: string) => void} options.log - 插件日志出口。
 * @returns {{
 *   dir: string,
 *   path: string,
 *   audit: (entry: Record<string, unknown>) => void,
 *   debug: (kind: string, fields?: Record<string, unknown>) => void,
 *   rpc: (event: { device: { id: string, name?: string }, ip?: string, endpoint: string, status: number, method?: string }) => void,
 *   head: (n?: number) => Promise<string[]>,
 *   flush: () => Promise<void>,
 * }} 审计器。
 */
export function createAudit({ config, log }) {
  const dir = dataDir()
  const file = path.join(dir, 'audit.jsonl')
  const debugFile = path.join(dir, 'debug.jsonl')

  /** @type {Promise<void>|undefined} */
  let directoryReady
  /** @type {Map<string, number>} */
  const lastWarnAt = new Map()
  /** @type {Map<string, number>} */
  const lastSampleAt = new Map()
  /** 当前 audit.jsonl 的估算字节数（启动时懒读一次）+ 写入量。 */
  let auditBytes = 0
  let auditBytesKnown = false
  /** 串行化写操作，保证轮转不会和 append 抢跑。 */
  let writeChain = Promise.resolve()

  /**
   * 节流告警。
   * @param {string} message - 告警正文。
   * @returns {void}
   */
  function warn(message) {
    const now = Date.now()
    const previous = lastWarnAt.get(message)
    if (previous !== undefined && now - previous < WARN_THROTTLE_MS) return
    lastWarnAt.set(message, now)
    if (lastWarnAt.size > 64) lastWarnAt.clear()
    log('warn', message)
  }

  /**
   * 确保数据目录存在（失败后允许下次重试，但告警被节流）。
   * @returns {Promise<void>} 目录就绪。
   */
  function ensureDirectory() {
    if (directoryReady === undefined) {
      directoryReady = mkdir(dir, { recursive: true }).then(
        () => undefined,
        (error) => {
          directoryReady = undefined
          warn(`remote-mobile: 无法创建数据目录 ${dir}: ${String(error?.message ?? error)}`)
          throw error
        },
      )
    }
    return directoryReady
  }

  /**
   * 读当前日志体量（只读一次，之后按写入累加）。
   * @returns {Promise<number>} 字节数。
   */
  async function currentBytes() {
    if (auditBytesKnown) return auditBytes
    try {
      const info = await stat(file)
      auditBytes = info.size
    } catch {
      auditBytes = 0
    }
    auditBytesKnown = true
    return auditBytes
  }

  /**
   * 超过阈值就轮转成 `audit.jsonl.1`（只保留一份历史）。
   * @returns {Promise<void>} 轮转完成。
   */
  async function maybeRotate() {
    if (config.audit.enabled !== true) return
    const bytes = await currentBytes()
    if (bytes < config.audit.maxBytes) return
    const backup = `${file}.1`
    try {
      await rm(backup, { force: true })
      await rename(file, backup)
    } catch (error) {
      // Windows 上目标存在会让 rename 失败，这里已经先删了；仍失败就不轮转。
      warn(`remote-mobile: 审计轮转失败: ${String(error?.message ?? error)}`)
    }
    auditBytes = 0
    auditBytesKnown = true
  }

  /**
   * 追加一行 JSON（fire-and-forget，写失败只告警）。
   * @param {string} target - 文件绝对路径。
   * @param {Record<string, unknown>} entry - 一行内容。
   * @returns {void}
   */
  function appendLine(target, entry) {
    let line
    try {
      line = `${JSON.stringify(entry)}\n`
    } catch (error) {
      warn(`remote-mobile: 审计记录无法序列化: ${String(error?.message ?? error)}`)
      return
    }
    const bytes = Buffer.byteLength(line, 'utf8')
    writeChain = writeChain
      .then(async () => {
        await ensureDirectory()
        if (target === file) {
          await maybeRotate()
          auditBytes += bytes
        }
        await appendFile(target, line, 'utf8')
      })
      .catch((error) => {
        warn(`remote-mobile: 写 ${path.basename(target)} 失败: ${String(error?.message ?? error)}`)
      })
  }

  return {
    dir,
    path: file,

    /**
     * 记一条审计（PLAN §3.5.6 的字段形状）。
     * `kind` ∈ `pair | connect | rpc | ws-open | approval | deny | revoke | kill | enabled`。
     * @param {Record<string, unknown>} entry - 除 `t` 之外的字段。
     * @returns {void}
     */
    audit(entry) {
      if (config.audit.enabled !== true) return
      appendLine(file, { t: new Date().toISOString(), ...entry })
    },

    /**
     * 记一条调试事件；`config.debug === false` 时整体关闭。
     * @param {string} kind - 事件类型。
     * @param {Record<string, unknown>} [fields] - 事件字段。
     * @returns {void}
     */
    debug(kind, fields = {}) {
      if (config.debug !== true) return
      appendLine(debugFile, { t: new Date().toISOString(), kind, ...fields })
    },

    /**
     * 记一条 `rpc` 审计，按「设备 + endpoint」5 秒采样。
     * @param {{ device: { id: string, name?: string }, ip?: string, endpoint: string, status: number, method?: string }} event - 事件。
     * @returns {void}
     */
    rpc({ device, ip, endpoint, status, method }) {
      if (config.audit.enabled !== true) return
      const key = `${device.id}\u0000${endpoint}`
      const now = Date.now()
      const previous = lastSampleAt.get(key)
      if (previous !== undefined && now - previous < RPC_SAMPLE_MS && status < 400) return
      lastSampleAt.set(key, now)
      if (lastSampleAt.size > 4096) lastSampleAt.clear()
      appendLine(file, {
        t: new Date().toISOString(),
        kind: 'rpc',
        deviceId: device.id,
        deviceName: device.name,
        ip,
        endpoint,
        method,
        status,
      })
    },

    /**
     * 读最近 `n` 行审计（PC 面板预览）。
     *
     * 语义说明：面板要的是「刚刚发生了什么」，所以取**文件尾部**的 n 行，按时间正序返回。
     * @param {number} [n] - 行数，默认 100，上限 500。
     * @returns {Promise<string[]>} 行（原始 JSON 文本）。
     */
    async head(n) {
      const limit = Math.min(Math.max(1, Number.isFinite(n) ? Math.floor(/** @type {number} */ (n)) : 100), MAX_HEAD_LINES)
      let text
      try {
        text = await readFile(file, 'utf8')
      } catch {
        return []
      }
      const lines = text.split('\n').filter((line) => line !== '')
      return lines.slice(Math.max(0, lines.length - limit))
    },

    /**
     * 等待在途写入落盘（卸载/kill switch 时用）。
     * @returns {Promise<void>} 写完。
     */
    async flush() {
      await writeChain
    },
  }
}
