/**
 * Host 侧配置 + 插件统一的错误类型。
 *
 * 配置来自 `cordis.patch.yml` 里 `remote-mobile` 那一行的 `config`，在本模块里
 * 手写校验（不 import 任何 `@deepseek-ai/*` 包，也不依赖 Schemastery）：每多一个
 * 内部依赖，就多一条让插件加载失败的路。未知键一律拒绝，拼写错误不会被静默忽略。
 *
 * 同时导出 `RmError` 与 `statusForError()`：整个插件只有一种错误形状
 * `{ok:false, error:{code, message}}`（PROTOCOL §5），HTTP 状态由错误码映射，
 * 路由层不再各自造状态码。
 *
 * @module dsh-plugin-remote-mobile/config
 */

import os from 'node:os'
import path from 'node:path'

/** 允许出现的顶层配置键；其余一律拒绝。 */
export const CONFIG_KEYS = Object.freeze([
  'enabled',
  'bindAddress',
  'port',
  'allowedNetworks',
  'cookieMaxAgeDays',
  'pairCodeTtlSec',
  'pairMaxAttempts',
  'lanOnly',
  'tunnel',
  'approvalRouting',
  'askTimeoutMs',
  'deviceOnlineWindowMs',
  'readonlyDefaults',
  'fileAccess',
  'audit',
  'debug',
])

/**
 * `tunnel` 子对象允许的键。
 *
 * 本版实现 `quick`（Cloudflare 匿名 Quick Tunnel），`frpc` 仍只是形状预留。
 * `binaryPath` 为空时按顺序找：配置 → PATH → `<插件目录>/tools/cloudflared.exe`。
 */
export const TUNNEL_KEYS = Object.freeze([
  'provider',
  'binaryPath',
  'idleTimeoutSec',
  'startTimeoutSec',
  'serverAddr',
  'serverPort',
  'remotePort',
  'tls',
])

/** 隧道提供方：`none` 关闭 / `quick` Cloudflare 匿名隧道 / `frpc` 预留未实现。 */
export const TUNNEL_PROVIDERS = Object.freeze(['none', 'quick', 'frpc'])

/** `readonlyDefaults` 子对象允许的键。 */
export const READONLY_DEFAULT_KEYS = Object.freeze(['terminal', 'credentials', 'pluginManager', 'openInApp'])

/** `fileAccess` 子对象允许的键。 */
export const FILE_ACCESS_KEYS = Object.freeze(['mode', 'roots', 'extraDeny'])

/** `/m/api/file` 的作用域模式：`workspace`（默认，只允许 workspace 根内）/ `any`（逃生舱）。 */
export const FILE_ACCESS_MODES = Object.freeze(['workspace', 'any'])

/** `audit` 子对象允许的键。 */
export const AUDIT_KEYS = Object.freeze(['enabled', 'maxBytes'])

/** 审批路由策略的合法取值。 */
export const APPROVAL_ROUTINGS = Object.freeze(['phone-first', 'pc-first', 'off'])

/** 默认监听端口（被占用时按 {@link PORT_SCAN_SPAN} 递增再让 OS 分配）。 */
export const DEFAULT_PORT = 17_890

/** 端口被占用时向后尝试的个数：17890..17909。 */
export const PORT_SCAN_SPAN = 20

/** `/m/approvals` 长轮询的可配置上限（秒级字段由客户端给，这里兜底）。 */
export const MAX_APPROVAL_WAIT_MS = 25_000

/** 定时器上限，与 Node 允许的最大 setTimeout 延迟一致。 */
const MAX_TIMER_MS = 2_147_483_647

/**
 * 错误码 → HTTP 状态（PROTOCOL §5）。
 *
 * 所有路由都走这一张表，避免「同一个错误码在两个端点回不同状态」。
 */
export const ERROR_STATUS = Object.freeze({
  'rm/unauthorized': 401,
  'rm/forbidden': 403,
  'rm/not-found': 404,
  'rm/pair-invalid': 401,
  'rm/pair-expired': 410,
  'rm/pair-used': 410,
  'rm/pair-locked': 429,
  'rm/readonly': 403,
  'rm/file-denied': 403,
  'rm/upstream': 502,
  'rm/disabled': 503,
  'rm/bad-request': 400,
  'rm/too-large': 413,
  'rm/approval-gone': 410,
  // 隧道相关：区分「没配」「没二进制」「端口没好」「启动失败」「超时」，
  // 这样面板和日志能直接告诉用户该修哪一步，而不是一律 rm/internal。
  'rm/tunnel-disabled': 503,
  'rm/tunnel-no-binary': 503,
  'rm/tunnel-no-port': 503,
  'rm/tunnel-no-listener': 409,
  'rm/tunnel-unavailable': 503,
  'rm/tunnel-spawn': 502,
  'rm/tunnel-exit': 502,
  'rm/tunnel-timeout': 504,
  'rm/internal': 500,
})

/**
 * 插件统一错误：`code` 必须是 PROTOCOL §5 里的错误码。
 */
export class RmError extends Error {
  /**
   * @param {string} code - `rm/*` 错误码。
   * @param {string} message - 中文说明（会原样回给手机/PC 面板）。
   * @param {Record<string, unknown>} [details] - 额外诊断字段，只进日志/调试响应。
   */
  constructor(code, message, details) {
    super(message)
    this.name = 'RmError'
    this.code = Object.prototype.hasOwnProperty.call(ERROR_STATUS, code) ? code : 'rm/internal'
    this.details = details
  }

  /**
   * 对应的 HTTP 状态码。
   * @returns {number} 状态码。
   */
  get status() {
    return statusForError(this)
  }
}

/**
 * 任意异常 → HTTP 状态。
 * @param {unknown} error - 抛出的值。
 * @returns {number} 状态码。
 */
export function statusForError(error) {
  const code = typeof error?.code === 'string' ? error.code : ''
  if (Object.prototype.hasOwnProperty.call(ERROR_STATUS, code)) return ERROR_STATUS[code]
  return 500
}

/**
 * 统一失败响应体。
 * @param {unknown} error - 抛出的值（RmError / Error / 任意）。
 * @param {string} [fallbackMessage] - 非 RmError 时的兜底文案。
 * @returns {{ ok: false, error: { code: string, message: string, details?: unknown } }} 响应体。
 */
export function failureBody(error, fallbackMessage) {
  const code = typeof error?.code === 'string' && Object.prototype.hasOwnProperty.call(ERROR_STATUS, error.code)
    ? error.code
    : 'rm/internal'
  const message = typeof error?.message === 'string' && error.message !== ''
    ? error.message
    : (fallbackMessage ?? '内部错误')
  const details = error?.details === undefined ? undefined : error.details
  return details === undefined
    ? { ok: false, error: { code, message } }
    : { ok: false, error: { code, message, details } }
}

/** 配置非法时抛出的错误：message 必须说清「哪个键、要什么」。 */
export class ConfigError extends Error {
  /**
   * @param {string} message - 具体问题与可接受的取值。
   */
  constructor(message) {
    super(`dsh-plugin-remote-mobile config: ${message}`)
    this.name = 'ConfigError'
  }
}

/**
 * `$DSH_HOME`：与 DSH 其它插件一致，env 优先，否则 `~/.dsh`。
 * @returns {string} 绝对路径。
 */
export function dshHome() {
  const fromEnv = process.env.DSH_HOME
  if (typeof fromEnv === 'string' && fromEnv.trim() !== '') return path.resolve(fromEnv.trim())
  return path.join(os.homedir(), '.dsh')
}

/**
 * 本插件的数据目录（设备表、审计）：`$DSH_HOME/remote-mobile`。
 * @returns {string} 绝对路径。
 */
export function dataDir() {
  return path.join(dshHome(), 'remote-mobile')
}

/**
 * 解析后的配置（默认值已填好）。
 * @typedef {object} ResolvedConfig
 * @property {boolean} enabled - 是否立刻监听局域网。
 * @property {string} bindAddress - 监听地址（`0.0.0.0` / 具体 IP / `127.0.0.1`）。
 * @property {number} port - 首选端口；被占用时按 17890..17909 递增，再不行用 0。
 * @property {string[]} allowedNetworks - 非空时只接受这些 CIDR（覆盖默认私有网段判定）。
 * @property {number} cookieMaxAgeDays - 设备 cookie 有效期（天）。
 * @property {number} pairCodeTtlSec - 配对码有效期（秒）。
 * @property {number} pairMaxAttempts - 单个配对码允许的错误尝试次数。
 * @property {boolean} lanOnly - 本期固定 true（`tunnel` 留到下一期）。
 * @property {{ provider: string, serverAddr: string, serverPort: number, remotePort: number, tls: boolean }} tunnel - 下一期预留。
 * @property {'phone-first'|'pc-first'|'off'} approvalRouting - 审批路由策略。
 * @property {number} askTimeoutMs - 手机侧最长 hold 时间。
 * @property {number} deviceOnlineWindowMs - 多久内有请求算「在线」。
 * @property {{ terminal: boolean, credentials: boolean, pluginManager: boolean, openInApp: boolean }} readonlyDefaults - 只读默认拦截的类别。
 * @property {{ mode: 'workspace'|'any', roots: string[], extraDeny: string[] }} fileAccess - `/m/api/file` 作用域。
 * @property {{ enabled: boolean, maxBytes: number }} audit - 审计开关与轮转阈值。
 * @property {boolean} debug - 是否写 debug.jsonl。
 */

/**
 * 拒绝未实现的键。
 * @param {Record<string, unknown>} raw - 对象。
 * @param {readonly string[]} allowed - 允许的键。
 * @param {string} where - 出错时报的位置（`config` / `config.tunnel`）。
 * @returns {void}
 */
function rejectUnknownKeys(raw, allowed, where) {
  const unknown = Object.keys(raw).filter((key) => !allowed.includes(key))
  if (unknown.length > 0) {
    throw new ConfigError(
      `${where}: unknown key(s) ${unknown.map((key) => JSON.stringify(key)).join(', ')}; `
      + `accepted keys are ${allowed.map((key) => JSON.stringify(key)).join(', ')}`,
    )
  }
}

/**
 * 读一个布尔值。
 * @param {Record<string, unknown>} raw - 对象。
 * @param {string} key - 键名。
 * @param {boolean} fallback - 缺省值。
 * @param {string} [where] - 出错时报的位置。
 * @returns {boolean} 解析结果。
 */
function readBoolean(raw, key, fallback, where = 'config') {
  const value = raw[key]
  if (value === undefined || value === null) return fallback
  if (typeof value !== 'boolean') {
    throw new ConfigError(`${where}.${key} must be a boolean, got ${JSON.stringify(value)}`)
  }
  return value
}

/**
 * 读一个整数并做区间检查。
 * @param {Record<string, unknown>} raw - 对象。
 * @param {string} key - 键名。
 * @param {number} fallback - 缺省值。
 * @param {number} min - 允许的最小值。
 * @param {number} max - 允许的最大值。
 * @param {string} [where] - 出错时报的位置。
 * @returns {number} 解析结果。
 */
function readInteger(raw, key, fallback, min, max, where = 'config') {
  const value = raw[key]
  if (value === undefined || value === null) return fallback
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < min || value > max) {
    throw new ConfigError(
      `${where}.${key} must be an integer between ${min} and ${max}, got ${JSON.stringify(value)}`,
    )
  }
  return value
}

/**
 * 读一个字符串。
 * @param {Record<string, unknown>} raw - 对象。
 * @param {string} key - 键名。
 * @param {string} fallback - 缺省值。
 * @param {string} [where] - 出错时报的位置。
 * @returns {string} 解析结果。
 */
function readString(raw, key, fallback, where = 'config') {
  const value = raw[key]
  if (value === undefined || value === null) return fallback
  if (typeof value !== 'string') {
    throw new ConfigError(`${where}.${key} must be a string, got ${JSON.stringify(value)}`)
  }
  return value
}

/**
 * 读一个普通对象（用于嵌套配置）。
 * @param {Record<string, unknown>} raw - 对象。
 * @param {string} key - 键名。
 * @returns {Record<string, unknown>} 子对象（缺省为空对象）。
 */
function readObject(raw, key) {
  const value = raw[key]
  if (value === undefined || value === null) return {}
  if (typeof value !== 'object' || Array.isArray(value)) {
    throw new ConfigError(`config.${key} must be an object, got ${JSON.stringify(value)}`)
  }
  return /** @type {Record<string, unknown>} */ (value)
}

/**
 * 读 CIDR 列表（`allowedNetworks`）。
 * @param {Record<string, unknown>} raw - 对象。
 * @returns {string[]} CIDR 列表。
 */
function readNetworks(raw) {
  const value = raw.allowedNetworks
  if (value === undefined || value === null) return []
  if (!Array.isArray(value)) {
    throw new ConfigError(`allowedNetworks must be an array of CIDR strings, got ${JSON.stringify(value)}`)
  }
  if (value.length > 64) {
    throw new ConfigError(`allowedNetworks must hold at most 64 entries, got ${value.length}`)
  }
  return value.map((entry, index) => {
    if (typeof entry !== 'string' || entry.trim() === '') {
      throw new ConfigError(`allowedNetworks[${index}] must be a non-empty CIDR string, got ${JSON.stringify(entry)}`)
    }
    return entry.trim()
  })
}

/**
 * 读一个「绝对路径字符串数组」（`fileAccess.roots`）。
 * @param {Record<string, unknown>} raw - 子对象。
 * @param {string} key - 键名。
 * @param {string} where - 出错时报的位置。
 * @returns {string[]} 绝对路径列表。
 */
function readAbsolutePaths(raw, key, where) {
  const value = raw[key]
  if (value === undefined || value === null) return []
  if (!Array.isArray(value)) {
    throw new ConfigError(`${where}.${key} must be an array of absolute paths, got ${JSON.stringify(value)}`)
  }
  if (value.length > 32) {
    throw new ConfigError(`${where}.${key} must hold at most 32 entries, got ${value.length}`)
  }
  return value.map((entry, index) => {
    if (typeof entry !== 'string' || entry.trim() === '') {
      throw new ConfigError(`${where}.${key}[${index}] must be a non-empty absolute path, got ${JSON.stringify(entry)}`)
    }
    const trimmed = entry.trim()
    if (!path.isAbsolute(trimmed)) {
      throw new ConfigError(`${where}.${key}[${index}] must be an absolute path, got ${JSON.stringify(entry)}`)
    }
    return path.resolve(trimmed)
  })
}

/**
 * 读一个「非空字符串数组」（`fileAccess.extraDeny`）。
 * @param {Record<string, unknown>} raw - 子对象。
 * @param {string} key - 键名。
 * @param {string} where - 出错时报的位置。
 * @returns {string[]} 字符串列表。
 */
function readStringArray(raw, key, where) {
  const value = raw[key]
  if (value === undefined || value === null) return []
  if (!Array.isArray(value)) {
    throw new ConfigError(`${where}.${key} must be an array of strings, got ${JSON.stringify(value)}`)
  }
  if (value.length > 64) {
    throw new ConfigError(`${where}.${key} must hold at most 64 entries, got ${value.length}`)
  }
  return value.map((entry, index) => {
    if (typeof entry !== 'string' || entry.trim() === '') {
      throw new ConfigError(`${where}.${key}[${index}] must be a non-empty string, got ${JSON.stringify(entry)}`)
    }
    return entry.trim()
  })
}

/**
 * 读监听地址。`0.0.0.0` 是默认值（PLAN §3.1.4）。
 * @param {Record<string, unknown>} raw - 对象。
 * @returns {string} 监听地址。
 */
function readBindAddress(raw) {
  const value = readString(raw, 'bindAddress', '0.0.0.0')
  const trimmed = value.trim()
  if (trimmed === '') throw new ConfigError('bindAddress must not be empty; use "0.0.0.0", "::" or a literal address')
  return trimmed
}

/**
 * 校验并解析一行插件配置。
 * @param {unknown} rawConfig - 加载器行里的 `config` 值。
 * @param {{ warn?: (message: string) => void }} [options] - 可选的告警出口（非法 `fileAccess.mode`）。
 * @returns {ResolvedConfig} 填好默认值的配置。
 */
export function resolveConfig(rawConfig, options = {}) {
  const input = rawConfig === undefined || rawConfig === null ? {} : rawConfig
  if (typeof input !== 'object' || Array.isArray(input)) {
    throw new ConfigError(`config must be an object, got ${JSON.stringify(input)}`)
  }
  const raw = /** @type {Record<string, unknown>} */ (input)
  rejectUnknownKeys(raw, CONFIG_KEYS, 'config')

  const tunnelRaw = readObject(raw, 'tunnel')
  rejectUnknownKeys(tunnelRaw, TUNNEL_KEYS, 'config.tunnel')
  const provider = readString(tunnelRaw, 'provider', 'none', 'config.tunnel').trim()
  if (!TUNNEL_PROVIDERS.includes(provider)) {
    throw new ConfigError(
      `config.tunnel.provider must be one of ${TUNNEL_PROVIDERS.map((v) => JSON.stringify(v)).join(', ')}, `
      + `got ${JSON.stringify(provider)}`,
    )
  }

  const readonlyRaw = readObject(raw, 'readonlyDefaults')
  rejectUnknownKeys(readonlyRaw, READONLY_DEFAULT_KEYS, 'config.readonlyDefaults')

  const auditRaw = readObject(raw, 'audit')
  rejectUnknownKeys(auditRaw, AUDIT_KEYS, 'config.audit')

  const fileAccessRaw = readObject(raw, 'fileAccess')
  rejectUnknownKeys(fileAccessRaw, FILE_ACCESS_KEYS, 'config.fileAccess')
  const modeRaw = fileAccessRaw.mode
  let fileAccessMode = 'workspace'
  if (modeRaw !== undefined && modeRaw !== null) {
    const candidate = typeof modeRaw === 'string' ? modeRaw.trim() : ''
    if (FILE_ACCESS_MODES.includes(candidate)) {
      fileAccessMode = candidate
    } else {
      // 非法值不阻塞插件加载：落到更安全的 workspace，并明确告警。
      const message = `fileAccess.mode 非法（${JSON.stringify(modeRaw)}），已按 "workspace" 处理；`
        + `可选值：${FILE_ACCESS_MODES.map((value) => JSON.stringify(value)).join(', ')}`
      if (typeof options.warn === 'function') options.warn(message)
      else console.warn(`remote-mobile: ${message}`)
    }
  }
  const fileAccessRoots = readAbsolutePaths(fileAccessRaw, 'roots', 'config.fileAccess')
  const fileAccessExtraDeny = readStringArray(fileAccessRaw, 'extraDeny', 'config.fileAccess')

  const routing = readString(raw, 'approvalRouting', 'phone-first').trim()
  if (!APPROVAL_ROUTINGS.includes(routing)) {
    throw new ConfigError(
      `approvalRouting must be one of ${APPROVAL_ROUTINGS.map((v) => JSON.stringify(v)).join(', ')}, `
      + `got ${JSON.stringify(routing)}`,
    )
  }

  const port = readInteger(raw, 'port', DEFAULT_PORT, 0, 65_535)
  const lanOnly = readBoolean(raw, 'lanOnly', true)

  return {
    enabled: readBoolean(raw, 'enabled', false),
    bindAddress: readBindAddress(raw),
    port,
    allowedNetworks: readNetworks(raw),
    cookieMaxAgeDays: readInteger(raw, 'cookieMaxAgeDays', 180, 1, 3650),
    pairCodeTtlSec: readInteger(raw, 'pairCodeTtlSec', 60, 10, 900),
    pairMaxAttempts: readInteger(raw, 'pairMaxAttempts', 5, 1, 100),
    lanOnly,
    tunnel: {
      provider: /** @type {'none'|'quick'|'frpc'} */ (provider),
      binaryPath: readString(tunnelRaw, 'binaryPath', '', 'config.tunnel').trim(),
      idleTimeoutSec: readInteger(tunnelRaw, 'idleTimeoutSec', 1800, 0, 86_400, 'config.tunnel'),
      startTimeoutSec: readInteger(tunnelRaw, 'startTimeoutSec', 90, 10, 300, 'config.tunnel'),
      serverAddr: readString(tunnelRaw, 'serverAddr', '', 'config.tunnel').trim(),
      serverPort: readInteger(tunnelRaw, 'serverPort', 7000, 1, 65_535, 'config.tunnel'),
      remotePort: readInteger(tunnelRaw, 'remotePort', 0, 0, 65_535, 'config.tunnel'),
      tls: readBoolean(tunnelRaw, 'tls', true, 'config.tunnel'),
    },
    approvalRouting: /** @type {'phone-first'|'pc-first'|'off'} */ (routing),
    askTimeoutMs: readInteger(raw, 'askTimeoutMs', 12_000, 0, MAX_TIMER_MS),
    deviceOnlineWindowMs: readInteger(raw, 'deviceOnlineWindowMs', 45_000, 5_000, 600_000),
    fileAccess: {
      mode: /** @type {'workspace'|'any'} */ (fileAccessMode),
      roots: fileAccessRoots,
      extraDeny: fileAccessExtraDeny,
    },
    readonlyDefaults: {
      terminal: readBoolean(readonlyRaw, 'terminal', true, 'config.readonlyDefaults'),
      credentials: readBoolean(readonlyRaw, 'credentials', true, 'config.readonlyDefaults'),
      pluginManager: readBoolean(readonlyRaw, 'pluginManager', true, 'config.readonlyDefaults'),
      openInApp: readBoolean(readonlyRaw, 'openInApp', true, 'config.readonlyDefaults'),
    },
    audit: {
      enabled: readBoolean(auditRaw, 'enabled', true, 'config.audit'),
      maxBytes: readInteger(auditRaw, 'maxBytes', 2_097_152, 16_384, 1_073_741_824, 'config.audit'),
    },
    debug: readBoolean(raw, 'debug', true),
  }
}

/**
 * 一段可读的配置摘要（启动日志/自检用）。
 * @param {ResolvedConfig} config - 已解析配置。
 * @returns {{ enabled: boolean, bind: string, approvalRouting: string, fileAccess: { mode: string, roots: number, extraDeny: number } }} 摘要。
 */
export function describeConfig(config) {
  return {
    enabled: config.enabled,
    bind: `${config.bindAddress}:${config.port}`,
    approvalRouting: config.approvalRouting,
    fileAccess: {
      mode: config.fileAccess.mode,
      roots: config.fileAccess.roots.length,
      extraDeny: config.fileAccess.extraDeny.length,
    },
  }
}
