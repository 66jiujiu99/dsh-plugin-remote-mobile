/**
 * 只读策略与永久黑名单（PROTOCOL §4，PLAN §3.5.2）。
 *
 * 两条原则：
 *   1. **失败即拒**（fail-closed）：只读设备只允许白名单里的端点，未知端点直接 403；
 *   2. **永久黑名单不分只读/读写**：终端、凭据、插件管理这些等于系统权限的端点
 *      任何手机都不给（手机一旦能开 shell，就等于持有 PC 用户的 shell）。
 *
 * 本模块是纯函数，不碰网络也不碰设备表——监听器/WS 帧校验各自把判断结果变成
 * `403 + rm/forbidden|rm/readonly`。
 *
 * @module dsh-plugin-remote-mobile/policy
 */

import { RmError } from '../config.js'

/**
 * 永久黑名单（前缀匹配，任何设备、任何路由都不允许）。
 *
 * 对应 PROTOCOL §4 第一行：`terminal/*`、`credentials/*`、`plugin/*`、
 * `plugin-manager/*`、`remote-mobile` 自身管理 RPC。
 */
export const PERMANENT_DENY = Object.freeze([
  'terminal/',
  'credentials/',
  'plugin/',
  'plugin-manager/',
  'pluginManager/',
  'remote-mobile',
  'settings/',
])

/**
 * 只读设备允许的 unary 端点（PROTOCOL §4 第二行 + PLAN §3.5.2 的只读读取集）。
 *
 * 只列**纯读**端点；`session/attachment` 是历史图片的读取，`workspaceFiles/*`
 * 是文件读取，都在「看」的范畴内。
 */
export const READONLY_UNARY_ALLOW = Object.freeze([
  'session/list',
  'session/page',
  'session/projections',
  'session/modelCatalog',
  'session/attachment',
  'session/follow',
  'session/control',
  'workspace/list',
  'workspace/readFile',
  'workspaceFiles/read',
  'workspaceFiles/readBytes',
  'workspaceFiles/stat',
  'workspaceFiles/list',
  'commands/list',
  'goals/get',
  'permissionPresets/catalog',
  '$events',
])

/**
 * 只读设备显式禁止的 unary 端点（写操作/裁决）。
 *
 * 白名单之外本来就一律拒；这里单独列出来是为了**审计可读**（日志里能说清
 * 「因为它是写操作」而不是「因为不在白名单里」）。
 */
export const READONLY_DENY = Object.freeze([
  'session/prompt',
  'session/cancel',
  'session/updateQueue',
  'session/create',
  'session/fork',
  'session/rename',
  'session/selectModel',
  '$events/result',
  'fileUploads/upload',
  'open-in-app/',
  'directoryPicker/',
  'confirmation/',
])

/**
 * 已知的流端点（**仅供参考/诊断，不参与放行判定**）。
 *
 * 放行判定见 `isStreamEndpoint`：现在只守永久黑名单，其余交给上游。
 * 保留这份清单是为了：
 *   1. 文档价值——说明手机端会用到哪些流；
 *   2. 诊断——日志里能标出"这是已知流"。
 *
 * 历史教训：这份清单曾被当作放行白名单，结果漏了 `remoteAccess/follow`
 * （会话掉进未分组）、`workspaceFiles/changes`（文件面板不刷新）、
 * `job/list`（官方插件状态不同步）。所以它**不能**再承担放行职责。
 */
export const STREAM_ENDPOINTS = Object.freeze([
  'session/follow',
  'session/control',
  'workspace/follow',
  'account/watch',
  'account/watchExpiry',
  'remoteAccess/follow',
  'job/follow',
  'job/list',
  'speech/follow',
  'workspaceFiles/changes',
  'productAnalytics/watchPolicy',
  'userQuestions/attachWait',
  '$events',
])

/**
 * 按命名约定判断一个端点「看起来是流」。
 *
 * **这个函数已经不再用于放行判定**（见 `isStreamEndpoint` 的说明），
 * 只保留给诊断/日志用：它能标出"看起来像流但被我们拦了"的情况。
 *
 * @param {string} endpoint - 端点名（形如 `workspaceFiles/changes`）。
 * @returns {boolean} 是否看起来像流。
 */
export function looksLikeStream(endpoint) {
  if (typeof endpoint !== 'string' || endpoint === '') return false
  const tail = endpoint.includes('/') ? endpoint.slice(endpoint.lastIndexOf('/') + 1) : endpoint
  return tail === 'follow' || tail === 'watch' || tail === 'changes' || tail === 'attach' || tail === 'list'
}

/**
 * 判断端点是否可作为 mux 的 `open` 目标。
 *
 * ## 为什么不再维护"流端点白名单"
 *
 * 早期版本硬编码了一份流端点名单，结果一次次漏：先是 `remoteAccess/follow`
 * （会话掉进"未分组"），再是 `workspaceFiles/changes`（文件面板不刷新），
 * 再是 `job/list`（手机上看不到官方插件状态）。DSH 有 144 个端点，
 * 靠我们逐个跟是跟不完的，而且漏掉的表现是"某块数据悄悄不更新"，极难发现。
 *
 * ## 现在的口径
 *
 * **只守永久黑名单，其余交给上游判定。**
 *
 * - 上游自己知道哪些端点能以流方式打开；对不合法的 open，它会回错误帧，
 *   手机端 UI 会把那块的错误显示出来——比"静默不更新"好得多。
 * - 我们能守住的、也必须守住的是**永久黑名单**（终端/凭据/插件管理/设置）：
 *   这些等于系统权限，任何设备、任何通道都不给。
 *
 * 这个取舍是明确的：宁可让上游去拒一个不该开的端点，也不要因为白名单过期
 * 而让合法功能静默失效。
 *
 * @param {string} endpoint - 端点名。
 * @returns {boolean} 是否允许在流通道上打开。
 */
export function isStreamEndpoint(endpoint) {
  if (typeof endpoint !== 'string' || endpoint === '') return false
  // 永久黑名单优先：terminal/*、credentials/*、plugin/*、settings/* 等一律拒。
  if (isPermanentDenied(endpoint)) return false
  return true
}

/**
 * 端点是否命中永久黑名单。
 * @param {string} endpoint - 端点名（形如 `session/list`）。
 * @returns {boolean} 结论。
 */
export function isPermanentDenied(endpoint) {
  if (typeof endpoint !== 'string' || endpoint === '') return false
  return PERMANENT_DENY.some((prefix) => (
    prefix.endsWith('/') ? endpoint.startsWith(prefix) : endpoint === prefix || endpoint.startsWith(`${prefix}/`)
  ))
}

/**
 * 判断一个操作是否被允许。
 *
 * @param {object} input - 判断输入。
 * @param {{ id: string, name?: string, readonly?: boolean, revokedAt?: number }|undefined} input.device - 设备；undefined 表示未认证。
 * @param {'unary'|'file'|'upload'|'ws-open'|'approval'} input.kind - 操作类别。
 * @param {string} [input.endpoint] - 端点名（`unary` / `ws-open`）。
 * @returns {{ ok: true }|{ ok: false, code: string, message: string }} 结论（失败时不抛异常，方便记录审计）。
 */
export function decide({ device, kind, endpoint }) {
  if (device === undefined) {
    return { ok: false, code: 'rm/unauthorized', message: '设备未认证，请重新配对' }
  }
  if (device.revokedAt !== undefined) {
    return { ok: false, code: 'rm/unauthorized', message: '该设备已被撤销，请重新配对' }
  }
  const readonly = device.readonly === true
  const name = typeof endpoint === 'string' ? endpoint : ''

  if (kind === 'approval') {
    if (readonly) return { ok: false, code: 'rm/readonly', message: '只读设备不能裁决审批' }
    return { ok: true }
  }

  if (kind === 'upload') {
    if (readonly) return { ok: false, code: 'rm/readonly', message: '只读设备不能上传文件' }
    return { ok: true }
  }

  if (kind === 'file') {
    // 产物下载/看图：只读设备也允许（PROTOCOL §4 把读文件列为只读允许）。
    return { ok: true }
  }

  if (name === '') {
    return { ok: false, code: 'rm/bad-request', message: '缺少端点名' }
  }

  if (isPermanentDenied(name)) {
    return {
      ok: false,
      code: 'rm/forbidden',
      message: `端点 ${name} 属于永久黑名单（终端/凭据/插件管理类），手机端不开放`,
    }
  }

  if (kind === 'ws-open') {
    if (!isStreamEndpoint(name)) {
      return {
        ok: false,
        code: 'rm/forbidden',
        message: `端点 ${name} 不是流端点，不能通过 /api/remote.mux 打开（unary 请走 POST /m/api/*）`,
      }
    }
    // 流端点全是只读订阅语义（follow / watch / changes），只读设备也放行。
    return { ok: true }
  }

  // kind === 'unary'
  if (!readonly) return { ok: true }
  if (READONLY_UNARY_ALLOW.includes(name)) return { ok: true }
  if (READONLY_DENY.some((entry) => (entry.endsWith('/') ? name.startsWith(entry) : name === entry))) {
    return { ok: false, code: 'rm/readonly', message: `只读设备不能调用写操作 ${name}` }
  }
  return { ok: false, code: 'rm/readonly', message: `只读设备只允许读取类端点，${name} 不在白名单内` }
}

/**
 * 用 {@link decide} 的结果抛错（调用方只想「拒就抛」时用）。
 * @param {ReturnType<typeof decide>} verdict - 结论。
 * @returns {void}
 * @throws {RmError} 结论为拒绝时。
 */
export function assertAllowed(verdict) {
  if (verdict.ok !== true) throw new RmError(verdict.code, verdict.message)
}
