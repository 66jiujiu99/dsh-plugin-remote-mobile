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
 * 流端点（只出现在 mux 的 `open` 帧里，HTTP 路径上没有它们）。
 *
 * 这份名单原来是给「自写移动页」用的，只有 4 个。改成整站反代之后，
 * 手机跑的是**完整 Web UI**，它会订阅更多流，缺一个就少一块数据：
 *
 *   - `account/watch`       → 账号状态。缺了：账号菜单空、未登录态。
 *   - `remoteAccess/follow` → 远程访问/工作区归属。缺了：**会话全落到「未分组」**。
 *   - `job/follow`          → 后台任务。缺了：任务面板空。
 *   - `speech/follow`       → 语音。缺了：只影响朗读。
 *
 * 全部是**只读订阅**（follow/watch 语义），不产生写操作，所以只读设备也放行。
 */
export const STREAM_ENDPOINTS = Object.freeze([
  'session/follow',
  'session/control',
  'workspace/follow',
  'account/watch',
  'remoteAccess/follow',
  'job/follow',
  'speech/follow',
  '$events',
])

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
    if (!STREAM_ENDPOINTS.includes(name)) {
      return {
        ok: false,
        code: 'rm/forbidden',
        message: `端点 ${name} 不是流端点，不能通过 /api/remote.mux 打开（unary 请走 POST /m/api/*）`,
      }
    }
    if (readonly) {
      // 四个流端点都是只读语义（session/follow、workspace/follow、$events、
      // session/control 的 follow 语义），只读设备整体允许。
      return { ok: true }
    }
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
