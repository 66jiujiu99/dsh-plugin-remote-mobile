/**
 * 审批影子应答者 + 手机长轮询队列（PROTOCOL §3，PLAN §3.3.5 / §6.2）。
 *
 * **为什么必须在 Host 侧抢答**：`approval/request` 是**串行 waterfall**，每个 Client
 * 的 `$events` 生成各注册一个 listener，前一个不返回就阻塞后面；PC 页面先连上 →
 * 手机永远轮不到。所以插件用 `prepend: true` 抢在第一位（已实测：注册最晚却最先被
 * 调用；hold 后 `return next()` 能把链交还 PC）。
 *
 * **两道闸门**（同步求值，不拦截时 PC 零延迟）：
 *   1. 没有在线设备（`deviceOnlineWindowMs` 内有过请求）→ `next()`；
 *   2. 在线设备全是只读（无审批权限）→ `next()`。
 *
 * **hold 上限** `askTimeoutMs`（默认 12s）：超时就 `next()` 交还 PC，绝不把 Agent 卡住。
 *
 * @module dsh-plugin-remote-mobile/approvals
 */

import crypto from 'node:crypto'

import { MAX_APPROVAL_WAIT_MS, RmError } from '../config.js'

/** 手机 `decision` → 审批结果词汇（`dsh-user-approval` 的取值域）。 */
const DECISION_VALUES = Object.freeze({
  approve: 'allowed-once',
  reject: 'rejected',
  cancel: 'cancelled',
})

/** 审批结果的合法取值（PROTOCOL §3 与 `user-approval` README 一致）。 */
const OUTCOMES = Object.freeze(['allowed-once', 'rejected', 'cancelled', 'unavailable'])

/** 已结算的审批保留多久（重复裁决要能回 409 而不是 404）。 */
const SETTLED_TTL_MS = 60_000

/**
 * 手机上的一张审批卡片（`GET /m/approvals` 的 items 元素）。
 * @typedef {object} ApprovalItem
 * @property {string} id - 审批 id（`ap-<n>`）。
 * @property {number} seq - 自增序号（长轮询游标）。
 * @property {'approval'|'info'} kind - 类型。
 * @property {string} title - 标题（工具名/原因摘要）。
 * @property {string} detail - 详情（原因/展示文案）。
 * @property {Array<{ id: string, label: string, style: string }>} choices - 可选项。
 * @property {number} createdAt - 创建时间（毫秒）。
 * @property {number} deadline - 超时时间（毫秒）。
 */

/**
 * 建审批队列。
 *
 * @param {object} options - 依赖。
 * @param {import('../config.js').ResolvedConfig} options.config - 已解析配置。
 * @param {ReturnType<import('../auth/devices.js').createDevices>} options.devices - 设备表。
 * @param {ReturnType<import('../audit.js').createAudit>} options.audit - 审计器。
 * @param {(level: 'debug'|'info'|'warn'|'error', message: string) => void} options.log - 日志出口。
 * @returns {object} 审批队列 API。
 */
export function createApprovals({ config, devices, audit, log }) {
  let seq = 0
  /** @type {Map<string, {
   *   view: ApprovalItem, request: object|undefined, resolve: (outcome: string|undefined) => void,
   *   settled: boolean, timer: ReturnType<typeof setTimeout>|undefined,
   * }>} */
  const items = new Map()
  /** @type {Map<string, { at: number, outcome: string|undefined }>} */
  const settledIds = new Map()
  /** @type {Set<{ since: number, resolve: (result: { items: ApprovalItem[], nextSeq: number, aborted?: boolean }) => void, timer: ReturnType<typeof setTimeout> }>} */
  const waiters = new Set()
  /** 路由是否处于可拦截状态（由 index.js 的运行时状态决定）。 */
  let active = false

  /**
   * 清掉过期的「已结算」记录。
   * @returns {void}
   */
  function sweepSettled() {
    const now = Date.now()
    for (const [id, entry] of settledIds) {
      if (now - entry.at > SETTLED_TTL_MS) settledIds.delete(id)
    }
  }

  /**
   * 当前**可裁决**的审批（手机长轮询只该看到这些）。
   * @param {number} since - 游标。
   * @returns {ApprovalItem[]} 列表（按 seq 升序）。
   */
  function visible(since) {
    /** @type {ApprovalItem[]} */
    const result = []
    for (const entry of items.values()) {
      if (entry.settled) continue
      if (entry.view.seq <= since) continue
      result.push(entry.view)
    }
    result.sort((left, right) => left.seq - right.seq)
    return result
  }

  /**
   * 唤醒所有「有新东西」的长轮询。
   * @returns {void}
   */
  function notify() {
    for (const waiter of [...waiters]) {
      const list = visible(waiter.since)
      if (list.length === 0) continue
      waiters.delete(waiter)
      clearTimeout(waiter.timer)
      waiter.resolve({ items: list, nextSeq: seq })
    }
  }

  /**
   * 把一个审批请求转成手机卡片。
   * @param {object} request - `approval/request` 的请求对象。
   * @returns {{ view: ApprovalItem, request: object }} 卡片。
   */
  function toItem(request) {
    seq += 1
    const createdAt = Date.now()
    const toolName = typeof request?.toolName === 'string' && request.toolName !== ''
      ? request.toolName
      : '操作审批'
    const reason = typeof request?.reason === 'string' && request.reason !== ''
      ? request.reason
      : (typeof request?.displayReason === 'string' ? request.displayReason : '')
    /** @type {ApprovalItem} */
    const view = {
      id: `ap-${seq}-${crypto.randomBytes(3).toString('hex')}`,
      seq,
      kind: 'approval',
      title: toolName,
      detail: reason.slice(0, 4000),
      choices: [
        { id: 'approve', label: '同意', style: 'primary' },
        { id: 'reject', label: '拒绝', style: 'danger' },
      ],
      createdAt,
      deadline: createdAt + config.askTimeoutMs,
    }
    return { view, request }
  }

  /**
   * 入队并等待手机裁决。
   * @param {object} request - `approval/request` 请求。
   * @returns {Promise<string|undefined>} 结果值；undefined 表示超时/无人答（调用方 `next()`）。
   */
  function enqueue(request) {
    const { view } = toItem(request)
    return new Promise((resolve) => {
      /** @type {any} */
      const entry = {
        view,
        request,
        resolve,
        settled: false,
        timer: undefined,
      }
      if (config.askTimeoutMs > 0) {
        entry.timer = setTimeout(() => {
          if (entry.settled) return
          settle(entry, undefined, 'timeout')
        }, config.askTimeoutMs)
        entry.timer.unref?.()
      } else {
        // askTimeoutMs=0：等价「问一下但不 hold」。
        settle(entry, undefined, 'timeout-zero')
      }
      items.set(view.id, entry)
      audit.audit({
        kind: 'approval',
        detail: `asked tool=${view.title}`,
        endpoint: view.id,
      })
      notify()
    })
  }

  /**
   * 结算一条审批（超时/裁决/接管都走这里）。
   * @param {object} entry - 队列条目。
   * @param {string|undefined} outcome - 结果值。
   * @param {string} reason - 结算原因（写审计）。
   * @returns {void}
   */
  function settle(entry, outcome, reason) {
    if (entry.settled) return
    entry.settled = true
    if (entry.timer !== undefined) {
      clearTimeout(entry.timer)
      entry.timer = undefined
    }
    items.delete(entry.view.id)
    settledIds.set(entry.view.id, { at: Date.now(), outcome })
    sweepSettled()
    audit.debug('approval-settled', { id: entry.view.id, outcome: outcome ?? '(none)', reason })
    // 通知所有长轮询：队列变了（可能变空，也要让它们有机会看到新 seq）。
    for (const waiter of [...waiters]) {
      const list = visible(waiter.since)
      if (list.length === 0) continue
      waiters.delete(waiter)
      clearTimeout(waiter.timer)
      waiter.resolve({ items: list, nextSeq: seq })
    }
    entry.resolve(outcome)
  }

  /**
   * 推一条不可裁决的 info 卡片（pc-first 用）。
   * @param {{ title: string, detail?: string }} input - 内容。
   * @returns {void}
   */
  function announce({ title, detail }) {
    seq += 1
    const createdAt = Date.now()
    const view = {
      id: `info-${seq}-${crypto.randomBytes(3).toString('hex')}`,
      seq,
      kind: 'info',
      title: String(title ?? '提示'),
      detail: String(detail ?? ''),
      choices: [],
      createdAt,
      deadline: createdAt,
    }
    items.set(view.id, {
      view,
      request: undefined,
      resolve: () => {},
      settled: false,
      timer: undefined,
    })
    notify()
    // info 卡片 20 秒后自动退场，避免手机一直挂着过期提示。
    const timer = setTimeout(() => {
      items.delete(view.id)
    }, 20_000)
    timer.unref?.()
  }

  /**
   * 一次性把队列里的审批全部交还 PC。
   * @param {string} reason - 原因（写审计）。
   * @returns {number} 交还的条数。
   */
  function settleAllFn(reason) {
    let count = 0
    for (const entry of [...items.values()]) {
      if (entry.view.kind !== 'approval') {
        items.delete(entry.view.id)
        continue
      }
      settle(entry, undefined, reason)
      count += 1
    }
    for (const waiter of [...waiters]) {
      waiters.delete(waiter)
      clearTimeout(waiter.timer)
      waiter.resolve({ items: [], nextSeq: seq })
    }
    return count
  }

  return {
    /**
     * 注册 `approval/request` 影子应答者。
     *
     * @param {object} ctx - Cordis 上下文（root ctx 即可；实测未打 scope 标签的
     *   listener 对 agent-scoped 派发是全局放行的）。
     * @param {{ isActive: () => boolean }} deps - 运行时状态探针。
     * @returns {() => void} 注销函数。
     */
    attach(ctx, { isActive }) {
      if (config.approvalRouting === 'off') {
        log('info', 'remote-mobile: approvalRouting=off，不注册审批影子应答者')
        return () => {}
      }
      /**
       * 闸门：要不要拦截这次审批（**必须同步求值**）。
       * @returns {boolean} 结论。
       */
      function shouldIntercept() {
        if (isActive() !== true) return false
        if (config.approvalRouting !== 'phone-first') return false
        if (config.askTimeoutMs <= 0) return false
        const online = devices.online()
        if (online.length === 0) return false // 闸门 1
        return online.some((device) => device.readonly !== true) // 闸门 2
      }

      /**
       * 影子应答者本体。
       * @param {object} request - `approval/request` 请求。
       * @param {() => Promise<unknown>} next - 交还给下游 waterfall。
       * @returns {Promise<unknown>} 结果。
       */
      async function listener(request, next) {
        if (config.approvalRouting === 'pc-first') {
          // 只旁路观察：给手机一条不可裁决的提示，然后立刻交还 PC。
          seq += 1
          audit.debug('approval-observed', { tool: request?.toolName })
          try {
            announce({ title: 'PC 正在等待确认', detail: String(request?.toolName ?? '') })
          } catch {
            // 旁路失败不影响 PC。
          }
          return next()
        }
        if (!shouldIntercept()) return next()
        const outcome = await enqueue(request)
        if (outcome === undefined) return next()
        return outcome
      }

      let dispose
      try {
        // Cordis 的 options 既接受 `{prepend:true}` 也接受 `true`（内部 unshift）。
        dispose = ctx.on('approval/request', listener, { prepend: true })
      } catch (error) {
        log('warn', `remote-mobile: 注册审批影子应答者失败：${String(error?.message ?? error)}`)
        return () => {}
      }
      log(
        'info',
        `remote-mobile: 审批影子应答者已注册（${config.approvalRouting}，`
        + `hold ≤ ${config.askTimeoutMs}ms）`,
      )
      return () => {
        try {
          if (typeof dispose === 'function') dispose()
          else ctx.off?.('approval/request', listener)
        } catch {
          // 卸载期的异常没有意义。
        }
      }
    },

    /** 推一条不可裁决的 info 卡片（pc-first 用）。 */
    announce,

    /**
     * `GET /m/approvals` 的长轮询。
     *
     * @param {object} options - 参数。
     * @param {number} since - 游标（上次拿到的 `nextSeq`）。
     * @param {number} waitMs - 想挂起的毫秒数（会被夹到 [0, 25000]）。
     * @param {AbortSignal} [signal] - 手机断开时用来提前结束。
     * @returns {Promise<{ items: ApprovalItem[], nextSeq: number, aborted?: boolean }>} 结果。
     */
    poll({ since, waitMs, signal }) {
      const cursor = Number.isFinite(since) && since > 0 ? Math.floor(since) : 0
      const immediate = visible(cursor)
      if (immediate.length > 0) return Promise.resolve({ items: immediate, nextSeq: seq })
      const wait = Math.min(Math.max(0, Number.isFinite(waitMs) ? Math.floor(waitMs) : 20_000), MAX_APPROVAL_WAIT_MS)
      if (wait === 0) return Promise.resolve({ items: [], nextSeq: seq })
      return new Promise((resolve) => {
        /** @type {{ since: number, resolve: (result: { items: ApprovalItem[], nextSeq: number, aborted?: boolean }) => void, timer: ReturnType<typeof setTimeout> }} */
        const waiter = {
          since: cursor,
          resolve,
          timer: setTimeout(() => {
            waiters.delete(waiter)
            resolve({ items: [], nextSeq: seq })
          }, wait),
        }
        waiter.timer.unref?.()
        waiters.add(waiter)
        signal?.addEventListener('abort', () => {
          if (!waiters.delete(waiter)) return
          clearTimeout(waiter.timer)
          resolve({ items: [], nextSeq: seq, aborted: true })
        }, { once: true })
      })
    },

    /**
     * 手机裁决（`POST /m/approvals/<id>`）。
     *
     * @param {string} id - 审批 id。
     * @param {unknown} decision - `approve` / `reject` / `cancel` / 结果值。
     * @param {{ device: object }} context - 裁决设备（写审计）。
     * @returns {{ ok: true, settled: true, outcome: string }} 结果。
     * @throws {RmError} 重复裁决（409）/ 未知审批 / 非法 decision。
     */
    decide(id, decision, context) {
      const text = typeof decision === 'string' ? decision.trim() : ''
      if (text === '') throw new RmError('rm/bad-request', 'decision 不能为空')
      const settled = settledIds.get(id)
      if (settled !== undefined) {
        // PROTOCOL §3：重复裁决 409（错误码仍用 rm/approval-gone 表达「没有待办」）。
        const error = new RmError('rm/approval-gone', '该审批已裁决或已超时，不能重复裁决')
        error.httpStatus = 409
        throw error
      }
      const entry = items.get(id)
      if (entry === undefined) {
        throw new RmError('rm/approval-gone', '审批不存在或已过期（可能已被 PC 处理）')
      }
      if (entry.view.kind !== 'approval') {
        throw new RmError('rm/forbidden', '该条目只是提示，不可裁决')
      }
      const value = DECISION_VALUES[text] ?? (OUTCOMES.includes(text) ? text : undefined)
      if (value === undefined) {
        throw new RmError('rm/bad-request', `decision 只能是 approve / reject / cancel 之一，收到 ${JSON.stringify(decision)}`)
      }
      if (typeof entry.request?.toolName === 'string') {
        audit.audit({
          kind: 'approval',
          deviceId: context?.device?.id,
          deviceName: context?.device?.name,
          endpoint: id,
          detail: `decided ${value} tool=${entry.request.toolName}`,
        })
      }
      settle(entry, value, 'decided')
      return { ok: true, settled: true, outcome: value }
    },

    /**
     * 待裁决数量（PC 面板 `status` 用）。
     * @returns {number} 数量。
     */
    pending() {
      let total = 0
      for (const entry of items.values()) if (!entry.settled && entry.view.kind === 'approval') total += 1
      return total
    },

    /** 一次性把队列里的审批全部交还 PC（kill switch / 关闭开关 / 卸载）。 */
    settleAll: settleAllFn,

    /**
     * 运行时状态（`enabled` / kill switch）变化时同步。
     * @param {boolean} flag - 是否允许拦截。
     * @returns {void}
     */
    setActive(flag) {
      active = flag === true
      if (active !== true) settleAllFn('inactive')
    },

    /** 当前是否允许拦截（诊断用）。 */
    get isActive() {
      return active
    },

    /** 队列规模（诊断用）。 */
    stats() {
      return { seq, queued: items.size, waiting: waiters.size }
    },

    /** 卸载：清空队列并让所有等待者返回。 */
    dispose() {
      settleAllFn('dispose')
      active = false
    },
  }
}
