/**
 * dsh-plugin-remote-mobile —— Host 半边入口。
 *
 * 装配关系（契约见 PROTOCOL.md，设计见 ../mobile-sync/PLAN.md）：
 *
 *   ctx.webServer.getOrigin() ──▶ upstream（cookie 交换 + 头改写）──▶ 反代到上游
 *   ctx.connection.authenticatedUrl() ─┘
 *
 *   手机 ──http://<LAN-IP>:17890/m*──▶ listener ──▶ devices（设备 cookie）
 *                                       │            └─▶ policy（只读/黑名单）
 *                                       └─▶ static（web/**）
 *   手机 ──WS /api/remote.mux───────▶ listener ──▶ proxy-ws（裸透传 + ready 帧脱敏）
 *
 *   Agent 工具要审批 ──▶ ctx.on('approval/request', …, {prepend:true}) ──▶ 手机长轮询
 *                                            └─ 超时/无人答 → next() 交还 PC
 *
 *   PC 面板 ──POST /plugin/remote-mobile/rpc──▶ admin（先 requestRejection）
 *
 * 生命周期：`enabled=false`（默认）时**不绑任何非环回地址**；面板开关热生效，
 * 关闭时立刻 `server.close()` 并断开所有 socket。所有错误都不吞：路由回统一错误体，
 * 排查细节写 `debug.jsonl`。
 *
 * @module dsh-plugin-remote-mobile
 */

import { fileURLToPath } from 'node:url'

import { createApprovals } from './lib/approval/queue.js'
import { createDevices } from './lib/auth/devices.js'
import { createPairing } from './lib/auth/pairing.js'
import { createAudit } from './lib/audit.js'
import { registerRoutes } from './lib/admin/routes.js'
import { buildUrls } from './lib/net/lan.js'
import { createListener } from './lib/net/listener.js'
import { createUpstream } from './lib/net/upstream.js'
import { createStatic } from './lib/static.js'
import { describeConfig, resolveConfig } from './lib/config.js'

/** 插件名（与 package.json / cordis.patch.yml 的行 id 对齐）。 */
export const name = 'dsh-plugin-remote-mobile'

/**
 * 取一个可用的 logger：Cordis 的 `ctx.logger` 既可能是「可调用的命名工厂」，
 * 也可能是带 `info/warn/error` 方法的对象，两种都兜住；都没有就退回 console。
 * @param {object} ctx - Cordis 上下文。
 * @returns {{ debug: Function, info: Function, warn: Function, error: Function }} 日志出口。
 */
function pickLogger(ctx) {
  const raw = ctx?.logger
  let target = raw
  if (typeof raw === 'function') {
    try {
      const named = raw.call(ctx, name)
      if (named !== undefined && named !== null) target = named
    } catch {
      target = raw
    }
  }
  /**
   * 写一条日志。
   * @param {string} level - 级别。
   * @param {string} message - 正文。
   * @returns {void}
   */
  const write = (level, message) => {
    const method = target?.[level]
    if (typeof method === 'function') {
      try {
        method.call(target, message)
        return
      } catch {
        // 落到 console。
      }
    }
    if (level === 'error' || level === 'warn') console.warn(message)
    else console.log(message)
  }
  return {
    debug: (message) => write('debug', message),
    info: (message) => write('info', message),
    warn: (message) => write('warn', message),
    error: (message) => write('error', message),
  }
}

/**
 * 插件入口。
 * @param {object} ctx - Cordis 上下文。
 * @param {unknown} rawConfig - `cordis.patch.yml` 里该行的 `config`。
 * @returns {void}
 */
export function apply(ctx, rawConfig) {
  const logger = pickLogger(ctx)
  // 配置非法直接抛：带着明确的键名失败，比加载出半个插件好排查。
  // `fileAccess.mode` 非法只告警不抛（落到更安全的 workspace），所以先建 logger。
  const config = resolveConfig(rawConfig, {
    warn: (message) => logger.warn(`remote-mobile: ${message}`),
  })

  /**
   * 写一条日志。
   * @param {'debug'|'info'|'warn'|'error'} level - 级别。
   * @param {string} message - 正文。
   * @returns {void}
   */
  const log = (level, message) => {
    const write = logger[level] ?? logger.info
    write(message)
  }

  const audit = createAudit({ config, log })
  const devices = createDevices({ config, audit, log })
  const pairing = createPairing({ config, devices, audit })
  const approvals = createApprovals({ config, devices, audit, log })

  /** 运行时状态：`enabled` 是用户意图，`killSwitch` 是急停状态。 */
  const state = {
    enabled: config.enabled === true,
    killSwitch: false,
  }

  /** @type {ReturnType<typeof createUpstream>|undefined} */
  let upstream
  /** @type {ReturnType<typeof createListener>|undefined} */
  let listener

  /**
   * 审批影子应答者是否该出手（两道闸门在 queue 里求值，这里只给运行时状态）。
   * @returns {boolean} 结论。
   */
  const isActive = () => state.enabled === true
    && state.killSwitch !== true
    && listener !== undefined
    && listener.running === true

  /**
   * 按当前状态对齐监听器（热启停）。
   * @returns {Promise<void>} 完成。
   */
  async function syncListener() {
    if (listener === undefined) return
    if (state.enabled === true && state.killSwitch !== true) {
      if (upstream !== undefined) {
        // 先换 cookie：失败也继续起监听器（`/m/ping` 会如实报 upstreamOk=false）。
        try {
          await upstream.ensure()
        } catch {
          // ensure() 内部已记录。
        }
      }
      if (listener.running !== true) {
        const started = await listener.start()
        log('info', `remote-mobile: 监听已开启，端口 ${started.port}，手机地址 ${started.urls[0] ?? '(无 LAN 地址)'}`)
      }
    } else if (listener.running === true) {
      const stopped = await listener.stop()
      log('info', `remote-mobile: 监听已关闭（断开 ${stopped.closed} 条连接）`)
    }
    approvals.setActive(isActive())
  }

  /**
   * 面板开关（`set.enabled`）：会同时解除 kill switch。
   * @param {boolean} enabled - 是否开启。
   * @returns {Promise<{ enabled: boolean, port: number, urls: string[] }>} 结果。
   */
  async function setEnabled(enabled) {
    const next = enabled === true
    state.enabled = next
    if (next) state.killSwitch = false
    await syncListener()
    audit.audit({ kind: 'enabled', detail: `enabled=${state.enabled} killSwitch=${state.killSwitch}` })
    return {
      enabled: state.enabled,
      port: listener?.port ?? 0,
      urls: listener?.urls() ?? [],
    }
  }

  /**
   * kill switch（PROTOCOL §2 / PLAN §3.5.3）：急停。关监听器 + 断开全部 socket
   * + 清空审批队列。设备表**保留**——kill 只是「立刻断开、可恢复」，撤销设备是
   * 另一个独立操作 `devices.revokeAll`（不可逆、会断开全部在途连接）。
   * `enabled` 保持用户意图，`killSwitch=true`，之后 `set.enabled true` 可重开。
   * @returns {Promise<{ closed: number }>} 结果。
   */
  async function kill() {
    state.killSwitch = true
    approvals.settleAll('kill-switch')
    const stopped = listener === undefined ? { closed: 0 } : await listener.stop()
    audit.audit({ kind: 'kill', detail: `closed ${stopped.closed} socket(s), devices kept` })
    log('warn', `remote-mobile: kill switch 已执行（断开 ${stopped.closed} 个连接，设备表保留）`)
    return { closed: stopped.closed }
  }

  /**
   * 组装面板 `status`（PROTOCOL §2）。
   * @returns {object} status。
   */
  function status() {
    return {
      enabled: state.enabled,
      port: listener?.port ?? 0,
      urls: listener?.urls() ?? [],
      lanIps: listener?.lanIps() ?? [],
      upstreamOk: listener?.running === true && upstream?.cookieOk === true,
      cookieOk: upstream?.cookieOk === true,
      devices: devices.list(),
      pendingApprovals: approvals.pending(),
      killSwitch: state.killSwitch,
      pair: pairing.current(),
      version: '0.1.0',
    }
  }

  /**
   * 生成配对 URL（面板二维码/文本用）。
   * @param {string} code - 6 位配对码。
   * @returns {string[]} URL 列表。
   */
  function pairUrls(code) {
    const base = listener?.urls() ?? []
    const port = listener?.port || config.port
    const urls = base.length > 0 ? base : buildUrls(port, '/m')
    const encoded = encodeURIComponent(code)
    return urls.map((url) => `${url.replace(/\/m$/, '/m/pair')}?c=${encoded}`)
  }

  // 设备表懒加载：读盘失败只是空表（配对后自愈），不影响插件加载。
  void devices.ready().catch((error) => {
    log('warn', `remote-mobile: 设备表加载失败：${String(error?.message ?? error)}`)
  })

  // 审批影子应答者在 apply 阶段就注册（不依赖 webServer），闸门在调用时求值。
  ctx.effect(() => {
    const detach = approvals.attach(ctx, { isActive })
    return () => {
      try {
        detach()
      } finally {
        approvals.dispose()
      }
    }
  }, 'remote-mobile: 审批影子应答者')

  // webServer / connection 就绪后再装配「监听器 + 上游 + 面板 RPC」。
  ctx.inject(['webServer', 'connection'], (runtimeCtx) => {
    const getWebServer = () => runtimeCtx.get('webServer')
    const getConnection = () => runtimeCtx.get('connection')

    upstream = createUpstream({
      config,
      log,
      audit,
      getOrigin: () => {
        const webServer = getWebServer()
        if (webServer === undefined || typeof webServer.getOrigin !== 'function') {
          throw new Error('webServer 服务不可用')
        }
        return webServer.getOrigin()
      },
      getAuthenticatedUrl: (url) => {
        const connection = getConnection()
        if (connection === undefined || typeof connection.authenticatedUrl !== 'function') {
          throw new Error('connection.authenticatedUrl 不可用')
        }
        return connection.authenticatedUrl(url)
      },
    })

    const statics = createStatic({
      dir: fileURLToPath(new URL('./web/', import.meta.url)),
      iconFallback: fileURLToPath(new URL('./icon.svg', import.meta.url)),
      log,
    })

    listener = createListener({
      config,
      devices,
      pairing,
      approvals,
      upstream,
      statics,
      audit,
      log,
    })

    // 面板 RPC：任何异常都不拖垮插件（否则面板会陷入 404 轮询）。
    runtimeCtx.effect(() => {
      let dispose
      try {
        dispose = registerRoutes(runtimeCtx, {
          connection: getConnection(),
          devices,
          pairing,
          approvals,
          getUpstream: () => upstream,
          audit,
          log,
          runtime: {
            status,
            setEnabled,
            kill,
            closeDeviceSockets: (deviceId) => listener?.closeDeviceSockets(deviceId) ?? 0,
            closeAllDeviceSockets: () => listener?.closeAllDeviceSockets() ?? 0,
            pairUrls,
          },
        })
      } catch (error) {
        audit.debug('admin-register-failed', {
          message: String(error?.message ?? error),
          stack: typeof error?.stack === 'string' ? error.stack.slice(0, 4000) : undefined,
        })
        log('error', `remote-mobile: PC 面板 RPC 注册失败：${String(error?.message ?? error)}`)
        return () => {}
      }
      return () => {
        try {
          dispose()
        } catch {
          // 卸载期异常没有意义。
        }
      }
    }, 'remote-mobile: PC 面板 RPC')

    // 监听器生命周期：随插件卸载关闭；启动/关闭随 `enabled` 热切换。
    runtimeCtx.effect(() => {
      void syncListener().catch((error) => {
        log('error', `remote-mobile: 监听器同步失败：${String(error?.message ?? error)}`)
      })
      return () => {
        approvals.setActive(false)
        const current = listener
        listener = undefined
        if (current !== undefined) {
          void current.stop().catch((error) => {
            log('warn', `remote-mobile: 关闭监听器失败：${String(error?.message ?? error)}`)
          })
        }
      }
    }, 'remote-mobile: 局域网监听器')

    const summary = describeConfig(config)
    log(
      'info',
      `remote-mobile: 就绪（enabled=${state.enabled}，bind=${summary.bind}，`
      + `approvalRouting=${summary.approvalRouting}，`
      + `fileAccess=${summary.fileAccess.mode}(roots=${summary.fileAccess.roots},extraDeny=${summary.fileAccess.extraDeny})，`
      + `数据目录 ${audit.dir}）`,
    )
  })
}
