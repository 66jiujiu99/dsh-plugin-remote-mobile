/**
 * 配对码（PROTOCOL §1 的 `/m/pair`，PLAN §3.2.3）。
 *
 * 规则（全部在内存里，不落盘）：
 *   - 6 位十进制，`pairCodeTtlSec`（默认 60s）内有效，**单次使用**；
 *   - 同一时刻只存在一个码（PC 面板再点一次就顶掉旧的）；
 *   - 单码最多 `pairMaxAttempts`（默认 5）次错误，超了立刻锁定 60 秒；
 *   - 同一 IP 每分钟最多 10 次配对请求，超了 429（`rm/pair-locked`）。
 *
 * 配对成功返回设备 cookie（`Set-Cookie: dshm_d=…`），**不把 DSH 的 token/cookie
 * 给手机**——手机只拿设备 secret（PLAN §3.2.1）。
 *
 * @module dsh-plugin-remote-mobile/pairing
 */

import crypto from 'node:crypto'

import { RmError } from '../config.js'

/** 单个码的错误尝试上限对应的锁定时长。 */
const LOCK_MS = 60_000

/**
 * 同 IP 的限流窗口与次数。
 *
 * 公网暴露（隧道）之后这不再是"锦上添花"：它是防止配对码被在线爆破的
 * 主要手段。10 次/分钟对正常用户（一次输对）绰绰有余，
 * 对爆破脚本则把速度压到不可行。
 */
const RATE_WINDOW_MS = 60_000
const RATE_MAX = 10

/**
 * 配对码字母表：去掉了容易看错的 `0/O/1/I/L`。
 *
 * 用户在手机上手输、或从 PC 屏幕抄写，这几个字符最容易出错，
 * 去掉之后可用字符 31 个。
 */
const PAIR_CODE_ALPHABET = '23456789ABCDEFGHJKMNPQRSTUVWXYZ'

/** 配对码长度。8 位 × log2(31) ≈ 39.6 bit。 */
const PAIR_CODE_LENGTH = 8

/** 配对码熵（bit），写进审计便于事后核对强度。 */
const PAIR_CODE_BITS = Math.round(PAIR_CODE_LENGTH * Math.log2(PAIR_CODE_ALPHABET.length) * 10) / 10

/**
 * 生成一个配对码。
 *
 * 用 `crypto.randomInt` 逐字符取值：它内部做拒绝采样，没有模偏
 * （`% 31` 直接用会有偏，长跑会削弱有效熵）。
 *
 * @returns {string} 形如 `K7M2QX9P`（大写，8 位）。
 */
function randomCode() {
  let out = ''
  for (let index = 0; index < PAIR_CODE_LENGTH; index += 1) {
    out += PAIR_CODE_ALPHABET[crypto.randomInt(0, PAIR_CODE_ALPHABET.length)]
  }
  return out
}

/** 等长字符串的定时安全比较。 */
function safeCompare(left, right) {
  const a = Buffer.from(String(left), 'utf8')
  const b = Buffer.from(String(right), 'utf8')
  if (a.length !== b.length) return false
  return crypto.timingSafeEqual(a, b)
}

/**
 * 建配对码服务。
 *
 * @param {object} options - 依赖。
 * @param {import('../config.js').ResolvedConfig} options.config - 已解析配置。
 * @param {ReturnType<import('./devices.js').createDevices>} options.devices - 设备表。
 * @param {ReturnType<import('../audit.js').createAudit>} options.audit - 审计器。
 * @returns {object} 配对服务 API。
 */
export function createPairing({ config, devices, audit }) {
  /** @type {{ code: string, expiresAt: number, attempts: number }|undefined} */
  let pending
  /**
   * 最近一次**已兑换**的码（只留一个，够区分 `rm/pair-used` 与 `rm/pair-expired`）。
   * 新码生成/取消时清空；只存码本身，不存任何 secret。
   * @type {{ code: string }|undefined}
   */
  let lastUsed
  /** 锁定的截止时间（超错次数/限流都会写这里）。 */
  let lockedUntil = 0
  /** @type {Map<string, number[]>} IP → 请求时间戳。 */
  const rate = new Map()

  /**
   * 清理过期状态（每次调用前跑，避免定时器）。
   * @returns {void}
   */
  function sweep() {
    const now = Date.now()
    if (pending !== undefined && pending.expiresAt <= now) pending = undefined
    if (lockedUntil <= now) lockedUntil = 0
    if (rate.size > 256) {
      for (const [ip, stamps] of rate) {
        const kept = stamps.filter((stamp) => now - stamp < RATE_WINDOW_MS)
        if (kept.length === 0) rate.delete(ip)
        else rate.set(ip, kept)
      }
    }
  }

  /**
   * 同 IP 限流。
   * @param {string} ip - 对端地址。
   * @returns {void}
   * @throws {RmError} 超过每分钟 10 次时。
   */
  function checkRate(ip) {
    const key = typeof ip === 'string' && ip !== '' ? ip : 'unknown'
    const now = Date.now()
    const stamps = (rate.get(key) ?? []).filter((stamp) => now - stamp < RATE_WINDOW_MS)
    if (stamps.length >= RATE_MAX) {
      rate.set(key, stamps)
      throw new RmError('rm/pair-locked', `配对请求过于频繁（同一地址每分钟最多 ${RATE_MAX} 次），请稍后再试`)
    }
    stamps.push(now)
    rate.set(key, stamps)
  }

  return {
    /**
     * 生成一个新配对码（PC 面板「添加设备」）。
     *
     * `ttlSec` 是面板/脚本按需指定的有效期（秒）；缺省或越界回落到
     * `config.pairCodeTtlSec`。返回值里的 `ttlSec` 是**实际生效**的值，
     * 面板据此显示倒计时，避免「请求 10s、实际 60s」的假有效期。
     * @param {number} [ttlSec] - 期望有效期（秒，10..900）。
     * @returns {{ code: string, expiresAt: number, ttlSec: number }} 新码、到期时间（毫秒）与实际 TTL。
     */
    create(ttlSec) {
      sweep()
      const requested = Number(ttlSec)
      const ttl = Number.isFinite(requested) && requested >= 10 && requested <= 900
        ? Math.round(requested)
        : config.pairCodeTtlSec
      // crypto.randomInt 无模偏。极少见地撞上「刚用过的码」就重抽，
      // 否则新码会被 `rm/pair-used` 判定挡住。
      let code = ''
      do {
        code = randomCode()
      } while (lastUsed !== undefined && code === lastUsed.code)
      const expiresAt = Date.now() + ttl * 1000
      pending = { code, expiresAt, attempts: 0 }
      lockedUntil = 0
      audit.debug('pair-created', { expiresAt, ttlSec: ttl, bits: PAIR_CODE_BITS })
      return { code, expiresAt, ttlSec: ttl }
    },

    /**
     * 取消当前配对码（PC 面板「取消」）。
     * @returns {{ ok: true }} 恒成功。
     */
    cancel() {
      const existed = pending !== undefined
      pending = undefined
      audit.debug('pair-cancelled', { existed })
      return { ok: true }
    },

    /**
     * 当前配对码状态（PC 面板轮询用；`code` 只回给本机面板）。
     * @returns {{ active: boolean, code?: string, expiresAt?: number }} 状态。
     */
    current() {
      sweep()
      if (pending === undefined) return { active: false }
      return {
        active: true,
        code: pending.code,
        expiresAt: pending.expiresAt,
        ttlSec: Math.max(0, Math.round((pending.expiresAt - Date.now()) / 1000)),
      }
    },

    /**
     * 用配对码换设备 cookie（`POST /m/pair`）。
     *
     * 成功后码立即作废（单次），并返回新设备的 `Set-Cookie`。
     * @param {{ code: unknown, name?: unknown, ua?: string, ip?: string }} input - 手机提交的内容。
     * @returns {Promise<{ device: object, setCookie: string }>} 新设备。
     * @throws {RmError} 各种 `rm/pair-*` / `rm/bad-request`。
     */
    async attempt({ code, name, ua, ip }) {
      sweep()
      checkRate(ip)
      // 规范化：去空白、转大写。这样用户用手机输入法自动首字母大写、
      // 或抄写时带空格，都不会被判成"码不正确"。
      const text = typeof code === 'string' ? code.trim().toUpperCase().replace(/\s+/g, '') : ''
      if (!/^[2-9A-HJ-NP-Z]{8}$/.test(text)) {
        throw new RmError(
          'rm/pair-invalid',
          `配对码格式不对：应为 8 位（数字与大写字母，不含 0/O/1/I/L），实际收到 ${text.length} 位`,
        )
      }
      if (lockedUntil !== 0) {
        throw new RmError('rm/pair-locked', '配对已锁定（错误次数过多），请等 60 秒后在 PC 面板重新生成配对码')
      }
      // 「已兑换过」与「过期」是两回事：前者提示别复用旧码，后者提示重新生成。
      if (lastUsed !== undefined && safeCompare(text, lastUsed.code)) {
        audit.audit({ kind: 'pair', detail: 'reuse-used-code', ip })
        throw new RmError('rm/pair-used', '该配对码已经被使用过，请在 PC 面板重新生成')
      }
      if (pending === undefined) {
        throw new RmError('rm/pair-expired', '配对码已过期或未生成，请在 PC 面板重新点「添加设备」')
      }
      if (pending.expiresAt <= Date.now()) {
        pending = undefined
        throw new RmError('rm/pair-expired', '配对码已过期，请在 PC 面板重新点「添加设备」')
      }
      if (!safeCompare(text, pending.code)) {
        pending.attempts += 1
        audit.audit({ kind: 'pair', detail: 'wrong-code', ip, attempts: pending.attempts })
        if (pending.attempts >= config.pairMaxAttempts) {
          pending = undefined
          lockedUntil = Date.now() + LOCK_MS
          throw new RmError('rm/pair-locked', `配对码错误次数达到 ${config.pairMaxAttempts} 次，已锁定 60 秒`)
        }
        throw new RmError(
          'rm/pair-invalid',
          `配对码不正确（还剩 ${Math.max(0, config.pairMaxAttempts - pending.attempts)} 次机会）`,
        )
      }

      // 命中：先作废码，再建设备（建设备失败也不会让码可重放）。
      const matched = pending
      pending = undefined
      lastUsed = { code: matched.code }
      try {
        const created = await devices.create({ name, ua, ip })
        audit.audit({
          kind: 'pair',
          deviceId: created.device.id,
          deviceName: created.device.name,
          ip,
          detail: 'paired',
        })
        audit.debug('pair-success', { deviceId: created.device.id, codeUsed: matched.code.slice(0, 2) })
        return created
      } catch (error) {
        throw error instanceof RmError
          ? error
          : new RmError('rm/internal', `创建设备失败：${String(error?.message ?? error)}`)
      }
    },
  }
}
