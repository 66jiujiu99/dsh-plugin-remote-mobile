/**
 * 设备身份层（PROTOCOL §1/§2 的鉴权地基，PLAN §3.2.3 / §3.5.1）。
 *
 * 两种凭证严格分开，任何情况下都不许串：
 *   - **设备 cookie**（`dshm_d=<deviceId>.<secret>`）只存在于手机，服务端只存
 *     `sha256(secret)`；比对用 `crypto.timingSafeEqual`。
 *   - **上游 cookie**（`dsh-auth-*`）只存在于插件内存，见 `lib/net/upstream.js`。
 *
 * 持久化落在 `<dataDir>/devices.json`（0600，原子替换）。PLAN 里写的「首选
 * `ctx.credentials`」需要 import `@deepseek-ai/*` 的 credentialKey，与本插件
 * 「零内部依赖」的约定冲突，因此本期统一走文件；撤销/轮换语义不变。
 *
 * @module dsh-plugin-remote-mobile/devices
 */

import crypto from 'node:crypto'
import { mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises'
import path from 'node:path'

import { RmError, dataDir } from '../config.js'

/** 设备 cookie 名（PROTOCOL / PLAN 附录 B）。 */
export const DEVICE_COOKIE = 'dshm_d'

/** 设备表版本，将来改形状时用来迁移。 */
const STORE_VERSION = 1

/** 单台设备 `lastSeenAt` 的落盘节流：内存每次更新，磁盘最多 15 秒一次。 */
const TOUCH_PERSIST_MS = 15_000

/** 设备数量上限：再多说明有人在乱配对，直接拒绝而不是无限增长。 */
const MAX_DEVICES = 32

/** 单条 UA 的存储截断长度。 */
const MAX_UA_LENGTH = 300

/**
 * 从 UA 猜一个设备名（PC 面板里可改名）。
 * @param {string|undefined} ua - User-Agent。
 * @returns {string} 设备名。
 */
export function guessDeviceName(ua) {
  const text = typeof ua === 'string' ? ua : ''
  if (/iphone/i.test(text)) return 'iPhone'
  if (/ipad/i.test(text)) return 'iPad'
  if (/android/i.test(text)) return 'Android 手机'
  if (/windows/i.test(text)) return 'Windows 浏览器'
  if (/macintosh|mac os x/i.test(text)) return 'Mac 浏览器'
  return '新设备'
}

/**
 * `sha256(secret)` 的十六进制形式。
 * @param {string} secret - base64url 随机串。
 * @returns {string} 64 位十六进制。
 */
export function hashSecret(secret) {
  return crypto.createHash('sha256').update(secret, 'utf8').digest('hex')
}

/**
 * 两个十六进制哈希是否相等（定长、定时安全比较）。
 * @param {string} left - 十六进制。
 * @param {string} right - 十六进制。
 * @returns {boolean} 结论。
 */
function safeEqualHex(left, right) {
  if (typeof left !== 'string' || typeof right !== 'string') return false
  const a = Buffer.from(left, 'hex')
  const b = Buffer.from(right, 'hex')
  if (a.length === 0 || a.length !== b.length) return false
  return crypto.timingSafeEqual(a, b)
}

/**
 * 从 `Cookie` 头里取一个 cookie 值。
 * @param {string|undefined} header - `Cookie` 头原文。
 * @param {string} name - cookie 名。
 * @returns {string|undefined} 值（未编码的原文）。
 */
export function readCookie(header, name) {
  if (typeof header !== 'string' || header === '') return undefined
  for (const part of header.split(';')) {
    const index = part.indexOf('=')
    if (index < 0) continue
    if (part.slice(0, index).trim() !== name) continue
    return part.slice(index + 1).trim()
  }
  return undefined
}

/**
 * 是否是普通对象。
 * @param {unknown} value - 任意值。
 * @returns {boolean} 结论。
 */
function isRecord(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

/**
 * 建设备表。
 *
 * @param {object} options - 依赖。
 * @param {import('../config.js').ResolvedConfig} options.config - 已解析配置。
 * @param {ReturnType<import('../audit.js').createAudit>} options.audit - 审计器（仅 debug）。
 * @param {(level: 'debug'|'info'|'warn'|'error', message: string) => void} options.log - 日志出口。
 * @returns {object} 设备表 API。
 */
export function createDevices({ config, audit, log }) {
  const dir = dataDir()
  const file = path.join(dir, 'devices.json')

  /** @type {Map<string, {
   *   id: string, name: string, ua: string, createdAt: number, lastSeenAt: number,
   *   lastIp: string, readonly: boolean, revokedAt: number|undefined, secretHash: string,
   * }>} */
  const devices = new Map()

  /** 写盘串行化：避免同一次 rename 抢跑。 */
  let writeChain = Promise.resolve()
  /** 上次落盘时间（用于 touch 节流）。 */
  let lastPersistAt = 0
  /** 懒加载 Promise（并发请求只读一次盘）。 */
  let loadPromise

  /**
   * 读盘（损坏/缺失都当空表，并留一条 debug）。
   * @returns {Promise<void>} 加载完成。
   */
  async function load() {
    let text
    try {
      text = await readFile(file, 'utf8')
    } catch {
      return
    }
    let parsed
    try {
      parsed = JSON.parse(text)
    } catch (error) {
      log('warn', `remote-mobile: devices.json 损坏，按空表启动：${String(error?.message ?? error)}`)
      return
    }
    if (!isRecord(parsed) || !Array.isArray(parsed.devices)) return
    for (const raw of parsed.devices) {
      if (!isRecord(raw)) continue
      if (typeof raw.id !== 'string' || typeof raw.secretHash !== 'string') continue
      devices.set(raw.id, {
        id: raw.id,
        name: typeof raw.name === 'string' && raw.name !== '' ? raw.name : '设备',
        ua: typeof raw.ua === 'string' ? raw.ua : '',
        createdAt: Number.isFinite(raw.createdAt) ? Number(raw.createdAt) : Date.now(),
        lastSeenAt: Number.isFinite(raw.lastSeenAt) ? Number(raw.lastSeenAt) : 0,
        lastIp: typeof raw.lastIp === 'string' ? raw.lastIp : '',
        readonly: raw.readonly === true,
        revokedAt: Number.isFinite(raw.revokedAt) ? Number(raw.revokedAt) : undefined,
        secretHash: raw.secretHash,
      })
    }
  }

  /**
   * 确保已加载（幂等）。
   * @returns {Promise<void>} 加载完成。
   */
  function ready() {
    if (loadPromise === undefined) loadPromise = load()
    return loadPromise
  }

  /**
   * 落盘（原子替换；失败只告警，不影响内存态）。
   * @returns {Promise<void>} 写完。
   */
  function persist() {
    lastPersistAt = Date.now()
    const snapshot = {
      v: STORE_VERSION,
      devices: [...devices.values()].map((device) => ({ ...device })),
    }
    const text = `${JSON.stringify(snapshot, null, 2)}\n`
    const temp = `${file}.${process.pid}.tmp`
    writeChain = writeChain
      .then(async () => {
        await mkdir(dir, { recursive: true })
        await writeFile(temp, text, { encoding: 'utf8', mode: 0o600 })
        // Windows 上 rename 覆盖已存在文件会失败，先删再换。
        await rm(file, { force: true })
        await rename(temp, file)
      })
      .catch((error) => {
        log('warn', `remote-mobile: 写 devices.json 失败：${String(error?.message ?? error)}`)
      })
    return writeChain
  }

  /**
   * 生成一台设备的 cookie 值 `<id>.<secret>`（secret 只在内存里出现一次）。
   * @param {string} id - 设备 id。
   * @param {string} secret - base64url 随机串。
   * @returns {string} cookie 值。
   */
  function cookieValue(id, secret) {
    return `${id}.${secret}`
  }

  /**
   * 构造 `Set-Cookie` 头（`HttpOnly; Path=/; SameSite=Lax; Max-Age=…`）。
   * 本期是 http，不加 `Secure`（PLAN §3.2.3）。
   * @param {string} id - 设备 id。
   * @param {string} secret - secret。
   * @returns {string} Set-Cookie 值。
   */
  function buildSetCookie(id, secret) {
    const maxAge = Math.max(1, Math.round(config.cookieMaxAgeDays * 86_400))
    return `${DEVICE_COOKIE}=${cookieValue(id, secret)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}`
  }

  /** 设备 cookie 的服务端有效期（毫秒）。 */
  const MAX_AGE_MS = Math.max(1, Math.round(config.cookieMaxAgeDays * 86_400_000))

  /**
   * 设备是否已过 cookie 有效期。
   *
   * `Set-Cookie` 的 `Max-Age` 只约束浏览器——cookie 被复制/被脚本重放时它不生效，
   * 所以服务端必须按 `createdAt` 再判一次，否则「180 天后失效」只是客户端承诺。
   * @param {object} device - 设备记录。
   * @param {number} now - 当前毫秒。
   * @returns {boolean} 结论。
   */
  function isExpired(device, now) {
    if (!Number.isFinite(device.createdAt)) return true
    return now - device.createdAt > MAX_AGE_MS
  }

  /**
   * 设备是否在线（窗口内有过请求且未撤销、未过期）。
   * @param {object} device - 设备记录。
   * @param {number} now - 当前毫秒。
   * @returns {boolean} 结论。
   */
  function isOnline(device, now) {
    if (device.revokedAt !== undefined) return false
    if (isExpired(device, now)) return false
    return device.lastSeenAt > 0 && now - device.lastSeenAt <= config.deviceOnlineWindowMs
  }

  /**
   * 对外（PC 面板）可见的设备视图。
   * @param {object} device - 设备记录。
   * @param {number} now - 当前毫秒。
   * @returns {object} 视图。
   */
  function view(device, now) {
    return {
      id: device.id,
      name: device.name,
      ua: device.ua,
      createdAt: device.createdAt,
      lastSeenAt: device.lastSeenAt,
      lastIp: device.lastIp,
      readonly: device.readonly,
      revoked: device.revokedAt !== undefined,
      online: isOnline(device, now),
    }
  }

  /**
   * 未撤销设备数量（`revokeAll` 会清空整表，所以按 Map 计）。
   * @returns {number} 数量。
   */
  function countActive() {
    const now = Date.now()
    let total = 0
    for (const device of devices.values()) {
      if (device.revokedAt === undefined && !isExpired(device, now)) total += 1
    }
    return total
  }

  return {
    ready,

    /** cookie 名（`dshm_d`）。 */
    cookieName: DEVICE_COOKIE,

    /**
     * 全部未撤销设备（PC 面板）。
     * @returns {object[]} 视图数组（按创建时间倒序）。
     */
    list() {
      const now = Date.now()
      return [...devices.values()]
        .filter((device) => device.revokedAt === undefined)
        .sort((left, right) => right.createdAt - left.createdAt)
        .map((device) => view(device, now))
    },

    /**
     * 在线设备（含是否允许审批：`readonly === false`）。
     * @returns {Array<object>} 设备记录副本数组。
     */
    online() {
      const now = Date.now()
      return [...devices.values()]
        .filter((device) => isOnline(device, now))
        .map((device) => ({ ...device }))
    },

    /**
     * 按 id 取设备。
     * @param {string} id - 设备 id。
     * @returns {object|undefined} 设备记录（活引用，调用方不要改 secretHash）。
     */
    get(id) {
      return devices.get(id)
    },

    /**
     * 未撤销设备数量。
     * @returns {number} 数量。
     */
    count: countActive,

    /**
     * 用设备 cookie 认证一台设备。
     *
     * 失败一律返回 undefined（调用方决定回 401 还是 302 配对页），不抛异常——
     * 手机上的过期 cookie 是常态，不是异常。
     * @param {string|undefined} cookieHeader - `Cookie` 头原文。
     * @returns {{ device: object, secret: string }|undefined} 命中时的设备。
     */
    authenticate(cookieHeader) {
      const value = readCookie(cookieHeader, DEVICE_COOKIE)
      if (value === undefined) return undefined
      const dot = value.indexOf('.')
      if (dot <= 0 || dot === value.length - 1) return undefined
      const id = value.slice(0, dot)
      const secret = value.slice(dot + 1)
      if (secret.length < 16 || secret.length > 200) return undefined
      const device = devices.get(id)
      if (device === undefined || device.revokedAt !== undefined) return undefined
      if (isExpired(device, Date.now())) return undefined
      if (!safeEqualHex(hashSecret(secret), device.secretHash)) return undefined
      return { device, secret }
    },

    /**
     * 建一台设备（配对成功后调用）。
     * @param {{ name?: string, ua?: string, ip?: string, readonly?: boolean }} input - 来源信息。
     * @returns {Promise<{ device: object, secret: string, setCookie: string }>} 新设备与 cookie。
     */
    async create({ name, ua, ip, readonly } = {}) {
      await ready()
      if (countActive() >= MAX_DEVICES) {
        throw new RmError('rm/forbidden', `设备数量已达上限 ${MAX_DEVICES}，请先在 PC 面板撤销不用的设备`)
      }
      const id = crypto.randomBytes(8).toString('hex')
      const secret = crypto.randomBytes(32).toString('base64url')
      const now = Date.now()
      const device = {
        id,
        name: typeof name === 'string' && name.trim() !== '' ? name.trim().slice(0, 60) : guessDeviceName(ua),
        ua: typeof ua === 'string' ? ua.slice(0, MAX_UA_LENGTH) : '',
        createdAt: now,
        lastSeenAt: now,
        lastIp: typeof ip === 'string' ? ip : '',
        readonly: readonly === true,
        revokedAt: undefined,
        secretHash: hashSecret(secret),
      }
      devices.set(id, device)
      await persist()
      audit.debug('device-created', { id, name: device.name, ip: device.lastIp })
      return { device, secret, setCookie: buildSetCookie(id, secret) }
    },

    /**
     * 设备发过请求：更新 `lastSeenAt/lastIp`，按 15 秒节流落盘。
     * @param {object} device - 设备记录（必须是 `devices` 里的活引用）。
     * @param {string} [ip] - 对端地址。
     * @returns {void}
     */
    touch(device, ip) {
      if (device === undefined || device.revokedAt !== undefined) return
      device.lastSeenAt = Date.now()
      if (typeof ip === 'string' && ip !== '') device.lastIp = ip
      if (Date.now() - lastPersistAt > TOUCH_PERSIST_MS) void persist()
    },

    /**
     * 改名。
     * @param {string} id - 设备 id。
     * @param {string} name - 新名字。
     * @returns {Promise<void>} 写盘完成。
     */
    async rename(id, name) {
      await ready()
      const device = devices.get(id)
      if (device === undefined || device.revokedAt !== undefined) {
        throw new RmError('rm/not-found', '设备不存在或已撤销')
      }
      const trimmed = typeof name === 'string' ? name.trim() : ''
      if (trimmed === '') throw new RmError('rm/bad-request', '设备名不能为空')
      device.name = trimmed.slice(0, 60)
      await persist()
    },

    /**
     * 设置只读。
     * @param {string} id - 设备 id。
     * @param {boolean} readonly - 是否只读。
     * @returns {Promise<object>} 更新后的视图。
     */
    async setReadonly(id, readonly) {
      await ready()
      const device = devices.get(id)
      if (device === undefined || device.revokedAt !== undefined) {
        throw new RmError('rm/not-found', '设备不存在或已撤销')
      }
      device.readonly = readonly === true
      await persist()
      audit.audit({ kind: 'revoke', detail: `readonly=${device.readonly}`, deviceId: id, deviceName: device.name })
      return view(device, Date.now())
    },

    /**
     * 撤销一台设备（删哈希 + 标记；在途 socket 由监听器负责关闭）。
     * @param {string} id - 设备 id。
     * @returns {Promise<{ device: object }>} 被撤销的设备。
     */
    async revoke(id) {
      await ready()
      const device = devices.get(id)
      if (device === undefined || device.revokedAt !== undefined) {
        throw new RmError('rm/not-found', '设备不存在或已撤销')
      }
      device.revokedAt = Date.now()
      device.secretHash = ''
      await persist()
      audit.audit({ kind: 'revoke', deviceId: id, deviceName: device.name, ip: device.lastIp })
      return { device }
    },

    /**
     * 撤销全部设备（kill switch 的一部分）。
     * @returns {Promise<number>} 被撤销的数量。
     */
    async revokeAll() {
      await ready()
      const now = Date.now()
      let count = 0
      for (const device of devices.values()) {
        if (device.revokedAt !== undefined) continue
        device.revokedAt = now
        device.secretHash = ''
        count += 1
      }
      devices.clear()
      await persist()
      if (count > 0) audit.audit({ kind: 'kill', detail: `revoked ${count} device(s)` })
      return count
    },
  }
}
