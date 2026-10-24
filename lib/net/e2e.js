/**
 * 端到端加密：Node 侧（Host）。
 *
 * 与 `web/e2e-crypto.js` **必须逐位互通**：同一套曲线、KDF、帧格式。
 * 任何一处不一致，手机上就会解密失败。互通性由 `test/e2e.test.mjs` 钉住
 * （用 Node 自己跑一遍浏览器那份脚本）。
 *
 * ## 设计
 *
 * - 曲线用 **P-256**（不是 X25519）：WebCrypto 的必选项，手机上也支持。
 * - `ECDH → HKDF-SHA256 → AES-256-GCM`：ECDH 的裸共享密钥不能直接用，
 *   必须过 KDF 才能当对称密钥。
 * - 帧格式 `[4B 长度][12B nonce][密文||tag]`，与浏览器侧一致。
 *
 * ## 密钥生命周期
 *
 * 每台设备一把密钥，配对时协商：
 *
 *   1. 手机生成 P-256 密钥对，把**公钥**放进 `POST /m/pair`。
 *   2. 服务端生成自己的密钥对（每设备一把），返回自己的公钥。
 *   3. 双方 ECDH 出同一个共享密钥 → HKDF（salt = 设备 id）→ AES 密钥。
 *
 * 私钥**只存在内存**（服务端）与手机本地；`devices.json` 里只存设备 id 与
 * 公钥（公钥不敏感，但留着便于排障）。
 *
 * ## 安全边界（必须理解）
 *
 * 这套加密**防的是被动监听**（Cloudflare 记录、公共 WiFi 抓包）。
 * 它**防不住主动篡改**：注入的 JavaScript 本身也经由同一条隧道下发，
 * 一个有能力改写响应的中间人可以把脚本改成"把密钥发给我"。
 *
 * 要防主动篡改，客户端必须是独立可信的（原生 App / 浏览器扩展 / 固定哈希校验）。
 * 本插件不做那一步——这是个诚实的限制，README 里写清了。
 *
 * @module dsh-plugin-remote-mobile/e2e
 */

import crypto from 'node:crypto'

/** 协议版本（写进 HKDF info，避免跨版本混用密钥）。 */
export const PROTOCOL = 'dsh-rm-e2e-v1'

/** Nonce 长度（AES-GCM 标准 96 位）。 */
const NONCE_BYTES = 12

/** 帧头长度。 */
const HEADER_BYTES = 4

/** 单帧上限，与浏览器侧一致。 */
const MAX_FRAME_BYTES = 16 * 1024 * 1024

/** GCM 认证标签长度。 */
const TAG_BYTES = 16

/** P-256 未压缩点长度：1 字节前缀 + 32 + 32。 */
const P256_PUBLIC_BYTES = 65

/**
 * 生成一对 P-256 ECDH 密钥。
 * @returns {{ privateKey: crypto.KeyObject, publicKeyB64: string }} 密钥对（公钥为 base64 raw）。
 */
export function generateKeyPair() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
  // 导出未压缩点（0x04 || X || Y），与 WebCrypto 的 exportKey('raw') 一致。
  const raw = publicKey.export({ type: 'spki', format: 'der' })
  const point = raw.subarray(raw.length - P256_PUBLIC_BYTES)
  return { privateKey, publicKeyB64: point.toString('base64') }
}

/**
 * 用对端公钥与自己的私钥派生 AES-256-GCM 密钥。
 *
 * @param {crypto.KeyObject} privateKey - 自己的私钥。
 * @param {string} peerPublicB64 - 对端公钥（base64，65 字节未压缩点）。
 * @param {string} saltText - HKDF salt（设备 id）。
 * @returns {Buffer} 32 字节 AES 密钥。
 * @throws {Error} 公钥格式非法。
 */
export function deriveKey(privateKey, peerPublicB64, saltText) {
  const point = Buffer.from(String(peerPublicB64 || ''), 'base64')
  if (point.length !== P256_PUBLIC_BYTES || point[0] !== 0x04) {
    throw new Error(`端到端公钥格式非法：期望 ${P256_PUBLIC_BYTES} 字节未压缩点（0x04 开头），实际 ${point.length} 字节`)
  }
  const peerPublic = crypto.createPublicKey({
    key: { kty: 'EC', crv: 'P-256', x: point.subarray(1, 33).toString('base64url'), y: point.subarray(33, 65).toString('base64url') },
    format: 'jwk',
  })
  const shared = crypto.diffieHellman({ privateKey, publicKey: peerPublic })
  // HKDF：salt = 设备 id，info = 协议版本。与浏览器侧 WebCrypto 的 deriveKey 等价。
  return Buffer.from(crypto.hkdfSync('sha256', shared, Buffer.from(String(saltText || ''), 'utf8'), Buffer.from(PROTOCOL, 'utf8'), 32))
}

/**
 * 加密一段明文并封帧。
 * @param {Buffer} key - 32 字节 AES 密钥。
 * @param {Buffer} plaintext - 明文。
 * @returns {Buffer} 完整帧。
 */
export function seal(key, plaintext) {
  const nonce = crypto.randomBytes(NONCE_BYTES)
  const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce)
  const body = Buffer.concat([cipher.update(plaintext), cipher.final()])
  const tag = cipher.getAuthTag()
  const payload = NONCE_BYTES + body.length + TAG_BYTES
  const header = Buffer.alloc(HEADER_BYTES)
  header.writeUInt32BE(payload, 0)
  return Buffer.concat([header, nonce, body, tag])
}

/**
 * 从帧里解出明文。
 * @param {Buffer} key - 32 字节 AES 密钥。
 * @param {Buffer} frame - 至少一个完整帧。
 * @returns {{ plaintext: Buffer, consumed: number }} 明文与消耗字节数。
 * @throws {Error} 长度非法 / 帧不完整 / 认证失败（被篡改）。
 */
export function open(key, frame) {
  if (frame.length < HEADER_BYTES) throw new Error('帧太短：缺少长度头')
  const payload = frame.readUInt32BE(0)
  if (payload < NONCE_BYTES + TAG_BYTES || payload > MAX_FRAME_BYTES) {
    throw new Error(`帧长度非法：${payload}`)
  }
  const total = HEADER_BYTES + payload
  if (frame.length < total) throw new Error('帧不完整')
  const nonce = frame.subarray(HEADER_BYTES, HEADER_BYTES + NONCE_BYTES)
  const body = frame.subarray(HEADER_BYTES + NONCE_BYTES, total - TAG_BYTES)
  const tag = frame.subarray(total - TAG_BYTES, total)
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, nonce)
  decipher.setAuthTag(tag)
  const plaintext = Buffer.concat([decipher.update(body), decipher.final()])
  return { plaintext, consumed: total }
}

/**
 * 流式解帧器（TCP/WS 会把帧拆开或粘连）。
 * @param {Buffer} key - 32 字节 AES 密钥。
 * @returns {{ push: (chunk: Buffer) => Buffer[] }} 解帧器。
 */
export function createReader(key) {
  let buffer = Buffer.alloc(0)
  return {
    push(chunk) {
      buffer = buffer.length === 0 ? Buffer.from(chunk) : Buffer.concat([buffer, chunk])
      const out = []
      for (;;) {
        if (buffer.length < HEADER_BYTES) break
        const payload = buffer.readUInt32BE(0)
        if (payload <= 0 || payload > MAX_FRAME_BYTES) throw new Error(`帧长度非法：${payload}`)
        const total = HEADER_BYTES + payload
        if (buffer.length < total) break
        const result = open(key, buffer.subarray(0, total))
        out.push(result.plaintext)
        buffer = buffer.subarray(result.consumed)
      }
      return out
    },
  }
}

/**
 * 每台设备的密钥表（**只在内存**）。
 *
 * 重启后清空 —— 这意味着手机需要在下次连接时重新握手（用设备 cookie 认证后
 * 再交换临时公钥）。这样私钥永不落盘，泄露面更小。
 */
export function createKeyStore() {
  /** @type {Map<string, { privateKey: crypto.KeyObject, publicKeyB64: string, key: Buffer }>} */
  const byDevice = new Map()

  return {
    /**
     * 为某台设备建立会话密钥（服务端侧）。
     * @param {string} deviceId - 设备 id。
     * @param {string} peerPublicB64 - 手机公钥。
     * @returns {string} 服务端公钥（base64），要回给手机。
     */
    establish(deviceId, peerPublicB64) {
      const pair = generateKeyPair()
      const key = deriveKey(pair.privateKey, peerPublicB64, deviceId)
      byDevice.set(deviceId, { privateKey: pair.privateKey, publicKeyB64: pair.publicKeyB64, key })
      return pair.publicKeyB64
    },

    /**
     * 取某设备的会话密钥。
     * @param {string} deviceId - 设备 id。
     * @returns {Buffer|undefined} 密钥（没有则 undefined，表示需要握手）。
     */
    get(deviceId) {
      return byDevice.get(deviceId)?.key
    },

    /** 丢弃某设备的会话密钥。 */
    drop(deviceId) {
      byDevice.delete(deviceId)
    },

    /** 丢弃全部（插件卸载/重启）。 */
    clear() {
      byDevice.clear()
    },

    /** 当前已握手的设备数（诊断用）。 */
    get size() {
      return byDevice.size
    },
  }
}
