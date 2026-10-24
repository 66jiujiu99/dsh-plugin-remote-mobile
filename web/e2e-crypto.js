/**
 * 端到端加密原语（浏览器侧，classic script）。
 *
 * 同时被 Service Worker（`importScripts`）和页面（`<script>`）使用，
 * 所以**不能**用 ESM，只能挂在 `self.DshE2E` 上。
 *
 * ## 密码学选择与理由
 *
 * - **P-256 ECDH**：不用 X25519，因为 WebCrypto 的 X25519 在 Safari / 旧 Chrome
 *   上支持不全；P-256 是 WebCrypto 的必选项，到处都能用。
 * - **HKDF-SHA256** 派生对称密钥：ECDH 出来的共享密钥不能直接当 AES 密钥用
 *   （它不是均匀随机的），必须先过 KDF。
 * - **AES-256-GCM**：认证加密，同时保证机密性与完整性。同一条连接上
 *   篡改密文会直接解密失败，不需要额外的 MAC。
 * - **12 字节随机 nonce**：GCM 的 nonce 绝不能重复（重复会灾难性泄露密钥流），
 *   所以用 CSPRNG 随机生成而不是计数器——跨设备、跨重启都不会撞。
 *
 * ## 帧格式
 *
 * ```
 * [4 字节大端长度][12 字节 nonce][密文 || 16 字节 tag]
 * ```
 *
 * 长度字段只覆盖 `nonce + 密文 + tag`，不含自身。
 *
 * @module dsh-plugin-remote-mobile/e2e-crypto
 */

(function attach(root) {
  'use strict'

  /** 协议版本：写进 HKDF 的 info，避免与将来版本混用密钥。 */
  var PROTOCOL = 'dsh-rm-e2e-v1'

  /** Nonce 长度（GCM 标准 96 位）。 */
  var NONCE_BYTES = 12

  /** 帧头长度（4 字节长度字段）。 */
  var HEADER_BYTES = 4

  /** 单帧上限（16MB）：防止恶意对端发一个天文数字让内存炸掉。 */
  var MAX_FRAME_BYTES = 16 * 1024 * 1024

  function subtle() {
    var c = root.crypto
    if (!c || !c.subtle) throw new Error('WebCrypto 不可用：端到端加密需要 https 或 localhost 上下文')
    return c.subtle
  }

  function b64encode(bytes) {
    var binary = ''
    var view = new Uint8Array(bytes)
    for (var i = 0; i < view.length; i += 1) binary += String.fromCharCode(view[i])
    return root.btoa(binary)
  }

  function b64decode(text) {
    var binary = root.atob(String(text || ''))
    var out = new Uint8Array(binary.length)
    for (var i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i)
    return out
  }

  /**
   * 生成一对 P-256 密钥（提取格式，便于把公钥发出去）。
   * @returns {Promise<{privateKey: CryptoKey, publicKeyB64: string}>} 密钥对。
   */
  async function generateKeyPair() {
    var pair = await subtle().generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits'])
    var raw = await subtle().exportKey('raw', pair.publicKey)
    return { privateKey: pair.privateKey, publicKeyB64: b64encode(raw) }
  }

  /**
   * 用 ECDH + HKDF 派生出 AES-256-GCM 密钥。
   *
   * @param {CryptoKey} privateKey - 自己的私钥。
   * @param {string} peerPublicB64 - 对端公钥（base64，65 字节未压缩点）。
   * @param {string} saltText - HKDF salt（用设备 id，保证每台设备密钥不同）。
   * @returns {Promise<CryptoKey>} 可用于 encrypt/decrypt 的 AES 密钥。
   */
  async function deriveKey(privateKey, peerPublicB64, saltText) {
    var peerRaw = b64decode(peerPublicB64)
    var peerKey = await subtle().importKey(
      'raw',
      peerRaw,
      { name: 'ECDH', namedCurve: 'P-256' },
      false,
      [],
    )
    var shared = await subtle().deriveBits({ name: 'ECDH', public: peerKey }, privateKey, 256)
    var hkdfKey = await subtle().importKey('raw', shared, 'HKDF', false, ['deriveKey'])
    var enc = new TextEncoder()
    return subtle().deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: enc.encode(String(saltText || '')),
        info: enc.encode(PROTOCOL),
      },
      hkdfKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt'],
    )
  }

  /**
   * 加密一段明文并封成帧。
   *
   * @param {CryptoKey} key - AES 密钥。
   * @param {Uint8Array} plaintext - 明文。
   * @returns {Promise<Uint8Array>} 完整帧（可直接写进 WebSocket / SW 回传）。
   */
  async function seal(key, plaintext) {
    var nonce = root.crypto.getRandomValues(new Uint8Array(NONCE_BYTES))
    var cipher = new Uint8Array(await subtle().encrypt({ name: 'AES-GCM', iv: nonce }, key, plaintext))
    var payload = NONCE_BYTES + cipher.length
    var frame = new Uint8Array(HEADER_BYTES + payload)
    new DataView(frame.buffer).setUint32(0, payload, false)
    frame.set(nonce, HEADER_BYTES)
    frame.set(cipher, HEADER_BYTES + NONCE_BYTES)
    return frame
  }

  /**
   * 从帧里解出明文。
   *
   * @param {CryptoKey} key - AES 密钥。
   * @param {Uint8Array} frame - 至少包含一个完整帧。
   * @returns {Promise<{plaintext: Uint8Array, consumed: number}>} 明文与消耗的字节数。
   */
  async function open(key, frame) {
    if (frame.length < HEADER_BYTES) throw new Error('帧太短：缺少长度头')
    var payload = new DataView(frame.buffer, frame.byteOffset, frame.byteLength).getUint32(0, false)
    if (payload < NONCE_BYTES + 16 || payload > MAX_FRAME_BYTES) {
      throw new Error('帧长度非法：' + payload)
    }
    var total = HEADER_BYTES + payload
    if (frame.length < total) throw new Error('帧不完整')
    var nonce = frame.subarray(HEADER_BYTES, HEADER_BYTES + NONCE_BYTES)
    var cipher = frame.subarray(HEADER_BYTES + NONCE_BYTES, total)
    var plaintext = new Uint8Array(await subtle().decrypt({ name: 'AES-GCM', iv: nonce }, key, cipher))
    return { plaintext: plaintext, consumed: total }
  }

  /**
   * 流式解帧器：WebSocket 消息可能把多帧粘在一起，也可能把一个帧拆开。
   * 喂多少收多少，攒够一个完整帧就吐出来。
   *
   * @param {CryptoKey} key - AES 密钥。
   * @returns {{ push: (chunk: Uint8Array) => Promise<Uint8Array[]> }} 解帧器。
   */
  function createReader(key) {
    var buffer = new Uint8Array(0)
    return {
      async push(chunk) {
        var merged = new Uint8Array(buffer.length + chunk.length)
        merged.set(buffer, 0)
        merged.set(chunk, buffer.length)
        buffer = merged
        var out = []
        for (;;) {
          if (buffer.length < HEADER_BYTES) break
          var payload = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength).getUint32(0, false)
          if (payload <= 0 || payload > MAX_FRAME_BYTES) throw new Error('帧长度非法：' + payload)
          var total = HEADER_BYTES + payload
          if (buffer.length < total) break
          var result = await open(key, buffer.subarray(0, total))
          out.push(result.plaintext)
          buffer = buffer.subarray(result.consumed)
        }
        return out
      },
    }
  }

  root.DshE2E = {
    PROTOCOL: PROTOCOL,
    generateKeyPair: generateKeyPair,
    deriveKey: deriveKey,
    seal: seal,
    open: open,
    createReader: createReader,
    b64encode: b64encode,
    b64decode: b64decode,
  }
})(typeof self !== 'undefined' ? self : globalThis)
