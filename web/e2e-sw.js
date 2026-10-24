/**
 * 端到端加密的 Service Worker（手机侧）。
 *
 * ## 它做什么
 *
 * 接管 `/m/*` 下的**请求体与响应体**，在浏览器与服务端之间加一层 AES-256-GCM：
 *
 * ```
 * 页面 fetch('/m/api/x', {body})   本来明文
 *      ↓ SW 拦截，seal(密钥, body)  变成密文
 *   发给服务端 → Cloudflare 只看到密文 → PC 上插件解密
 * ```
 *
 * **不加密** HTML / JS / CSS：浏览器必须能直接执行它们，加密了就跑不起来。
 *
 * ## 握手（关键）
 *
 * 密钥不能写在页面里（那等于没加密）。流程：
 *
 *   1. SW 生成 P-256 密钥对（**私钥永不离开 SW**）。
 *   2. SW 把公钥 PUT 到 `/m/e2e/handshake`，服务端回应自己的公钥。
 *   3. 双方 ECDH → HKDF（salt = 设备 id）→ 同一个 AES 密钥。
 *   4. 之后所有 `/m/api/*`、`/m/e2e/data/*` 的 body 都走密文。
 *
 * 握手本身用设备 cookie 认证（`credentials: 'include'`），所以只有配对过的
 * 设备能建立会话密钥。
 *
 * ## 什么**不**加密（诚实说明）
 *
 * - **URL 路径**：Cloudflare 能看到你请求了 `/m/api/session/list`。
 * - **HTML/JS/CSS 内容**：必须明文下发才能执行。
 * - **响应长度与时序**：密文长度 ≈ 明文长度，能推断个大概。
 *
 * 换句话说：**内容受保护，元数据不保护**。这是网页方案的物理上限。
 *
 * @module dsh-plugin-remote-mobile/e2e-sw
 */

/* global self, DshE2E, caches, fetch, URL, Request, Response, Headers */

importScripts('/m/e2e-crypto.js')

/** 端到端相关的路径前缀（只有这些走加密）。 */
const E2E_PREFIX = '/m/e2e/'

/** 握手端点。 */
const HANDSHAKE_PATH = '/m/e2e/handshake'

/** 密钥缓存名（存的是**公钥与 salt**，私钥只在内存）。 */
const STATE_CACHE = 'dsh-e2e-state-v1'

/** 内存里的会话状态。SW 被回收就重新握手。 */
let session = null

/** 握手进行中的 Promise（避免并发握手指向两个会话）。 */
let handshaking = null

/**
 * 从 Cache Storage 读上次的公钥（仅用于跨 SW 重启保持稳定，不存私钥）。
 * @returns {Promise<{ publicKeyB64?: string, deviceId?: string }|undefined>} 状态。
 */
async function readPersistedState() {
  try {
    const cache = await caches.open(STATE_CACHE)
    const hit = await cache.match('/m/e2e/state')
    if (!hit) return undefined
    return await hit.json()
  } catch {
    return undefined
  }
}

/**
 * 持久化公钥与设备 id（**不存私钥**）。
 * @param {{ publicKeyB64: string, deviceId: string }} state - 状态。
 * @returns {Promise<void>} 完成。
 */
async function persistState(state) {
  try {
    const cache = await caches.open(STATE_CACHE)
    await cache.put('/m/e2e/state', new Response(JSON.stringify(state), {
      headers: { 'content-type': 'application/json' },
    }))
  } catch {
    // 存不进去不影响功能（下次重新握手即可）。
  }
}

/**
 * 与服务端握手，建立会话密钥。
 * @returns {Promise<boolean>} 是否成功。
 */
async function handshake() {
  if (handshaking) return handshaking
  handshaking = (async () => {
    try {
      const pair = await DshE2E.generateKeyPair()
      const response = await fetch(HANDSHAKE_PATH, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        // 关键：带上设备 cookie，服务端据此认定是哪台设备。
        credentials: 'include',
        body: JSON.stringify({ publicKey: pair.publicKeyB64 }),
      })
      if (!response.ok) return false
      const payload = await response.json()
      if (!payload || typeof payload.publicKey !== 'string' || typeof payload.deviceId !== 'string') {
        return false
      }
      const key = await DshE2E.deriveKey(pair.privateKey, payload.publicKey, payload.deviceId)
      session = { key, deviceId: payload.deviceId }
      await persistState({ publicKeyB64: pair.publicKeyB64, deviceId: payload.deviceId })
      return true
    } catch {
      return false
    } finally {
      handshaking = null
    }
  })()
  return handshaking
}

/**
 * 确保已有会话密钥。
 * @returns {Promise<boolean>} 是否可用。
 */
async function ensureSession() {
  if (session) return true
  return handshake()
}

/**
 * 处理一次加密请求：加密 body、发出去、解密响应。
 *
 * @param {Request} request - 原始请求。
 * @returns {Promise<Response>} 解密后的响应（体是明文，页面拿到的和普通请求一样）。
 */
async function handleEncrypted(request) {
  if (!(await ensureSession())) {
    return new Response(JSON.stringify({ ok: false, error: { code: 'rm/e2e-unsupported', message: '端到端握手失败' } }), {
      status: 502,
      headers: { 'content-type': 'application/json' },
    })
  }

  const url = new URL(request.url)
  // 明文 body（GET 没有 body）。
  const plainBody = request.method === 'GET' || request.method === 'HEAD'
    ? new Uint8Array(0)
    : new Uint8Array(await request.arrayBuffer())
  const sealed = await DshE2E.seal(session.key, plainBody)

  // 把路径从 /m/e2e/xxx 映射到服务端真实的 /m/xxx。
  const target = url.pathname.slice(E2E_PREFIX.length - 1) + url.search

  const headers = new Headers()
  // 只保留必要的头；content-type 服务端会自己判断（密文是二进制）。
  headers.set('content-type', 'application/octet-stream')
  headers.set('x-dsh-e2e', '1')
  // 原始方法与路径要告诉服务端（因为密文里只有 body）。
  headers.set('x-dsh-e2e-method', request.method)
  headers.set('x-dsh-e2e-path', target)

  let upstream
  try {
    upstream = await fetch(target, {
      method: 'POST',
      headers,
      credentials: 'include',
      body: sealed,
    })
  } catch (error) {
    return new Response(JSON.stringify({ ok: false, error: { code: 'rm/e2e-network', message: String(error && error.message || error) } }), {
      status: 502,
      headers: { 'content-type': 'application/json' },
    })
  }

  // 服务端的响应也是密文（除非它是错误页）。
  if (upstream.headers.get('x-dsh-e2e') !== '1') {
    // 服务端没加密（老版本 / 错误）→ 原样返回，页面能照常处理。
    return upstream
  }

  const sealedResp = new Uint8Array(await upstream.arrayBuffer())
  const reader = DshE2E.createReader(session.key)
  const chunks = await reader.push(sealedResp)
  const merged = new Uint8Array(chunks.reduce((sum, part) => sum + part.length, 0))
  let offset = 0
  for (const part of chunks) {
    merged.set(part, offset)
    offset += part.length
  }

  const respHeaders = new Headers(upstream.headers)
  respHeaders.delete('x-dsh-e2e')
  respHeaders.delete('content-encoding')
  respHeaders.delete('content-length')
  // 解密后是明文，标回原始 content-type（服务端放在自定义头里）。
  const originalType = upstream.headers.get('x-dsh-e2e-content-type')
  if (originalType) respHeaders.set('content-type', originalType)
  respHeaders.delete('x-dsh-e2e-content-type')

  return new Response(merged, { status: upstream.status, statusText: upstream.statusText, headers: respHeaders })
}

/**
 * SW 安装：立刻接管。
 */
self.addEventListener('install', (event) => {
  event.waitUntil(self.skipWaiting())
})

/**
 * SW 激活：清掉旧缓存，接管所有页面。
 */
self.addEventListener('activate', (event) => {
  event.waitUntil((async () => {
    // 清掉除状态缓存外的旧版本缓存。
    const names = await caches.keys()
    await Promise.all(names.filter((name) => name !== STATE_CACHE && name.startsWith('dsh-e2e-')).map((name) => caches.delete(name)))
    await self.clients.claim()
  })())
})

/**
 * 拦截请求。
 *
 * 只有 `/m/e2e/*` 走加密；其余（HTML/JS/CSS/图片、以及明文 API）原样放行。
 * 这样即使加密出问题，页面本身仍能加载——降级路径是明确的。
 */
self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url)
  if (!url.pathname.startsWith(E2E_PREFIX)) return
  if (url.pathname === HANDSHAKE_PATH) return
  event.respondWith(handleEncrypted(event.request))
})

/**
 * 页面可以通过 postMessage 查状态（调试用）。
 */
self.addEventListener('message', (event) => {
  if (event.data === 'e2e-status') {
    event.source?.postMessage({ type: 'e2e-status', ready: session !== null })
  }
})
