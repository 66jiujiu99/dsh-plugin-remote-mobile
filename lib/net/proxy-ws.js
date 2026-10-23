/**
 * `/api/remote.mux` 的 WebSocket 裸透传（PROTOCOL §1、PLAN §3.1.6）。
 *
 * **不用 `ws` 库**：插件包解析不到 Electron 壳的 node_modules，而给 profile 加依赖要
 * 走联网安装。这里的做法是 `net.connect` 上游后手工写握手请求，然后把两条 socket
 * 用「帧感知的 Transform」接起来——帧本身端到端透传，插件只在两处插手：
 *
 *   1. **上游 → 手机**：`$events` 的 ready 帧里 `host.home` 会泄露 PC 的用户主目录
 *      （实测 `C:\Users\jiujiu`），这里把 `value.host` 换成 `{home:'~'}`。
 *      只在「完整文本帧 + JSON.parse 成功 + `value.type==='ready'`」时改写，其余原样。
 *   2. **手机 → 上游**：`open` 帧里的 `endpoint` 必须是流端点（`session/follow` /
 *      `session/control` / `workspace/follow` / `$events`），否则本地回一条 error 帧并
 *      丢弃该帧（否则上游会回 `gateway/signature-invalid`，手机上看到的是难懂的协议错误）。
 *
 * 另外：握手时**剥掉 `Sec-WebSocket-Extensions`**（permessage-deflate）。浏览器默认
 * 会带它，一旦协商成功帧就是压缩的，上面第 1 条就没法解析了；局域网带宽不是瓶颈，
 * 关掉压缩换取可审计性。
 *
 * 帧解析以 RFC6455 为准：server→client 帧不带 mask，client→server 帧带 mask。
 * 分片消息（`fin=0`）不重写，原样透传（DSH 的 JSON 帧都很小，不会分片）。
 *
 * @module dsh-plugin-remote-mobile/proxy-ws
 */

import net from 'node:net'
import { Transform } from 'node:stream'

import { STREAM_ENDPOINTS } from '../policy/policy.js'

/** 握手响应头的上限：防止对端灌垃圾把内存撑爆。 */
const MAX_HANDSHAKE_BYTES = 16 * 1024

/** 单帧上限（16MiB，远大于正常 JSON 帧）。 */
const MAX_FRAME_BYTES = 16 * 1024 * 1024

/** opcode：文本帧。 */
const OP_TEXT = 0x1

/** 解析一帧后的结果。 @typedef {{ fin: boolean, opcode: number, masked: boolean, payload: Buffer, total: number }} ParsedFrame */

/**
 * 从缓冲区里切出一帧（payload 需要时解 mask；不复制未 masked 的 payload）。
 * @param {Buffer} buffer - 缓冲区。
 * @param {number} [offset] - 起始偏移。
 * @returns {{ ok: true, frame: ParsedFrame }|{ ok: false, need: number }} 解析结果。
 */
export function readFrame(buffer, offset = 0) {
  const available = buffer.length - offset
  if (available < 2) return { ok: false, need: 2 - available }
  const first = buffer[offset]
  const second = buffer[offset + 1]
  const fin = (first & 0x80) !== 0
  const opcode = first & 0x0f
  const masked = (second & 0x80) !== 0
  let length = second & 0x7f
  let cursor = offset + 2
  if (length === 126) {
    if (buffer.length - cursor < 2) return { ok: false, need: 2 - (buffer.length - cursor) }
    length = buffer.readUInt16BE(cursor)
    cursor += 2
  } else if (length === 127) {
    if (buffer.length - cursor < 8) return { ok: false, need: 8 - (buffer.length - cursor) }
    const big = buffer.readBigUInt64BE(cursor)
    if (big > BigInt(Number.MAX_SAFE_INTEGER)) return { ok: false, need: Number.MAX_SAFE_INTEGER }
    length = Number(big)
    cursor += 8
  }
  if (length > MAX_FRAME_BYTES) return { ok: false, need: Number.MAX_SAFE_INTEGER }
  let mask
  if (masked) {
    if (buffer.length - cursor < 4) return { ok: false, need: 4 - (buffer.length - cursor) }
    mask = buffer.subarray(cursor, cursor + 4)
    cursor += 4
  }
  if (buffer.length - cursor < length) return { ok: false, need: length - (buffer.length - cursor) }
  const raw = buffer.subarray(cursor, cursor + length)
  let payload = raw
  if (masked) {
    payload = Buffer.allocUnsafe(length)
    for (let index = 0; index < length; index += 1) payload[index] = raw[index] ^ mask[index & 3]
  }
  return { ok: true, frame: { fin, opcode, masked, payload, total: cursor + length - offset } }
}

/**
 * 编码一帧 server→client 帧（不带 mask）。
 * @param {number} opcode - opcode。
 * @param {Buffer} payload - payload。
 * @param {boolean} [fin] - 是否终结帧。
 * @returns {Buffer} 帧字节。
 */
export function encodeFrame(opcode, payload, fin = true) {
  const length = payload.length
  let header
  if (length < 126) {
    header = Buffer.allocUnsafe(2)
    header[1] = length
  } else if (length < 65_536) {
    header = Buffer.allocUnsafe(4)
    header[1] = 126
    header.writeUInt16BE(length, 2)
  } else {
    header = Buffer.allocUnsafe(10)
    header[1] = 127
    header.writeBigUInt64BE(BigInt(length), 2)
  }
  header[0] = (fin ? 0x80 : 0) | (opcode & 0x0f)
  return Buffer.concat([header, payload], header.length + length)
}

/**
 * 造一个能重写帧的 Transform。
 *
 * @param {object} options - 参数。
 * @param {(frame: ParsedFrame) => Buffer|null|undefined} options.onFrame - 返回新帧字节则替换；null 丢弃；undefined 原样透传。
 * @param {(error: Error) => void} [options.onError] - 解析失败回调（之后切回裸透传）。
 * @returns {Transform} 流。
 */
function frameTransform({ onFrame, onError }) {
  /** @type {Buffer} */
  let pending = Buffer.alloc(0)
  let passthrough = false
  return new Transform({
    transform(chunk, _encoding, callback) {
      if (passthrough) {
        callback(null, chunk)
        return
      }
      pending = pending.length === 0 ? chunk : Buffer.concat([pending, chunk])
      try {
        for (;;) {
          if (pending.length === 0) break
          const parsed = readFrame(pending, 0)
          if (parsed.ok !== true) {
            // 帧头都解析不了（need 巨大）→ 流已错位，切裸透传。
            if (parsed.need === Number.MAX_SAFE_INTEGER) throw new Error('frame-too-large')
            break
          }
          const { frame } = parsed
          const raw = pending.subarray(0, frame.total)
          pending = pending.subarray(frame.total)
          const replacement = onFrame(frame)
          if (replacement === null) continue
          this.push(replacement === undefined ? raw : replacement)
        }
      } catch (error) {
        passthrough = true
        onError?.(error instanceof Error ? error : new Error(String(error)))
        this.push(pending)
        pending = Buffer.alloc(0)
      }
      callback()
    },
    flush(callback) {
      if (pending.length > 0) this.push(pending)
      pending = Buffer.alloc(0)
      callback()
    },
  })
}

/**
 * 上游 → 手机方向的帧处理：只改 ready 帧里的 `host`。
 * @param {{ fin: boolean, opcode: number, payload: Buffer }} frame - 帧。
 * @returns {Buffer|undefined} 新帧字节；undefined 表示原样透传。
 */
export function sanitizeServerFrame(frame) {
  if (frame.opcode !== OP_TEXT || frame.fin !== true) return undefined
  let parsed
  try {
    parsed = JSON.parse(frame.payload.toString('utf8'))
  } catch {
    return undefined
  }
  if (typeof parsed !== 'object' || parsed === null) return undefined
  let mutated = false
  // 形状 A：{type:'item', streamId, value:{type:'ready', clientId, host}}（mux 实际形状）
  const value = parsed.value
  if (value !== null && typeof value === 'object' && value.type === 'ready' && value.host !== undefined) {
    value.host = { home: '~' }
    mutated = true
  }
  // 形状 B：{type:'ready', host}（万一上游直接透传 ready 帧）
  if (parsed.type === 'ready' && parsed.host !== undefined) {
    parsed.host = { home: '~' }
    mutated = true
  }
  if (!mutated) return undefined
  return encodeFrame(OP_TEXT, Buffer.from(JSON.stringify(parsed), 'utf8'))
}

/**
 * 手机 → 上游方向的帧处理：校验 `open` 帧的 endpoint。
 * @param {{ fin: boolean, opcode: number, payload: Buffer }} frame - 帧。
 * @param {(endpoint: string) => { ok: boolean, message?: string }} authorizeOpen - 端点判定（只读/黑名单）。
 * @returns {{ action: 'pass' }|{ action: 'drop', error: { streamId?: string, message: string } }} 决定。
 */
export function inspectClientFrame(frame, authorizeOpen) {
  if (frame.opcode !== OP_TEXT || frame.fin !== true) return { action: 'pass' }
  let parsed
  try {
    parsed = JSON.parse(frame.payload.toString('utf8'))
  } catch {
    return { action: 'pass' }
  }
  if (typeof parsed !== 'object' || parsed === null || parsed.type !== 'open') return { action: 'pass' }
  const endpoint = typeof parsed.endpoint === 'string' ? parsed.endpoint : ''
  const streamId = typeof parsed.streamId === 'string' ? parsed.streamId : undefined
  if (!STREAM_ENDPOINTS.includes(endpoint)) {
    return {
      action: 'drop',
      error: {
        streamId,
        message: `端点 ${endpoint || '(空)'} 不是流端点，不能通过 /api/remote.mux 打开；`
          + 'unary 端点请走 POST /m/api/<endpoint>',
      },
    }
  }
  const verdict = authorizeOpen(endpoint)
  if (verdict.ok !== true) {
    return { action: 'drop', error: { streamId, message: verdict.message ?? '该端点不被允许' } }
  }
  return { action: 'pass' }
}

/**
 * 把一个已通过鉴权的 upgrade 请求透传到上游。
 *
 * @param {object} options - 参数。
 * @param {import('node:http').IncomingMessage} options.req - 原始 upgrade 请求。
 * @param {import('node:net').Socket} options.socket - 客户端 socket。
 * @param {Buffer} options.head - upgrade 事件里已读出的残留字节。
 * @param {{ hostname: string, port: number, authority: string, origin: string, cookie?: string }} options.target - 上游地址与凭据。
 * @param {(endpoint: string) => { ok: boolean, message?: string }} options.authorizeOpen - `open` 帧端点判定。
 * @param {(event: string, fields?: Record<string, unknown>) => void} [options.audit] - 审计。
 * @param {(level: 'debug'|'info'|'warn'|'error', message: string) => void} [options.log] - 日志。
 * @param {(reason: string) => void} [options.onClose] - 任一侧断开时回调（监听器用来记账）。
 * @param {string} [options.upstreamPath] - 发给上游的请求路径（已剥掉 `/m` 前缀）；缺省用 `req.url`。
 * @returns {{ closed: boolean }} 句柄。
 */
export function proxyWebSocket({ req, socket, head, target, authorizeOpen, audit, log, onClose, upstreamPath }) {
  const handle = { closed: false }
  let finished = false

  /** @type {import('node:net').Socket|undefined} */
  let upSocket
  /** @type {Transform|undefined} */
  let s2c
  /** @type {Transform|undefined} */
  let c2s
  /** 握手前客户端已经发出的字节（`head`）。 */
  let clientLeftover = head !== undefined && head.length > 0 ? Buffer.from(head) : undefined
  /** 握手响应的累积缓冲。 */
  let headerBuffer = Buffer.alloc(0)
  /** 握手完成前上游吐出的帧字节。 */
  let upstreamResidual = Buffer.alloc(0)
  let handshakeDone = false

  /**
   * 收尾：销毁所有流，只回调一次。
   * @param {string} reason - 原因。
   * @returns {void}
   */
  function finish(reason) {
    if (finished) return
    finished = true
    handle.closed = true
    for (const record of [s2c, c2s, upSocket]) {
      try {
        record?.destroy()
      } catch {
        // 已经销毁。
      }
    }
    try {
      socket.destroy()
    } catch {
      // 已经断开。
    }
    onClose?.(reason)
  }

  // 两侧都不设超时，否则 Node 默认的 300s 会把长连接掐断。
  socket.setTimeout(0)
  socket.setNoDelay(true)
  socket.on('error', () => finish('client-error'))
  socket.on('close', () => finish('client-close'))

  const version = req.headers['sec-websocket-version']
  const key = req.headers['sec-websocket-key']
  if (typeof version !== 'string' || typeof key !== 'string' || key === '') {
    try {
      socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n')
    } catch {
      // 已断开。
    }
    finish('bad-handshake')
    return handle
  }

  // `upstreamPath`：整站反代形态下手机请求的是 `/m/api/remote.mux`，
  // 但上游只认 `/api/remote.mux`，所以路径必须由调用方显式给出（已剥掉前缀）。
  const lines = [
    `GET ${typeof upstreamPath === 'string' && upstreamPath !== '' ? upstreamPath : (req.url ?? '/api/remote.mux')} HTTP/1.1`,
    `Host: ${target.authority}`,
    `Origin: ${target.origin}`,
    'Upgrade: websocket',
    'Connection: Upgrade',
    `Sec-WebSocket-Key: ${key}`,
    `Sec-WebSocket-Version: ${version}`,
  ]
  if (typeof target.cookie === 'string' && target.cookie !== '') lines.push(`Cookie: ${target.cookie}`)
  // 见文件头注释：主动关掉 permessage-deflate，保证帧可解析。
  const protocol = req.headers['sec-websocket-protocol']
  if (typeof protocol === 'string' && protocol !== '') lines.push(`Sec-WebSocket-Protocol: ${protocol}`)
  if (typeof req.headers['user-agent'] === 'string') lines.push(`User-Agent: ${req.headers['user-agent']}`)
  const requestText = `${lines.join('\r\n')}\r\n\r\n`

  /**
   * 建立两条帧管线（只在拿到 101 之后调用）。
   * @returns {void}
   */
  function startFramePumps() {
    s2c = frameTransform({
      onFrame: (frame) => sanitizeServerFrame(frame),
      onError: (error) => {
        log?.('warn', `remote-mobile: mux 下游帧解析失败，切裸透传：${error.message}`)
      },
    })
    c2s = frameTransform({
      onFrame: (frame) => {
        const decision = inspectClientFrame(frame, authorizeOpen)
        if (decision.action === 'pass') return undefined
        audit?.('ws-frame-denied', { streamId: decision.error.streamId, message: decision.error.message })
        const errorFrame = encodeFrame(OP_TEXT, Buffer.from(JSON.stringify({
          type: 'error',
          ...(decision.error.streamId === undefined ? {} : { streamId: decision.error.streamId }),
          error: { code: 'rm/stream-not-allowed', message: decision.error.message },
        }), 'utf8'))
        try {
          socket.write(errorFrame)
        } catch {
          finish('client-write-failed')
        }
        // 丢弃这一帧（不转发给上游）。
        return null
      },
      onError: (error) => {
        log?.('warn', `remote-mobile: mux 上行帧解析失败，切裸透传：${error.message}`)
      },
    })
    s2c.on('error', () => finish('s2c-error'))
    c2s.on('error', () => finish('c2s-error'))

    upSocket.removeListener('data', onUpstreamData)
    upSocket.pipe(s2c).pipe(socket, { end: false })
    socket.pipe(c2s).pipe(upSocket, { end: false })
    if (upstreamResidual.length > 0) {
      s2c.write(upstreamResidual)
      upstreamResidual = Buffer.alloc(0)
    }
    if (clientLeftover !== undefined) {
      c2s.write(clientLeftover)
      clientLeftover = undefined
    }
  }

  /**
   * 握手阶段：解析上游响应头；101 就切管线，其它状态原样转发。
   * @param {Buffer} chunk - 上游数据。
   * @returns {void}
   */
  function feedHandshake(chunk) {
    headerBuffer = Buffer.concat([headerBuffer, chunk])
    const end = headerBuffer.indexOf('\r\n\r\n')
    if (end < 0) {
      if (headerBuffer.length > MAX_HANDSHAKE_BYTES) finish('upstream-handshake-too-large')
      return
    }
    const headerText = headerBuffer.subarray(0, end + 4).toString('latin1')
    upstreamResidual = Buffer.from(headerBuffer.subarray(end + 4))
    headerBuffer = Buffer.alloc(0)
    const statusLine = headerText.split('\r\n', 1)[0]
    const status = Number(/^HTTP\/1\.[01] (\d{3})/.exec(statusLine)?.[1] ?? 0)
    if (status !== 101) {
      audit?.('ws-rejected', { status, path: req.url })
      try {
        socket.write(Buffer.from(headerText, 'latin1'))
        if (upstreamResidual.length > 0) socket.write(upstreamResidual)
      } catch {
        // 客户端已断开。
      }
      // 剩下的响应 body 原样转发（上游可能带一段说明），转发完就收尾。
      upSocket.removeListener('data', onUpstreamData)
      upSocket.on('data', (rest) => {
        try {
          socket.write(rest)
        } catch {
          finish('client-write-failed')
        }
      })
      upSocket.on('end', () => finish('upstream-rejected'))
      upSocket.on('close', () => finish('upstream-closed'))
      return
    }
    // 101：上游响应头原样交给手机（Sec-WebSocket-Accept 是对原始 key 算的，必须原样）。
    try {
      socket.write(Buffer.from(headerText, 'latin1'))
    } catch {
      finish('client-write-failed')
      return
    }
    handshakeDone = true
    audit?.('ws-open', { path: req.url })
    startFramePumps()
  }

  /**
   * 上游数据入口：握手前解析头，握手后交给 s2c 管线（管线建好后本监听器被移除）。
   * @param {Buffer} chunk - 数据。
   * @returns {void}
   */
  function onUpstreamData(chunk) {
    if (handshakeDone) return
    feedHandshake(chunk)
  }

  upSocket = net.connect({ host: target.hostname, port: target.port })
  upSocket.setTimeout(0)
  upSocket.setNoDelay(true)
  upSocket.on('data', onUpstreamData)
  upSocket.on('error', (error) => {
    if (handshakeDone) return
    log?.('warn', `remote-mobile: mux 上游连接失败：${String(error?.message ?? error)}`)
    try {
      socket.end('HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n')
    } catch {
      // 已断开。
    }
    finish('upstream-error')
  })
  upSocket.on('close', () => {
    if (!handshakeDone) finish('upstream-closed')
  })
  upSocket.on('connect', () => {
    upSocket.write(requestText, 'latin1')
  })

  return handle
}
