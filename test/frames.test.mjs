/**
 * WS 帧编解码与重写（lib/net/proxy-ws.js 的纯函数）。
 *
 * 覆盖三件事：
 *   1. `readFrame` 能解 client→server 的 masked 帧（含 126/127 长长度分支）；
 *   2. `sanitizeServerFrame` 只改 ready 帧的 `host`，其它帧原样；
 *   3. `inspectClientFrame` 在本地挡掉非流端点的 `open` 帧。
 */

import assert from 'node:assert/strict'
import test from 'node:test'

import {
  encodeFrame,
  inspectClientFrame,
  readFrame,
  sanitizeServerFrame,
} from '../lib/net/proxy-ws.js'

/**
 * 编码一帧 client→server（带 mask），用于喂 `readFrame`。
 * @param {number} opcode - opcode。
 * @param {Buffer} payload - payload。
 * @param {boolean} [fin] - 是否终结。
 * @returns {Buffer} 帧字节。
 */
function encodeMasked(opcode, payload, fin = true) {
  const mask = Buffer.from([0x11, 0x22, 0x33, 0x44])
  const length = payload.length
  let header
  if (length < 126) {
    header = Buffer.allocUnsafe(2)
    header[1] = 0x80 | length
  } else if (length < 65_536) {
    header = Buffer.allocUnsafe(4)
    header[1] = 0x80 | 126
    header.writeUInt16BE(length, 2)
  } else {
    header = Buffer.allocUnsafe(10)
    header[1] = 0x80 | 127
    header.writeBigUInt64BE(BigInt(length), 2)
  }
  header[0] = (fin ? 0x80 : 0) | (opcode & 0x0f)
  const masked = Buffer.from(payload)
  for (let index = 0; index < masked.length; index += 1) masked[index] ^= mask[index & 3]
  return Buffer.concat([header, mask, masked])
}

test('readFrame：masked 文本帧往返', () => {
  const payload = Buffer.from(JSON.stringify({ type: 'open', streamId: 'f1', endpoint: '$events' }))
  const frame = encodeMasked(0x1, payload)
  const parsed = readFrame(frame, 0)
  assert.equal(parsed.ok, true)
  assert.equal(parsed.frame.opcode, 0x1)
  assert.equal(parsed.frame.masked, true)
  assert.equal(parsed.frame.fin, true)
  assert.equal(parsed.frame.total, frame.length)
  assert.deepEqual(parsed.frame.payload, payload)
  // 只有部分字节时要求更多数据。
  const partial = readFrame(frame.subarray(0, 4), 0)
  assert.equal(partial.ok, false)
  assert.equal(partial.need > 0, true)
})

test('readFrame：126 与 127 长度分支', () => {
  const medium = Buffer.alloc(300, 0x41)
  const frameMedium = encodeMasked(0x1, medium)
  const parsedMedium = readFrame(frameMedium, 0)
  assert.equal(parsedMedium.ok, true)
  assert.equal(parsedMedium.frame.payload.length, 300)

  const large = Buffer.alloc(70_000, 0x42)
  const frameLarge = encodeMasked(0x2, large)
  const parsedLarge = readFrame(frameLarge, 0)
  assert.equal(parsedLarge.ok, true)
  assert.equal(parsedLarge.frame.payload.length, 70_000)
  assert.equal(parsedLarge.frame.opcode, 0x2)
})

test('readFrame：缓冲区里有两帧时能顺序切出（total 偏移正确）', () => {
  const first = encodeMasked(0x1, Buffer.from('{"a":1}'))
  const second = encodeMasked(0x1, Buffer.from('{"b":2}'))
  const buffer = Buffer.concat([first, second])
  const parsedFirst = readFrame(buffer, 0)
  assert.equal(parsedFirst.ok, true)
  const parsedSecond = readFrame(buffer, parsedFirst.frame.total)
  assert.equal(parsedSecond.ok, true)
  assert.equal(parsedSecond.frame.payload.toString('utf8'), '{"b":2}')
})

test('encodeFrame：server→client 帧不带 mask，长度正确', () => {
  const payload = Buffer.from('hello')
  const frame = encodeFrame(0x1, payload)
  assert.equal(frame.length, payload.length + 2)
  assert.equal(frame[0], 0x81)
  assert.equal(frame[1], 5)
  const parsed = readFrame(frame, 0)
  assert.equal(parsed.ok, true)
  assert.equal(parsed.frame.masked, false)
  assert.equal(parsed.frame.payload.toString('utf8'), 'hello')

  const big = encodeFrame(0x1, Buffer.alloc(200, 0x61))
  assert.equal(big[1], 126)
  assert.equal(readFrame(big, 0).frame.payload.length, 200)
})

test('sanitizeServerFrame：ready 帧的 host 被换成 {home:"~"}（$events 首帧脱敏）', () => {
  const ready = {
    type: 'item',
    streamId: 's1',
    value: { type: 'ready', clientId: 'c1', host: { home: 'C:\\Users\\jiujiu' } },
  }
  const frame = { fin: true, opcode: 0x1, masked: false, payload: Buffer.from(JSON.stringify(ready)) }
  const rewritten = sanitizeServerFrame(frame)
  assert.notEqual(rewritten, undefined)
  // 返回值是完整帧（含 2 字节头），解出来再断言。
  const reparsed = readFrame(rewritten, 0)
  assert.equal(reparsed.ok, true)
  const parsed = JSON.parse(reparsed.frame.payload.toString('utf8'))
  assert.deepEqual(parsed.value.host, { home: '~' })
  assert.equal(parsed.value.clientId, 'c1')
  assert.equal(rewritten.includes('C:\\Users'), false)
})

test('sanitizeServerFrame：非 ready 帧原样透传（返回 undefined）', () => {
  const item = { type: 'item', streamId: 's1', value: { type: 'event', event: { type: 'turn/start' } } }
  assert.equal(
    sanitizeServerFrame({ fin: true, opcode: 0x1, masked: false, payload: Buffer.from(JSON.stringify(item)) }),
    undefined,
  )
  // 非文本帧、分片帧、非 JSON 文本帧都原样。
  assert.equal(sanitizeServerFrame({ fin: true, opcode: 0x2, masked: false, payload: Buffer.from('{}') }), undefined)
  assert.equal(sanitizeServerFrame({ fin: false, opcode: 0x1, masked: false, payload: Buffer.from('{}') }), undefined)
  assert.equal(sanitizeServerFrame({ fin: true, opcode: 0x1, masked: false, payload: Buffer.from('not json') }), undefined)
})

test('inspectClientFrame：open 帧只受策略层约束，不再按端点白名单本地拒', () => {
  // 早期版本在这里按"流端点白名单"本地拒掉非流端点，结果一次次漏
  // （remoteAccess/follow、workspaceFiles/changes、job/list 都漏过）。
  // 现在：黑名单之外的 open 一律放行，交给上游判定。
  const authorizeOpen = () => ({ ok: true })
  const openSessionList = {
    fin: true,
    opcode: 0x1,
    masked: true,
    payload: Buffer.from(JSON.stringify({
      type: 'open',
      streamId: 'f1',
      endpoint: 'session/list',
      payload: { args: { _request: {} } },
    })),
  }
  // 不再因为"看起来不是流"就本地拒。
  assert.equal(inspectClientFrame(openSessionList, authorizeOpen).action, 'pass')

  const openFollow = {
    fin: true,
    opcode: 0x1,
    masked: true,
    payload: Buffer.from(JSON.stringify({ type: 'open', streamId: 'f2', endpoint: 'session/follow' })),
  }
  assert.equal(inspectClientFrame(openFollow, authorizeOpen).action, 'pass')

  // 但**永久黑名单**仍然在本地就拒（这道边界不能交给上游）。
  const openTerminal = {
    fin: true,
    opcode: 0x1,
    masked: true,
    payload: Buffer.from(JSON.stringify({ type: 'open', streamId: 'f3', endpoint: 'terminal/attach' })),
  }
  const blocked = inspectClientFrame(openTerminal, authorizeOpen)
  assert.equal(blocked.action, 'drop')
  assert.equal(blocked.error.streamId, 'f3')

  // 策略层拒绝（例如只读设备的黑名单端点）同样 drop。
  const deniedByPolicy = inspectClientFrame(openFollow, () => ({ ok: false, message: '只读设备不允许' }))
  assert.equal(deniedByPolicy.action, 'drop')
  assert.equal(deniedByPolicy.error.message, '只读设备不允许')

  // 非 open 帧与非 JSON 帧原样放行。
  const cancel = {
    fin: true,
    opcode: 0x1,
    masked: true,
    payload: Buffer.from(JSON.stringify({ type: 'cancel', streamId: 'f2' })),
  }
  assert.equal(inspectClientFrame(cancel, authorizeOpen).action, 'pass')
  assert.equal(
    inspectClientFrame({ fin: true, opcode: 0x1, masked: true, payload: Buffer.from('garbage') }, authorizeOpen).action,
    'pass',
  )
})
