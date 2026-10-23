/**
 * 代理头改写（lib/net/upstream.js 的纯函数）：手机头 → 上游头 / 上游头 → 手机头。
 *
 * 表驱动的理由：这里是整条反代链最容易「漏改一个 header」的地方，每一条都必须
 * 有明确的期望（PROTOCOL §0 的边界铁律）。
 */

import assert from 'node:assert/strict'
import test from 'node:test'

import { rewriteRequestHeaders, rewriteResponseHeaders } from '../lib/net/upstream.js'

test('请求头：Host/Origin/Cookie 被重写，手机凭据与转发头被删掉', () => {
  const mobile = {
    host: '192.168.1.5:17890',
    origin: 'http://192.168.1.5:17890',
    cookie: 'dshm_d=abc.def',
    authorization: 'Bearer nope',
    'x-forwarded-for': '192.168.1.5',
    'x-forwarded-proto': 'http',
    'sec-fetch-site': 'same-origin',
    'sec-fetch-mode': 'cors',
    connection: 'keep-alive',
    'content-length': '999',
    'user-agent': 'MobileSafari',
    accept: 'application/json',
  }
  const out = rewriteRequestHeaders(mobile, {
    authority: '127.0.0.1:13291',
    origin: 'http://127.0.0.1:13291',
    cookie: 'dsh-auth-xyz=v1.payload.sig',
  })
  assert.equal(out.host, '127.0.0.1:13291')
  assert.equal(out.origin, 'http://127.0.0.1:13291')
  assert.equal(out.cookie, 'dsh-auth-xyz=v1.payload.sig')
  assert.equal(out['user-agent'], 'MobileSafari')
  assert.equal(out.accept, 'application/json')
  // 手机侧凭据与转发语义必须消失。
  assert.equal(out.authorization, undefined)
  assert.equal(out['x-forwarded-for'], undefined)
  assert.equal(out['x-forwarded-proto'], undefined)
  assert.equal(out['sec-fetch-site'], undefined)
  assert.equal(out['sec-fetch-mode'], undefined)
  // 旧的 content-length 不能带过去（body 长度已被插件重写）。
  assert.equal(out['content-length'], undefined)
  assert.equal(out.connection, 'close')
})

test('请求头：没有 origin 的请求不硬造 Origin（非浏览器客户端）', () => {
  const out = rewriteRequestHeaders({ host: '10.0.0.2:17890' }, {
    authority: '127.0.0.1:13291',
    origin: 'http://127.0.0.1:13291',
    keepOrigin: false,
  })
  assert.equal(out.origin, undefined)
  assert.equal(out.host, '127.0.0.1:13291')
})

test('响应头：Set-Cookie 与 HSTS 永远不给手机，逐跳头被剥', () => {
  const upstream = {
    'content-type': 'application/json',
    'content-length': '42',
    'set-cookie': ['dsh-auth-xyz=v1.payload.sig; Path=/'],
    'strict-transport-security': 'max-age=63072000',
    connection: 'keep-alive',
    'transfer-encoding': 'chunked',
    'x-content-type-options': 'nosniff',
    etag: 'W/"abc"',
  }
  const out = rewriteResponseHeaders(upstream)
  assert.equal(out['content-type'], 'application/json')
  assert.equal(out['content-length'], '42')
  assert.equal(out['x-content-type-options'], 'nosniff')
  assert.equal(out.etag, 'W/"abc"')
  assert.equal(out['set-cookie'], undefined)
  assert.equal(out['strict-transport-security'], undefined)
  assert.equal(out.connection, undefined)
  assert.equal(out['transfer-encoding'], undefined)
})

test('响应头：数组值合并成一个字符串（Node writeHead 需要）', () => {
  const out = rewriteResponseHeaders({ vary: ['Accept-Encoding', 'Origin'] })
  assert.equal(out.vary, 'Accept-Encoding, Origin')
})
