/**
 * `proxy-site.js` 单测：整站反代的路径、头、重定向改写。
 *
 * 这些是纯函数，钉住四条**安全与正确性**事实：
 *   1. 前缀必须精确剥离（`/mx` 不能被当成 `/m` 下的路径）。
 *   2. 上游 `Set-Cookie` 绝不能下发到手机（安全边界）。
 *   3. 手机的设备 cookie 绝不能发给上游（安全边界）。
 *   4. `Location` 要改回 `/m` 前缀下，否则手机上会跳到根路径（那里是 404）。
 */

import assert from 'node:assert/strict'
import test from 'node:test'

import {
  buildDownstreamHeaders,
  buildUpstreamHeaders,
  isUnderPrefix,
  rewriteLocation,
  stripPrefix,
} from '../lib/net/proxy-site.js'

const PREFIX = '/m'
const UPSTREAM = 'http://127.0.0.1:12345'

test('stripPrefix：精确剥离，保留查询串', () => {
  assert.equal(stripPrefix('/m', PREFIX), '/')
  assert.equal(stripPrefix('/m/', PREFIX), '/')
  assert.equal(stripPrefix('/m/foo', PREFIX), '/foo')
  assert.equal(stripPrefix('/m/foo/bar?x=1&y=2', PREFIX), '/foo/bar?x=1&y=2')
  assert.equal(stripPrefix('/m?sessionId=abc', PREFIX), '/?sessionId=abc')
  assert.equal(stripPrefix('/m/api/remote.mux', PREFIX), '/api/remote.mux')
})

test('stripPrefix：`/mx` 与 `/other` 不被误伤', () => {
  // 关键：`/mx` 不是 `/m` 下的路径，必须原样返回（否则会转发到错误的路径）。
  assert.equal(stripPrefix('/mx', PREFIX), '/mx')
  assert.equal(stripPrefix('/mx/foo', PREFIX), '/mx/foo')
  assert.equal(stripPrefix('/other', PREFIX), '/other')
})

test('isUnderPrefix：边界精确', () => {
  assert.equal(isUnderPrefix('/m', PREFIX), true)
  assert.equal(isUnderPrefix('/m/', PREFIX), true)
  assert.equal(isUnderPrefix('/m/a', PREFIX), true)
  assert.equal(isUnderPrefix('/mx', PREFIX), false)
  assert.equal(isUnderPrefix('/mx/a', PREFIX), false)
  assert.equal(isUnderPrefix('/other', PREFIX), false)
})

test('rewriteLocation：站内路径加前缀', () => {
  assert.equal(rewriteLocation('/login', PREFIX, UPSTREAM), '/m/login')
  assert.equal(rewriteLocation('/', PREFIX, UPSTREAM), '/m/')
  assert.equal(rewriteLocation('/a/b?c=1', PREFIX, UPSTREAM), '/m/a/b?c=1')
})

test('rewriteLocation：已带前缀不二次叠加', () => {
  assert.equal(rewriteLocation('/m/login', PREFIX, UPSTREAM), '/m/login')
  assert.equal(rewriteLocation('/m', PREFIX, UPSTREAM), '/m')
})

test('rewriteLocation：同源绝对 URL 改写，跨域保留', () => {
  assert.equal(
    rewriteLocation('http://127.0.0.1:12345/login', PREFIX, UPSTREAM),
    '/m/login',
  )
  // 跨域：必须原样（改写会破坏第三方跳转）。
  assert.equal(
    rewriteLocation('https://example.com/login', PREFIX, UPSTREAM),
    'https://example.com/login',
  )
})

test('rewriteLocation：相对路径不动（浏览器自带前缀语义）', () => {
  assert.equal(rewriteLocation('foo/bar', PREFIX, UPSTREAM), 'foo/bar')
  assert.equal(rewriteLocation('../x', PREFIX, UPSTREAM), '../x')
  assert.equal(rewriteLocation('', PREFIX, UPSTREAM), '')
})

test('buildUpstreamHeaders：注入上游凭据，剥掉手机凭据', () => {
  const headers = buildUpstreamHeaders(
    {
      host: '192.168.1.5:17890',
      cookie: 'dshm_d=device-secret-should-not-leak',
      authorization: 'Bearer x',
      origin: 'http://192.168.1.5:17890',
      'sec-fetch-site': 'same-origin',
      'x-forwarded-for': '1.2.3.4',
      'user-agent': 'phone',
    },
    { authority: '127.0.0.1:12345', origin: 'http://127.0.0.1:12345', cookie: 'dsh-auth-x=upstream' },
  )

  // 上游视角的 Host/Origin 必须改写（否则上游 401）。
  assert.equal(headers.host, '127.0.0.1:12345')
  assert.equal(headers.origin, 'http://127.0.0.1:12345')
  // 只保留上游凭据，手机的设备 cookie 被剥掉。
  assert.equal(headers.cookie, 'dsh-auth-x=upstream')
  assert.equal(headers.authorization, undefined)
  // 泄露面相关的头被剥掉。
  assert.equal(headers['sec-fetch-site'], undefined)
  assert.equal(headers['x-forwarded-for'], undefined)
  // 普通头保留。
  assert.equal(headers['user-agent'], 'phone')
  // 上游是 loopback 明文，逐跳连接语义显式关掉。
  assert.equal(headers.connection, 'close')
})

test('buildUpstreamHeaders：有 body 时补 content-length', () => {
  const body = Buffer.from('hello', 'utf8')
  const headers = buildUpstreamHeaders(
    { 'content-length': '999' },
    { authority: '127.0.0.1:12345', origin: 'http://127.0.0.1:12345', body },
  )
  assert.equal(headers['content-length'], '5', '必须用真实 body 长度覆盖手机给的')
})

test('buildDownstreamHeaders：绝不把上游 Set-Cookie 交给手机', () => {
  const headers = buildDownstreamHeaders(
    {
      'set-cookie': 'dsh-auth-x=super-secret; HttpOnly',
      'content-type': 'text/html',
      'content-security-policy': "default-src 'self'",
      'strict-transport-security': 'max-age=31536000',
      'x-frame-options': 'SAMEORIGIN',
    },
    { prefix: PREFIX, upstreamOrigin: UPSTREAM },
  )

  // 安全边界：上游凭据绝不能下发。
  assert.equal(headers['set-cookie'], undefined, 'Set-Cookie 必须被剥离')
  // 这些在 /m 前缀下会误伤或被隧道层接管。
  assert.equal(headers['content-security-policy'], undefined)
  assert.equal(headers['strict-transport-security'], undefined)
  assert.equal(headers['x-frame-options'], undefined)
  // 内容类型保留。
  assert.equal(headers['content-type'], 'text/html')
})

test('buildDownstreamHeaders：改写 Location', () => {
  const headers = buildDownstreamHeaders(
    { location: '/login', 'content-length': '0' },
    { prefix: PREFIX, upstreamOrigin: UPSTREAM },
  )
  assert.equal(headers.location, '/m/login')
})

test('buildDownstreamHeaders：数组型头条先拍平再改写', () => {
  const headers = buildDownstreamHeaders(
    { location: ['/x', '/y'] },
    { prefix: PREFIX, upstreamOrigin: UPSTREAM },
  )
  assert.equal(headers.location, '/m/x')
})
