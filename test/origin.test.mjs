/**
 * `isSameAuthorityOrigin` 单测：Origin/Host 同源判定。
 *
 * 这个函数是**安全边界**的一部分（挡跨站请求），同时也是**功能正确性**的关键：
 * 判太严 → 隧道下全程报"不同源"，配对都提交不了（真机上就这么卡住的）；
 * 判太松 → 跨站请求能带过来，安全边界就破了。
 *
 * 所以两个方向都要钉住。
 */

import assert from 'node:assert/strict'
import test from 'node:test'

import { isSameAuthorityOrigin } from '../lib/net/lan.js'

test('局域网 http：带端口的 Host 与 Origin 一致 → 同源', () => {
  assert.equal(isSameAuthorityOrigin('http://192.168.1.5:17890', '192.168.1.5:17890'), true)
  assert.equal(isSameAuthorityOrigin('http://127.0.0.1:17890', '127.0.0.1:17890'), true)
})

test('局域网 http：端口不一致 → 跨源', () => {
  assert.equal(isSameAuthorityOrigin('http://192.168.1.5:9999', '192.168.1.5:17890'), false)
})

test('隧道 https：无端口 Host（Cloudflare → 源站）→ 必须同源', () => {
  // 这是真机上暴露的 bug：原来只要协议是 https 就直接返回 false，
  // 导致隧道下每个带 Origin 的请求都被判跨源，配对提交不了。
  const host = 'jacksonville-enhanced-richardson-jackie.trycloudflare.com'
  assert.equal(isSameAuthorityOrigin(`https://${host}`, host), true)
  // 显式 :443 也应同源。
  assert.equal(isSameAuthorityOrigin(`https://${host}:443`, host), true)
})

test('隧道：Host 与 Origin 的域名不同 → 跨源', () => {
  assert.equal(
    isSameAuthorityOrigin('https://evil.example.com', 'mine.trycloudflare.com'),
    false,
  )
})

test('http 无端口 Host：Origin 带默认端口 80 视为同源', () => {
  assert.equal(isSameAuthorityOrigin('http://example.com', 'example.com'), true)
  assert.equal(isSameAuthorityOrigin('http://example.com:80', 'example.com'), true)
  // 但 8080 这种非默认端口不该被当成无端口 Host 的匹配。
  assert.equal(isSameAuthorityOrigin('http://example.com:8080', 'example.com'), false)
})

test('非 http(s) 协议一律拒', () => {
  assert.equal(isSameAuthorityOrigin('file://example.com', 'example.com'), false)
  assert.equal(isSameAuthorityOrigin('ftp://example.com', 'example.com'), false)
})

test('畸形输入不抛异常，一律判跨源（fail-closed）', () => {
  assert.equal(isSameAuthorityOrigin('', 'host'), false)
  assert.equal(isSameAuthorityOrigin('not a url', 'host'), false)
  assert.equal(isSameAuthorityOrigin('http://x', ''), false)
  assert.equal(isSameAuthorityOrigin('http://x', 'bad host header with spaces'), false)
})

test('大小写不敏感（域名本就大小写不敏感）', () => {
  assert.equal(isSameAuthorityOrigin('http://EXAMPLE.COM:17890', 'example.com:17890'), true)
  assert.equal(isSameAuthorityOrigin('https://Mine.TryCloudflare.COM', 'mine.trycloudflare.com'), true)
})
