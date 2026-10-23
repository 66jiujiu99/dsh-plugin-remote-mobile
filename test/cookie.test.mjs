/**
 * 上游 cookie：名字计算、Set-Cookie 解析、以及**本地假上游**上的完整交换 + 401 重交换。
 *
 * 假上游只做两件事：`GET /?token=` 发 cookie；`POST /api/session/list` 校验 cookie。
 * 这样能覆盖 401 → 重交换 → 重试的真实路径，而不需要起整个 DSH。
 */

import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import http from 'node:http'
import test from 'node:test'

import {
  cookieNameFor,
  createUpstream,
  pickAuthCookie,
  rewriteRequestHeaders,
} from '../lib/net/upstream.js'

/** 静音 logger。 */
const quietLog = () => {}

/**
 * 建一个假上游。
 * @param {object} [options] - 选项。
 * @param {string} [options.authority] - 期望的 Host。
 * @returns {Promise<{ server: http.Server, origin: string, state: object, close: () => Promise<void> }>} 假上游。
 */
async function startFakeUpstream({ authority } = {}) {
  const state = {
    /** @type {Set<string>} 当前有效的 cookie 值。 */
    valid: new Set(),
    exchanges: 0,
    lastHost: '',
    lastOrigin: '',
  }
  let expectedAuthority = authority ?? ''
  const server = http.createServer((req, res) => {
    state.lastHost = String(req.headers.host ?? '')
    state.lastOrigin = String(req.headers.origin ?? '')
    const url = new URL(req.url ?? '/', 'http://fake.invalid')
    if (url.pathname === '/') {
      if (!url.searchParams.has('token')) {
        res.writeHead(401, { 'content-type': 'text/plain' })
        res.end('no token')
        return
      }
      state.exchanges += 1
      const value = `v1.${crypto.randomBytes(8).toString('hex')}.sig`
      state.valid.clear()
      state.valid.add(value)
      const name = cookieNameFor(expectedAuthority)
      res.writeHead(303, {
        location: './',
        'set-cookie': [`${name}=${value}; Path=/; HttpOnly; SameSite=Strict`],
      })
      res.end()
      return
    }
    if (url.pathname === '/api/session/list') {
      const cookie = String(req.headers.cookie ?? '')
      const match = /dsh-auth-[^=]+=(v1[^;]+)/.exec(cookie)
      if (match === null || !state.valid.has(match[1])) {
        res.writeHead(401, { 'content-type': 'application/json' })
        res.end(JSON.stringify({ type: 'server-response', result: { ok: false, error: { code: 'unauthorized' } } }))
        return
      }
      res.writeHead(200, { 'content-type': 'application/json', 'set-cookie': ['boom=1; Path=/'] })
      res.end(JSON.stringify({ type: 'server-response', result: { ok: true, value: { items: [] } } }))
      return
    }
    res.writeHead(404)
    res.end()
  })
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  const address = server.address()
  const port = typeof address === 'object' && address !== null ? address.port : 0
  expectedAuthority = `127.0.0.1:${port}`
  return {
    server,
    origin: `http://127.0.0.1:${port}`,
    state,
    close: () => new Promise((resolve) => server.close(() => resolve(undefined))),
  }
}

test('cookie 名 = dsh-auth- + base64url(sha256(authority))', () => {
  const authority = '127.0.0.1:13291'
  const expected = `dsh-auth-${crypto.createHash('sha256').update(authority).digest('base64url')}`
  assert.equal(cookieNameFor(authority), expected)
  // 43 字符 base64url（32 字节 digest）。
  assert.equal(cookieNameFor(authority).length, 'dsh-auth-'.length + 43)
  // authority 不同 → 名字不同（Host 写错时能立刻发现）。
  assert.notEqual(cookieNameFor('127.0.0.1:13292'), cookieNameFor(authority))
})

test('pickAuthCookie 只挑 dsh-auth-*，忽略其它 Set-Cookie', () => {
  assert.deepEqual(
    pickAuthCookie(['other=1; Path=/', 'dsh-auth-abc=v1.x.y; Path=/; HttpOnly']),
    { name: 'dsh-auth-abc', value: 'v1.x.y' },
  )
  assert.equal(pickAuthCookie(['other=1']), undefined)
  assert.equal(pickAuthCookie(undefined), undefined)
})

test('cookie 交换 + 一元请求：仅凭插件内存里的 cookie 拿到 200', async () => {
  const fake = await startFakeUpstream()
  try {
    const upstream = createUpstream({
      config: {},
      log: quietLog,
      audit: { debug() {}, audit() {} },
      getOrigin: () => fake.origin,
      getAuthenticatedUrl: (url) => `${url}?token=probe-token`,
    })
    assert.equal(await upstream.ensure(), true)
    assert.equal(upstream.cookieOk, true)
    assert.equal(fake.state.exchanges, 1)
    // 交换请求必须带正确的 Host（cookie 的 authority 由它决定）。
    assert.equal(fake.state.lastHost, `127.0.0.1:${new URL(fake.origin).port}`)

    const body = Buffer.from(JSON.stringify({
      type: 'client-request',
      rpcId: 'r1',
      method: 'session/list',
      payload: { args: { _request: {} } },
    }))
    const headers = rewriteRequestHeaders({}, {
      authority: `127.0.0.1:${new URL(fake.origin).port}`,
      origin: fake.origin,
    })
    headers['content-type'] = 'application/json'
    headers['content-length'] = String(body.length)
    const res = await upstream.send({ path: '/api/session/list', method: 'POST', headers, body })
    assert.equal(res.statusCode, 200)
    const text = await new Promise((resolve) => {
      /** @type {Buffer[]} */
      const chunks = []
      res.on('data', (chunk) => chunks.push(chunk))
      res.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')))
    })
    assert.match(text, /"ok":true/)
    // 上游 Set-Cookie 不能出现在我们要回给手机的 header 里（由 rewriteResponseHeaders 保证）。
    assert.deepEqual(res.headers['set-cookie'], ['boom=1; Path=/'])
  } finally {
    await fake.close()
  }
})

test('401 时自动重交换一次并重试（cookie 过期场景）', async () => {
  const fake = await startFakeUpstream()
  try {
    const upstream = createUpstream({
      config: {},
      log: quietLog,
      audit: { debug() {}, audit() {} },
      getOrigin: () => fake.origin,
      getAuthenticatedUrl: (url) => `${url}?token=t`,
    })
    await upstream.ensure()
    assert.equal(fake.state.exchanges, 1)

    // 模拟 cookie 过期：上游清空有效集合。
    fake.state.valid.clear()
    const authority = `127.0.0.1:${new URL(fake.origin).port}`
    const res = await upstream.send({
      path: '/api/session/list',
      method: 'POST',
      headers: {
        host: authority,
        origin: fake.origin,
        'content-type': 'application/json',
        'content-length': '2',
        connection: 'close',
      },
      body: Buffer.from('{}'),
    })
    assert.equal(res.statusCode, 200)
    res.resume()
    // 第一次 401 → 重交换 → 第二次 200。
    assert.equal(fake.state.exchanges, 2)
  } finally {
    await fake.close()
  }
})

test('cookie 交换失败（上游 401）时 cookieOk=false 且不崩', async () => {
  const server = http.createServer((_req, res) => {
    res.writeHead(401)
    res.end('nope')
  })
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  const address = server.address()
  const port = typeof address === 'object' && address !== null ? address.port : 0
  try {
    const upstream = createUpstream({
      config: {},
      log: quietLog,
      audit: { debug() {}, audit() {} },
      getOrigin: () => `http://127.0.0.1:${port}`,
      getAuthenticatedUrl: (url) => `${url}?token=t`,
    })
    assert.equal(await upstream.ensure(), false)
    assert.equal(upstream.cookieOk, false)
    assert.match(upstream.lastError, /cookie/)
  } finally {
    await new Promise((resolve) => server.close(() => resolve(undefined)))
  }
})
