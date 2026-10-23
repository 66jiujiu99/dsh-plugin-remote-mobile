/**
 * 配置解析与 multipart 解析（lib/config.js / lib/net/listener.js 的纯函数）。
 */

import assert from 'node:assert/strict'
import test from 'node:test'

import { ConfigError, resolveConfig, statusForError } from '../lib/config.js'
import { parseMultipart } from '../lib/net/listener.js'

test('默认配置：enabled=false（不绑任何非环回地址），端口与审批策略符合 PLAN §4.5', () => {
  const config = resolveConfig({})
  assert.equal(config.enabled, false)
  assert.equal(config.bindAddress, '0.0.0.0')
  assert.equal(config.port, 17_890)
  assert.deepEqual(config.allowedNetworks, [])
  assert.equal(config.cookieMaxAgeDays, 180)
  assert.equal(config.pairCodeTtlSec, 60)
  assert.equal(config.pairMaxAttempts, 5)
  assert.equal(config.approvalRouting, 'phone-first')
  assert.equal(config.askTimeoutMs, 12_000)
  assert.equal(config.deviceOnlineWindowMs, 45_000)
  assert.equal(config.readonlyDefaults.terminal, true)
  assert.equal(config.audit.enabled, true)
  assert.equal(config.tunnel.provider, 'none')
})

test('未知键被拒绝（拼写错误不能静默忽略）', () => {
  assert.throws(() => resolveConfig({ enabledd: true }), ConfigError)
  assert.throws(() => resolveConfig({ approvalRouting: 'phone-first', readonlyDefault: {} }), ConfigError)
  assert.throws(() => resolveConfig({ tunnel: { provider: 'none', serverAdrr: 'x' } }), ConfigError)
})

test('非法取值被拒绝并点名键', () => {
  assert.throws(() => resolveConfig({ enabled: 'yes' }), /enabled must be a boolean/)
  assert.throws(() => resolveConfig({ port: 70_000 }), /port must be an integer/)
  assert.throws(() => resolveConfig({ approvalRouting: 'phone' }), /approvalRouting must be one of/)
  assert.throws(() => resolveConfig({ tunnel: { provider: 'ngrok' } }), /provider/)
  assert.throws(() => resolveConfig({ bindAddress: '' }), /bindAddress/)
})

test('错误码 → HTTP 状态映射（PROTOCOL §5）', () => {
  assert.equal(statusForError({ code: 'rm/unauthorized' }), 401)
  assert.equal(statusForError({ code: 'rm/forbidden' }), 403)
  assert.equal(statusForError({ code: 'rm/not-found' }), 404)
  assert.equal(statusForError({ code: 'rm/pair-expired' }), 410)
  assert.equal(statusForError({ code: 'rm/pair-locked' }), 429)
  assert.equal(statusForError({ code: 'rm/too-large' }), 413)
  assert.equal(statusForError({ code: 'rm/upstream' }), 502)
  assert.equal(statusForError({ code: 'rm/disabled' }), 503)
  assert.equal(statusForError({ code: 'whatever' }), 500)
})

test('parseMultipart：取出第一个文件与普通字段', () => {
  const boundary = 'X-BOUNDARY-123'
  const body = Buffer.from([
    `--${boundary}`,
    'Content-Disposition: form-data; name="sessionId"',
    '',
    'sess-42',
    `--${boundary}`,
    'Content-Disposition: form-data; name="file"; filename="photo.jpg"',
    'Content-Type: image/jpeg',
    '',
    '\u0001\u0002binary-bytes',
    `--${boundary}--`,
    '',
  ].join('\r\n'), 'utf8')
  const parsed = parseMultipart(body, `multipart/form-data; boundary=${boundary}`)
  assert.equal(parsed.fields.sessionId, 'sess-42')
  assert.notEqual(parsed.file, undefined)
  assert.equal(parsed.file.name, 'photo.jpg')
  assert.equal(parsed.file.type, 'image/jpeg')
  assert.deepEqual(parsed.file.bytes, Buffer.from('\u0001\u0002binary-bytes', 'utf8'))
})

test('parseMultipart：缺 boundary 时报 bad-request', () => {
  assert.throws(() => parseMultipart(Buffer.from('x'), 'multipart/form-data'), /boundary/)
})

test('fileAccess：默认 workspace + 空 roots/extraDeny（fail-closed 起点）', () => {
  const config = resolveConfig({})
  assert.deepEqual(config.fileAccess, { mode: 'workspace', roots: [], extraDeny: [] })
})

test('fileAccess：非法 mode 落地 workspace 并 warn（不阻塞插件加载）', () => {
  const warnings = []
  const config = resolveConfig({ fileAccess: { mode: 'wide-open' } }, { warn: (message) => warnings.push(message) })
  assert.equal(config.fileAccess.mode, 'workspace')
  assert.equal(warnings.length, 1)
  assert.match(warnings[0], /fileAccess\.mode/)

  // `any` 是合法逃生舱。
  assert.equal(resolveConfig({ fileAccess: { mode: 'any' } }).fileAccess.mode, 'any')
})

test('fileAccess：roots 必须是绝对路径、extraDeny 必须是非空字符串', () => {
  const abs = process.cwd()
  assert.deepEqual(resolveConfig({ fileAccess: { roots: [abs] } }).fileAccess.roots, [abs])
  assert.throws(() => resolveConfig({ fileAccess: { roots: ['relative/dir'] } }), /absolute path/)
  assert.throws(() => resolveConfig({ fileAccess: { roots: [42] } }), /non-empty absolute path/)
  assert.throws(() => resolveConfig({ fileAccess: { extraDeny: [''] } }), /non-empty string/)
  assert.throws(() => resolveConfig({ fileAccess: { nope: true } }), /unknown key/)
})
