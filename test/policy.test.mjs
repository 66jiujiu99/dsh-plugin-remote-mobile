/**
 * 只读策略 / 永久黑名单（lib/policy/policy.js）。
 *
 * 重点是**失败即拒**：只读设备的未知端点必须 403，而不是透传到上游。
 */

import assert from 'node:assert/strict'
import test from 'node:test'

import { decide, isPermanentDenied } from '../lib/policy/policy.js'

const writer = { id: 'd1', name: '读写设备', readonly: false }
const reader = { id: 'd2', name: '只读设备', readonly: true }

test('未认证/已撤销设备：unauthorized', () => {
  assert.equal(decide({ device: undefined, kind: 'unary', endpoint: 'session/list' }).code, 'rm/unauthorized')
  assert.equal(
    decide({ device: { ...writer, revokedAt: Date.now() }, kind: 'unary', endpoint: 'session/list' }).code,
    'rm/unauthorized',
  )
})

test('永久黑名单：读写设备也拒', () => {
  for (const endpoint of ['terminal/run', 'credentials/read', 'plugin/install', 'plugin-manager/list', 'remote-mobile/status']) {
    const verdict = decide({ device: writer, kind: 'unary', endpoint })
    assert.equal(verdict.ok, false, endpoint)
    assert.equal(verdict.code, 'rm/forbidden', endpoint)
    assert.equal(isPermanentDenied(endpoint), true, endpoint)
  }
  assert.equal(isPermanentDenied('session/list'), false)
})

test('读写设备：白名单之外的普通端点允许', () => {
  assert.deepEqual(decide({ device: writer, kind: 'unary', endpoint: 'session/prompt' }), { ok: true })
  assert.deepEqual(decide({ device: writer, kind: 'file' }), { ok: true })
  assert.deepEqual(decide({ device: writer, kind: 'upload' }), { ok: true })
  assert.deepEqual(decide({ device: writer, kind: 'approval' }), { ok: true })
})

test('只读设备：读取类白名单允许，写操作 403，未知端点 fail-closed', () => {
  for (const endpoint of ['session/list', 'session/page', 'session/projections', 'session/modelCatalog', 'workspace/list', 'workspace/readFile', 'session/attachment']) {
    assert.deepEqual(decide({ device: reader, kind: 'unary', endpoint }), { ok: true }, endpoint)
  }
  for (const endpoint of ['session/prompt', 'session/cancel', 'session/updateQueue', 'session/rename']) {
    const verdict = decide({ device: reader, kind: 'unary', endpoint })
    assert.equal(verdict.ok, false, endpoint)
    assert.equal(verdict.code, 'rm/readonly', endpoint)
  }
  assert.equal(decide({ device: reader, kind: 'unary', endpoint: 'totally/unknown' }).code, 'rm/readonly')
  assert.equal(decide({ device: reader, kind: 'file' }).ok, true)
  assert.equal(decide({ device: reader, kind: 'upload' }).code, 'rm/readonly')
  assert.equal(decide({ device: reader, kind: 'approval' }).code, 'rm/readonly')
})

test('WS 流端点：整站反代所需的流全部放行，unary 端点本地就拒', () => {
  // 这份名单不是「多放几个无所谓」：完整 Web UI 每个流对应一块数据，
  // 缺 `remoteAccess/follow` 会让所有会话掉进「未分组」，缺 `account/watch`
  // 会让账号菜单变空。所以这里逐个钉住，防止回退。
  for (const endpoint of [
    'session/follow',
    'session/control',
    'workspace/follow',
    '$events',
    'account/watch',      // 账号状态
    'remoteAccess/follow', // 工作区归属（会话分组靠它）
    'job/follow',          // 后台任务
    'speech/follow',       // 语音
  ]) {
    assert.deepEqual(decide({ device: writer, kind: 'ws-open', endpoint }), { ok: true }, endpoint)
    assert.deepEqual(decide({ device: reader, kind: 'ws-open', endpoint }), { ok: true }, endpoint)
  }
  for (const endpoint of ['session/list', 'session/prompt']) {
    const verdict = decide({ device: writer, kind: 'ws-open', endpoint })
    assert.equal(verdict.ok, false, endpoint)
    assert.equal(verdict.code, 'rm/forbidden', endpoint)
  }
  // 流通道上也不能开永久黑名单端点。
  assert.equal(decide({ device: writer, kind: 'ws-open', endpoint: 'terminal/run' }).code, 'rm/forbidden')
})

test('空端点名：bad-request', () => {
  assert.equal(decide({ device: writer, kind: 'unary', endpoint: '' }).code, 'rm/bad-request')
})
