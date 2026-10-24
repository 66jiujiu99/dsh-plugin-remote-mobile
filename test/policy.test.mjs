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

test('WS 端点：黑名单之外的 open 一律放行（交给上游判定是不是流）', () => {
  // 历史上这里是"流端点白名单"，结果一次次漏：remoteAccess/follow（会话掉进
  // 未分组）、workspaceFiles/changes（文件面板不刷新）、job/list（官方插件状态
  // 不同步）。DSH 有 144 个端点，跟不完。现在改成：只守永久黑名单，
  // 其余交给上游——上游对不合法的 open 会回错误帧，比静默不更新好得多。
  for (const endpoint of [
    'session/follow',
    'session/control',
    'workspace/follow',
    '$events',
    'account/watch',            // 账号状态
    'account/watchExpiry',
    'remoteAccess/follow',      // 工作区归属（会话分组靠它）
    'job/follow',               // 后台任务
    'job/list',                 // 官方插件状态（真机上暴露的第三个遗漏）
    'speech/follow',            // 语音
    'workspaceFiles/changes',   // 文件变更订阅
    'productAnalytics/watchPolicy',
    'userQuestions/attachWait',
    // 即使上游会拒，也由上游来拒，而不是我们猜。
    'session/list',
    'session/prompt',
  ]) {
    assert.deepEqual(decide({ device: writer, kind: 'ws-open', endpoint }), { ok: true }, endpoint)
    assert.deepEqual(decide({ device: reader, kind: 'ws-open', endpoint }), { ok: true }, endpoint)
  }
  // 但永久黑名单仍然在本地就拒——这些等于系统权限，不能交给上游去冒风险。
  for (const endpoint of ['terminal/run', 'terminal/attach', 'credentials/set', 'pluginManager/listPlugins', 'settings/get']) {
    const verdict = decide({ device: writer, kind: 'ws-open', endpoint })
    assert.equal(verdict.ok, false, endpoint)
    assert.equal(verdict.code, 'rm/forbidden', endpoint)
  }
})

test('流端点判定：只守永久黑名单，其余放行', async () => {
  const { isStreamEndpoint, looksLikeStream } = await import('../lib/policy/policy.js')

  // looksLikeStream 现在只用于诊断（日志里标"看起来像流"），不参与放行。
  assert.equal(looksLikeStream('workspaceFiles/changes'), true)
  assert.equal(looksLikeStream('job/list'), true)
  assert.equal(looksLikeStream('session/prompt'), false)
  assert.equal(looksLikeStream(''), false)

  // 放行判定：黑名单之外全部放行，包括那些"看起来不像流"的端点
  // （上游会自己拒掉不合法的 open）。
  assert.equal(isStreamEndpoint('workspaceFiles/changes'), true)
  assert.equal(isStreamEndpoint('job/list'), true)
  assert.equal(isStreamEndpoint('someFutureFeature/whatever'), true)
  assert.equal(isStreamEndpoint('session/list'), true)

  // **安全边界不变**：永久黑名单即使命名像流也必须拒。
  assert.equal(isStreamEndpoint('terminal/follow'), false)
  assert.equal(isStreamEndpoint('terminal/attach'), false)
  assert.equal(isStreamEndpoint('credentials/watch'), false)
  assert.equal(isStreamEndpoint('plugin/changes'), false)
  assert.equal(isStreamEndpoint('settings/get'), false)
  // 空端点名不放行。
  assert.equal(isStreamEndpoint(''), false)
})

test('空端点名：bad-request', () => {
  assert.equal(decide({ device: writer, kind: 'unary', endpoint: '' }).code, 'rm/bad-request')
})
