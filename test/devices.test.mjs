/**
 * 设备表往返：secret 哈希、cookie 编解码、在线判定、撤销、只读、持久化。
 *
 * 用临时 `DSH_HOME` 隔离，绝不碰真实 `~/.dsh`。
 */

import assert from 'node:assert/strict'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'

/**
 * 准备隔离环境并加载设备模块（dataDir() 在调用时读 `DSH_HOME`）。
 * @returns {Promise<{ dir: string, createDevices: Function, hashSecret: Function, DEVICE_COOKIE: string }>} 环境。
 */
async function setup() {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'rm-devices-'))
  process.env.DSH_HOME = dir
  const mod = await import('../lib/auth/devices.js')
  return { dir, ...mod }
}

/** 静音依赖。 */
const deps = {
  config: {
    cookieMaxAgeDays: 180,
    deviceOnlineWindowMs: 45_000,
  },
  log: () => {},
  audit: {
    debug() {},
    audit() {},
  },
}

test('建设备 → cookie 认证 → 改名/只读 → 撤销后失效 → 落盘', async () => {
  const { dir, createDevices, hashSecret, DEVICE_COOKIE } = await setup()
  try {
    const devices = createDevices(deps)
    await devices.ready()
    const created = await devices.create({ name: '测试手机', ua: 'iPhone', ip: '192.168.1.9' })
    assert.match(created.device.id, /^[0-9a-f]{16}$/)
    assert.equal(created.device.name, '测试手机')
    assert.equal(created.setCookie.startsWith(`${DEVICE_COOKIE}=`), true)
    assert.match(created.setCookie, /HttpOnly/)
    assert.match(created.setCookie, /SameSite=Lax/)
    assert.match(created.setCookie, /Max-Age=15552000/)

    // cookie 值 `<id>.<secret>`，服务端只存 sha256(secret)。
    const cookieValue = created.setCookie.slice(`${DEVICE_COOKIE}=`.length).split(';', 1)[0]
    assert.equal(cookieValue.split('.')[0], created.device.id)
    const stored = await readFile(path.join(dir, 'remote-mobile', 'devices.json'), 'utf8')
    assert.equal(stored.includes(created.secret), false, '磁盘上不能出现明文 secret')
    assert.equal(stored.includes(hashSecret(created.secret)), true)

    // 认证：有效 cookie。
    const hit = devices.authenticate(`${DEVICE_COOKIE}=${cookieValue}`)
    assert.notEqual(hit, undefined)
    assert.equal(hit.device.id, created.device.id)
    // 认证：坏 secret / 坏 id / 无 cookie。
    assert.equal(devices.authenticate(`${DEVICE_COOKIE}=${created.device.id}.wrong-secret-value`), undefined)
    assert.equal(devices.authenticate(`${DEVICE_COOKIE}=deadbeef.deadbeefdeadbeefdead`), undefined)
    assert.equal(devices.authenticate(undefined), undefined)

    // 改名 + 只读。
    await devices.rename(created.device.id, '客厅 iPad')
    await devices.setReadonly(created.device.id, true)
    const list = devices.list()
    assert.equal(list.length, 1)
    assert.equal(list[0].name, '客厅 iPad')
    assert.equal(list[0].readonly, true)
    assert.equal(list[0].online, true)
    // 只读设备在线但不应算「可审批」：由审批闸门读取 readonly 判断。
    assert.equal(devices.online().some((device) => device.readonly !== true), false)

    // 撤销：cookie 立刻失效。
    await devices.revoke(created.device.id)
    assert.equal(devices.authenticate(`${DEVICE_COOKIE}=${cookieValue}`), undefined)
    assert.equal(devices.list().length, 0)
  } finally {
    delete process.env.DSH_HOME
    await rm(dir, { recursive: true, force: true })
  }
})

test('持久化往返：重新建设备表能读回同一台设备', async () => {
  const { dir, createDevices, DEVICE_COOKIE } = await setup()
  try {
    const first = createDevices(deps)
    await first.ready()
    const created = await first.create({ name: '往返设备', ua: 'Android', ip: '10.0.0.5' })
    const cookieValue = created.setCookie.slice(`${DEVICE_COOKIE}=`.length).split(';', 1)[0]

    // 新实例模拟「Host 重启」。
    const second = createDevices(deps)
    await second.ready()
    const hit = second.authenticate(`${DEVICE_COOKIE}=${cookieValue}`)
    assert.notEqual(hit, undefined)
    assert.equal(hit.device.name, '往返设备')
    assert.equal(hit.device.lastIp, '10.0.0.5')
  } finally {
    delete process.env.DSH_HOME
    await rm(dir, { recursive: true, force: true })
  }
})

test('在线判定：超过窗口即离线；revokeAll 清空全表', async () => {
  const { dir, createDevices } = await setup()
  try {
    const devices = createDevices(deps)
    await devices.ready()
    const created = await devices.create({ name: 'A', ua: '', ip: '' })
    assert.equal(devices.online().length, 1)
    // 手动把 lastSeenAt 拨回窗口之外。
    created.device.lastSeenAt = Date.now() - 60_000
    assert.equal(devices.online().length, 0)
    assert.equal(devices.list()[0].online, false)

    const revoked = await devices.revokeAll()
    assert.equal(revoked, 1)
    assert.equal(devices.count(), 0)
    assert.equal(devices.list().length, 0)
  } finally {
    delete process.env.DSH_HOME
    await rm(dir, { recursive: true, force: true })
  }
})

test('配对码：正确码只能用一次，错误码计数，超限锁定', async () => {
  const { dir, createDevices } = await setup()
  try {
    const { createPairing } = await import('../lib/auth/pairing.js')
    const devices = createDevices(deps)
    await devices.ready()
    const pairing = createPairing({
      config: { pairCodeTtlSec: 60, pairMaxAttempts: 3 },
      devices,
      audit: { debug() {}, audit() {} },
    })

    // 没有码时先建码。
    assert.equal(pairing.current().active, false)
    const { code, expiresAt } = pairing.create()
    assert.match(code, /^\d{6}$/)
    assert.equal(expiresAt > Date.now(), true)
    assert.equal(pairing.current().active, true)

    // 错误码 → pair-invalid，并且计入次数。
    await assert.rejects(
      pairing.attempt({ code: code === '000000' ? '111111' : '000000', ua: '', ip: '10.0.0.9' }),
      (error) => error.code === 'rm/pair-invalid',
    )

    // 正确码 → 拿到 setCookie；复用同一个码 → rm/pair-used（不是 expired）。
    const created = await pairing.attempt({ code, name: '我的手机', ua: 'iPhone', ip: '10.0.0.9' })
    assert.equal(created.device.name, '我的手机')
    assert.match(created.setCookie, /dshm_d=/)
    await assert.rejects(
      pairing.attempt({ code, ua: '', ip: '10.0.0.9' }),
      (error) => error.code === 'rm/pair-used',
    )

    // 新码覆盖旧码后，旧码仍报「已使用」，新码正常可用。
    const fresh = pairing.create(10)
    await assert.rejects(
      pairing.attempt({ code, ua: '', ip: '10.0.0.11' }),
      (error) => error.code === 'rm/pair-used',
    )
    const pairedAgain = await pairing.attempt({ code: fresh.code, ua: '', ip: '10.0.0.11' })
    assert.ok(pairedAgain.device.id.length > 0)

    // 新码连续错 3 次 → locked。
    const second = pairing.create()
    let locked
    for (let attempt = 0; attempt < 4; attempt += 1) {
      const wrong = second.code === '999999' ? '000000' : '999999'
      try {
        await pairing.attempt({ code: wrong, ua: '', ip: '10.0.0.10' })
      } catch (error) {
        locked = error.code
      }
    }
    assert.equal(locked, 'rm/pair-locked')
  } finally {
    delete process.env.DSH_HOME
    await rm(dir, { recursive: true, force: true })
  }
})

test('超过 cookieMaxAgeDays 的设备 cookie 服务端也判过期（不是只靠浏览器 Max-Age）', async () => {
  const { dir, createDevices, hashSecret, DEVICE_COOKIE } = await setup()
  try {
    const { mkdir, writeFile } = await import('node:fs/promises')
    const dataDir = path.join(dir, 'remote-mobile')
    await mkdir(dataDir, { recursive: true })
    const secret = 'e'.repeat(32)
    const now = Date.now()
    await writeFile(
      path.join(dataDir, 'devices.json'),
      `${JSON.stringify({
        v: 1,
        devices: [{
          id: '0123456789abcdef',
          name: '旧手机',
          ua: '',
          createdAt: now - 181 * 86_400_000,
          lastSeenAt: now,
          lastIp: '192.168.1.9',
          readonly: false,
          secretHash: hashSecret(secret),
        }],
      })}\n`,
      { encoding: 'utf8', mode: 0o600 },
    )

    const devices = createDevices(deps)
    await devices.ready()
    // 过期：认证失败（监听器据此回 401），也不计入 actives。
    assert.equal(devices.authenticate(`${DEVICE_COOKIE}=0123456789abcdef.${secret}`), undefined)
    assert.equal(devices.count(), 0)
    assert.equal(devices.list()[0].online, false)
  } finally {
    delete process.env.DSH_HOME
    await rm(dir, { recursive: true, force: true })
  }
})

test('配对码有效期：自定义 ttlSec 真的生效，越界回落默认值', async () => {
  const { dir, createDevices } = await setup()
  try {
    const { createPairing } = await import('../lib/auth/pairing.js')
    const devices = createDevices(deps)
    await devices.ready()
    const pairing = createPairing({
      config: { pairCodeTtlSec: 60, pairMaxAttempts: 3 },
      devices,
      audit: { debug() {}, audit() {} },
    })

    // 缺省 → 配置值。
    const fallback = pairing.create()
    assert.equal(fallback.ttlSec, 60)
    assert.ok(Math.abs(fallback.expiresAt - Date.now() - 60_000) < 1_000)

    // 自定义 → 真的按 10s 算（曾经 routes 校验后丢弃，恒 60s）。
    const short = pairing.create(10)
    assert.equal(short.ttlSec, 10)
    assert.ok(Math.abs(short.expiresAt - Date.now() - 10_000) < 1_000)
    assert.ok(pairing.current().ttlSec <= 10)

    // 越界在 routes 层就有 400；pairing 这层兜底回落默认值，绝不生成超短码。
    assert.equal(pairing.create(5).ttlSec, 60)
    assert.equal(pairing.create(1000).ttlSec, 60)
  } finally {
    delete process.env.DSH_HOME
    await rm(dir, { recursive: true, force: true })
  }
})
