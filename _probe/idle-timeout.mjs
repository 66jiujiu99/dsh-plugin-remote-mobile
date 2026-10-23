/**
 * 验证空闲超时：隧道开着但没人用 → 到点自动关闭。
 *
 * 这是相对 magpie 的一个关键改进：它用的是「从启动起算的硬超时」，
 * 用户在用的时候也会被掐断；我们用的是空闲计时，用着就一直给。
 *
 * 用假 cloudflared（真 exe）避免每次都走网络。
 */

import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'

import { createTunnel } from '../lib/net/tunnel.js'

/**
 * 编译假 cloudflared exe。
 * @param {string} dir - 临时目录。
 * @returns {Promise<string>} exe 路径。
 */
async function makeFakeExe(dir) {
  const source = path.join(dir, 'fake.cs')
  const exe = path.join(dir, 'cloudflared.exe')
  await writeFile(source, [
    'using System;',
    'using System.Threading;',
    'class P { static void Main(string[] a) {',
    '  Console.Error.WriteLine("INF |  https://idle-test-abc.trycloudflare.com  |");',
    '  Thread.Sleep(600000);',
    '} }',
  ].join('\n'), 'utf8')
  const built = spawnSync('C:/Windows/Microsoft.NET/Framework64/v4.0.30319/csc.exe', ['-nologo', `-out:${exe}`, source], { encoding: 'utf8' })
  if (built.status !== 0) throw new Error(`csc 失败：${built.stdout}${built.stderr}`)
  return exe
}

test('空闲超时：到点自动关闭隧道', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'rm-idle-'))
  try {
    const fake = await makeFakeExe(dir)
    // 最短可行空闲窗口：配置下限是 0..86400，这里用 1 秒 + 内部 10s 轮询太慢，
    // 所以直接把 idleTimeoutSec 设为 1，靠 tickIdle 的 10s 间隔——
    // 为了不让测试跑 10 秒以上，这里改为断言「touch 会刷新 lastActivityAt」，
    // 超时逻辑本身由 tickIdle 的纯算术保证（见下一条测试）。
    const tunnel = createTunnel({
      config: {
        tunnel: { provider: 'quick', binaryPath: fake, idleTimeoutSec: 1, startTimeoutSec: 30 },
      },
      log: () => {},
      audit: { audit() {}, debug() {} },
      getPort: () => 12345,
    })

    const { url } = await tunnel.start()
    assert.equal(url, 'https://idle-test-abc.trycloudflare.com')
    assert.equal(tunnel.status().phase, 'running')

    // touch 会刷新空闲起点（idleSec 归零）。
    tunnel.touch()
    const statusAfterTouch = tunnel.status()
    assert.equal(statusAfterTouch.phase, 'running')
    assert.ok(typeof statusAfterTouch.idleSec === 'number', 'running 时应给出 idleSec')

    // 等内部 10s 轮询触发一次（idleTimeoutSec=1 早已超过）。
    await new Promise((resolve) => setTimeout(resolve, 12_000))
    assert.equal(tunnel.status().phase, 'idle', '空闲超时后隧道应自动关闭')
    assert.equal(tunnel.publicHost, undefined, '关闭后不该继续放行该域名')

    await tunnel.close('test')
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('空闲超时：持续 touch 能一直保活（不会被误杀）', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'rm-idle-'))
  try {
    const fake = await makeFakeExe(dir)
    const tunnel = createTunnel({
      config: {
        tunnel: { provider: 'quick', binaryPath: fake, idleTimeoutSec: 2, startTimeoutSec: 30 },
      },
      log: () => {},
      audit: { audit() {}, debug() {} },
      getPort: () => 12345,
    })
    await tunnel.start()

    // 持续 14 秒（超过两倍空闲窗口），每 2 秒 touch 一次。
    for (let index = 0; index < 7; index += 1) {
      await new Promise((resolve) => setTimeout(resolve, 2000))
      tunnel.touch()
      assert.equal(tunnel.status().phase, 'running', `第 ${index + 1} 次 touch 后仍应在运行`)
    }

    await tunnel.close('test')
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})
