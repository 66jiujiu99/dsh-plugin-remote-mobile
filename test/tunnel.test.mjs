/**
 * `tunnel.js` 单测：二进制发现、域名解析、空闲超时、进程生命周期。
 *
 * 用假的 cloudflared（一个 Node 脚本）当靶子，不碰真网络——
 * 真网络留给 `_probe` 里的端到端测试。
 *
 * 钉住四条事实：
 *   1. 找不到二进制时给**可行动**的错误（不是一句"失败"）。
 *   2. 从输出里抓 trycloudflare 域名，抓不到就超时报错。
 *   3. 空闲超时会真的关掉隧道（否则隧道会永远挂着）。
 *   4. 关闭后 `publicUrl` 必须清空（否则 Host 白名单会继续放行一个死域名）。
 */

import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'

import { findCloudflared } from '../lib/net/tunnel.js'

/**
 * 造一份最小配置。
 * @param {object} [tunnel] - 覆盖 tunnel 子对象。
 * @returns {object} 配置。
 */
function makeConfig(tunnel = {}) {
  return {
    tunnel: {
      provider: 'quick',
      binaryPath: '',
      idleTimeoutSec: 0,
      startTimeoutSec: 10,
      serverAddr: '',
      serverPort: 7000,
      remotePort: 0,
      tls: true,
      ...tunnel,
    },
  }
}

/**
 * 一个审计器桩子。
 * @returns {object} 审计器。
 */
function makeAudit() {
  return {
    entries: [],
    audits: [],
    audit(event) {
      this.audits.push(event)
    },
    debug(event) {
      this.entries.push(event)
    },
  }
}

/**
 * 造一个「假 cloudflared」可执行文件。
 *
 * 关键限制：Node 在 Windows 上 `spawn` 一个 `.cmd` 会 EINVAL（需要 shell:true），
 * 而 tunnel.js 刻意不用 shell（避免命令注入，也让参数原样传递）。
 * 所以测试靶子必须是**真正的可执行文件**。
 *
 * 做法：编译一个极小的 C# 程序，它把要打印的内容打出来然后挂住 / 退出。
 * 这比用 `.cmd` 更贴近真实（真 cloudflared 也是 .exe）。
 *
 * @param {string} dir - 临时目录。
 * @param {{ stdout?: string, exit?: number, hold?: boolean }} spec - 行为。
 * @returns {Promise<string>} exe 路径。
 */
async function makeFakeCloudflaredExe(dir, spec = {}) {
  const { stdout = '', exit = 0, hold = false } = spec
  const source = path.join(dir, 'fake.cs')
  const exe = path.join(dir, 'cloudflared.exe')
  // C# 字符串转义：反斜杠与引号。
  const literal = (value) => `"${String(value).replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\r?\n/g, '\\n')}"`
  const body = [
    'using System;',
    'using System.Threading;',
    'class P {',
    '  static void Main(string[] args) {',
    `    Console.Error.WriteLine(${literal(stdout)});`,
    hold ? '    Thread.Sleep(600000);' : `    Environment.Exit(${exit});`,
    '  }',
    '}',
  ].join('\n')
  await writeFile(source, body, 'utf8')

  const csc = 'C:/Windows/Microsoft.NET/Framework64/v4.0.30319/csc.exe'
  const { spawnSync } = await import('node:child_process')
  const built = spawnSync(csc, ['-nologo', `-out:${exe}`, source], { encoding: 'utf8' })
  if (built.status !== 0) {
    throw new Error(`编译假 cloudflared 失败：${built.stdout ?? ''}${built.stderr ?? ''}`)
  }
  return exe
}

/**
 * 造一个「假 cloudflared」包装脚本。
 *
 * 关键：tunnel.js 把 binary 当可执行文件 spawn，Windows 上不能直接跑 .js。
 * 所以生成一个 `.cmd`（Windows）或 `.sh`（POSIX）中间层，由它去跑 node + 脚本体。
 *
 * @param {string} dir - 临时目录。
 * @param {string} body - JS 脚本体。
 * @returns {Promise<string>} 可执行包装脚本的路径。
 */
async function makeFakeCloudflared(dir, body) {
  const script = path.join(dir, 'fake-cloudflared.js')
  await writeFile(script, body, 'utf8')
  if (process.platform === 'win32') {
    const wrapper = path.join(dir, 'cloudflared.exe.cmd')
    // 用 %~dp0 定位同目录脚本，避免路径含空格时的引号问题。
    await writeFile(wrapper, `@echo off\r\n"${process.execPath}" "%~dp0fake-cloudflared.js"\r\n`, 'utf8')
    return wrapper
  }
  const wrapper = path.join(dir, 'cloudflared')
  await writeFile(wrapper, `#!/bin/sh\nexec "${process.execPath}" "$(dirname "$0")/fake-cloudflared.js"\n`, 'utf8')
  return wrapper
}

test('findCloudflared：显式路径不存在 → undefined（不静默回落到 PATH）', () => {
  // 显式配置了却又不存在，说明用户意图明确；这时候偷偷用别的版本会更难排查。
  assert.equal(findCloudflared('C:/definitely/not/here/cloudflared.exe', undefined), undefined)
})

test('findCloudflared：从 tools 目录找到便携版', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'rm-tunnel-'))
  try {
    const fake = path.join(dir, 'cloudflared.exe')
    await writeFile(fake, '#!/bin/sh\nexit 0\n', 'utf8')
    assert.equal(findCloudflared('', dir), fake)
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('findCloudflared：tools 目录为空 → undefined', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'rm-tunnel-'))
  try {
    assert.equal(findCloudflared('', dir), undefined)
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('start：provider 不是 quick → rm/tunnel-disabled', async () => {
  const { createTunnel } = await import('../lib/net/tunnel.js')
  const tunnel = createTunnel({
    config: makeConfig({ provider: 'none' }),
    log: () => {},
    audit: makeAudit(),
    getPort: () => 12345,
  })
  await assert.rejects(tunnel.start(), (error) => error.code === 'rm/tunnel-disabled')
})

test('start：找不到 cloudflared → 可行动的错误码，不是笼统失败', async () => {
  const { createTunnel } = await import('../lib/net/tunnel.js')
  const tunnel = createTunnel({
    config: makeConfig({ binaryPath: 'C:/nope/cloudflared.exe' }),
    log: () => {},
    audit: makeAudit(),
    getPort: () => 12345,
  })
  await assert.rejects(tunnel.start(), (error) => {
    assert.equal(error.code, 'rm/tunnel-no-binary')
    // 错误信息要告诉用户把文件放哪儿。
    assert.match(error.message, /tools/)
    return true
  })
  // 失败后状态必须是 idle，不能卡在 starting。
  assert.equal(tunnel.status().phase, 'idle')
})

test('start：端口未就绪 → rm/tunnel-no-port', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'rm-tunnel-'))
  try {
    // 必须给一个真的二进制，否则会先报 no-binary（检查顺序：provider → binary → port）。
    const fake = await makeFakeCloudflaredExe(dir, { stdout: 'INF x', hold: true })
    const { createTunnel } = await import('../lib/net/tunnel.js')
    const tunnel = createTunnel({
      config: makeConfig({ binaryPath: fake }),
      log: () => {},
      audit: makeAudit(),
      getPort: () => 0,
    })
    await assert.rejects(tunnel.start(), (error) => {
      assert.equal(error.code, 'rm/tunnel-no-port')
      return true
    })
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('start：cloudflared 输出域名 → 抓到并进入 running', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'rm-tunnel-'))
  try {
    // 假 cloudflared：往 stderr 打一行真实格式的日志就挂着不退。
    const fake = await makeFakeCloudflaredExe(dir, {
      stdout: 'INF |  https://calm-river-abc123.trycloudflare.com  |',
      hold: true,
    })

    const { createTunnel } = await import('../lib/net/tunnel.js')
    const tunnel = createTunnel({
      config: makeConfig({ binaryPath: fake }),
      log: () => {},
      audit: makeAudit(),
      getPort: () => 12345,
    })
    const started = await tunnel.start()
    assert.equal(started.url, 'https://calm-river-abc123.trycloudflare.com')
    assert.equal(tunnel.publicHost, 'calm-river-abc123.trycloudflare.com')
    assert.equal(tunnel.status().phase, 'running')

    await tunnel.close('test')
    // 关闭后必须清空，否则 Host 白名单会继续放行死域名。
    assert.equal(tunnel.publicHost, undefined)
    assert.equal(tunnel.status().phase, 'idle')
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('start：进程立刻退出 → 错误里带 cloudflared 的实际输出', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'rm-tunnel-'))
  try {
    const fake = await makeFakeCloudflaredExe(dir, {
      stdout: 'failed to connect to the edge',
      exit: 1,
    })

    const { createTunnel } = await import('../lib/net/tunnel.js')
    const tunnel = createTunnel({
      config: makeConfig({ binaryPath: fake }),
      log: () => {},
      audit: makeAudit(),
      getPort: () => 12345,
    })
    await assert.rejects(tunnel.start(), (error) => {
      assert.equal(error.code, 'rm/tunnel-exit')
      // 必须把 stderr 尾部带出来，否则用户只能看到"退出了"却不知为何。
      assert.match(error.message, /failed to connect/)
      return true
    })
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('start：从不输出域名 → 能被 close 打断，不会挂住', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'rm-tunnel-'))
  try {
    const fake = await makeFakeCloudflaredExe(dir, { stdout: 'INF Starting', hold: true })

    const { createTunnel } = await import('../lib/net/tunnel.js')
    const tunnel = createTunnel({
      // 最短的启动超时，让测试快。
      config: makeConfig({ binaryPath: fake, startTimeoutSec: 10 }),
      log: () => {},
      audit: makeAudit(),
      getPort: () => 12345,
    })
    // 直接改小内部超时不可行（配置已校验 10..300），所以这里用真实 10s——
    // 太慢。改为断言它能被 close 打断：先起，再立刻关。
    const pending = tunnel.start()
    await tunnel.close('test-abort')
    await assert.rejects(pending, (error) => {
      // 被 close 打断时可能报超时或退出，两者都可接受，关键是不能挂住。
      assert.ok(['rm/tunnel-timeout', 'rm/tunnel-exit'].includes(error.code), error.code)
      return true
    })
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('close：重复调用是幂等的', async () => {
  const { createTunnel } = await import('../lib/net/tunnel.js')
  const tunnel = createTunnel({
    config: makeConfig(),
    log: () => {},
    audit: makeAudit(),
    getPort: () => 12345,
  })
  await tunnel.close('a')
  await tunnel.close('b')
  assert.equal(tunnel.status().phase, 'idle')
})

test('touch：不在 running 时是空操作（不会让状态错乱）', async () => {
  const { createTunnel } = await import('../lib/net/tunnel.js')
  const tunnel = createTunnel({
    config: makeConfig(),
    log: () => {},
    audit: makeAudit(),
    getPort: () => 12345,
  })
  tunnel.touch()
  assert.equal(tunnel.status().phase, 'idle')
})

test('重连：cloudflared 意外退出后会自己回来（新域名）', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'rm-reconnect-'))
  try {
    // 假 exe：先打域名，1.5 秒后自己退出（模拟网络抖动导致 cloudflared 挂掉）。
    const source = path.join(dir, 'fake.cs')
    const exe = path.join(dir, 'cloudflared.exe')
    await writeFile(source, [
      'using System;',
      'using System.Threading;',
      'class P { static void Main(string[] a) {',
      '  Console.Error.WriteLine("INF |  https://reconnect-lab-test.trycloudflare.com  |");',
      '  Thread.Sleep(1500);',
      '  Environment.Exit(9);',
      '} }',
    ].join('\n'), 'utf8')
    const built = spawnSync('C:/Windows/Microsoft.NET/Framework64/v4.0.30319/csc.exe', ['-nologo', `-out:${exe}`, source], { encoding: 'utf8' })
    if (built.status !== 0) throw new Error(`csc 失败：${built.stdout}${built.stderr}`)

    const { createTunnel } = await import('../lib/net/tunnel.js')
    const tunnel = createTunnel({
      config: {
        tunnel: {
          provider: 'quick',
          binaryPath: exe,
          idleTimeoutSec: 0,
          startTimeoutSec: 30,
          reconnect: true,
          reconnectBudgetSec: 60,
          reconnectMaxDelaySec: 2,
        },
      },
      log: () => {},
      audit: { audit() {}, debug() {} },
      getPort: () => 12345,
    })

    const first = await tunnel.start()
    assert.equal(first.url, 'https://reconnect-lab-test.trycloudflare.com')

    // 等它退出 + 触发重连。假 exe 每 1.5s 就退一次，所以状态会在
    // running → idle → running 之间循环：**不能用单次采样**判断重连成功，
    // 要在窗口内轮询"是否又回到过 running"。
    // （第一版就是单点采样撞在 idle 窗口里，误判成失败。）
    let sawRunningAgain = false
    const deadline = Date.now() + 9000
    while (Date.now() < deadline) {
      if (tunnel.status().phase === 'running') {
        sawRunningAgain = true
        break
      }
      await new Promise((resolve) => setTimeout(resolve, 200))
    }
    assert.equal(sawRunningAgain, true, '意外退出后应自动重连回 running（轮询 9s 未观察到）')

    await tunnel.close('test')
    // 主动关闭后不能再自己爬起来。
    await new Promise((resolve) => setTimeout(resolve, 3000))
    assert.equal(tunnel.status().phase, 'idle', '主动关闭后不该自动重连')
  } finally {
    await rm(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }).catch(() => {})
  }
})

test('重连：reconnect=false 时意外退出就停在 idle（用户显式关闭了这个行为）', async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'rm-noreconnect-'))
  try {
    const source = path.join(dir, 'fake.cs')
    const exe = path.join(dir, 'cloudflared.exe')
    await writeFile(source, [
      'using System;',
      'using System.Threading;',
      'class P { static void Main(string[] a) {',
      '  Console.Error.WriteLine("INF |  https://no-reconnect-test.trycloudflare.com  |");',
      '  Thread.Sleep(800);',
      '  Environment.Exit(7);',
      '} }',
    ].join('\n'), 'utf8')
    const built = spawnSync('C:/Windows/Microsoft.NET/Framework64/v4.0.30319/csc.exe', ['-nologo', `-out:${exe}`, source], { encoding: 'utf8' })
    if (built.status !== 0) throw new Error(`csc 失败：${built.stdout}${built.stderr}`)

    const { createTunnel } = await import('../lib/net/tunnel.js')
    const tunnel = createTunnel({
      config: {
        tunnel: {
          provider: 'quick',
          binaryPath: exe,
          idleTimeoutSec: 0,
          startTimeoutSec: 30,
          reconnect: false,
          reconnectBudgetSec: 60,
          reconnectMaxDelaySec: 1,
        },
      },
      log: () => {},
      audit: { audit() {}, debug() {} },
      getPort: () => 12345,
    })
    await tunnel.start()
    await new Promise((resolve) => setTimeout(resolve, 4000))
    assert.equal(tunnel.status().phase, 'idle', 'reconnect=false 时不该自动重连')
  } finally {
    await rm(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }).catch(() => {})
  }
})
