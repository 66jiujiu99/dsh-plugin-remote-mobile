/**
 * 验证「进程所有权」：父进程被强杀后，隧道必须跟着消失。
 *
 * 这是安全要求，不是优化：DSH 崩了/被任务管理器结束，如果 cloudflared
 * 还挂在公网上，就等于留下一个没人管、但仍在暴露 /m 的入口。
 *
 * 做法：起一个中间人进程，它创建 tunnel；我们 SIGKILL 中间人，
 * 然后检查 cloudflared 是否还在。
 */

import { spawn } from 'node:child_process'
import http from 'node:http'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const here = path.dirname(fileURLToPath(import.meta.url))
const CLOUDFLARED = 'C:/Data/deepseek/tools/cloudflared.exe'

/** 中间人：起本地服务 + 隧道，打印域名后保持存活。 */
const MIDDLE_SOURCE = `
import http from 'node:http'
import { createTunnel } from ${JSON.stringify(`file:///${path.join(here, '..', 'lib', 'net', 'tunnel.js').replace(/\\/g, '/')}`)}

const server = http.createServer((req, res) => { res.end('ok') })
server.listen(0, '127.0.0.1', async () => {
  const port = server.address().port
  const tunnel = createTunnel({
    config: { tunnel: { provider: 'quick', binaryPath: ${JSON.stringify(CLOUDFLARED)}, idleTimeoutSec: 0, startTimeoutSec: 120 } },
    log: () => {},
    audit: { audit() {}, debug() {} },
    getPort: () => port,
  })
  try {
    const { url } = await tunnel.start()
    process.stdout.write('URL=' + url + '\\nREADY\\n')
  } catch (error) {
    process.stdout.write('ERR=' + String(error && error.message) + '\\n')
    process.exit(1)
  }
  // 保持存活，等被强杀。
  setInterval(() => {}, 1000)
})
`

/**
 * 列出所有 cloudflared 进程的 PID。
 * @returns {string[]} PID 列表。
 */
async function listCloudflared() {
  const { execFileSync } = await import('node:child_process')
  try {
    const out = execFileSync('tasklist', ['/FI', 'IMAGENAME eq cloudflared.exe', '/FO', 'CSV', '/NH'], { encoding: 'utf8' })
    return out
      .split(/\r?\n/)
      .map((line) => /^"cloudflared\.exe","(\d+)"/.exec(line)?.[1])
      .filter((pid) => pid !== undefined)
  } catch {
    return []
  }
}

async function main() {
  const before = await listCloudflared()
  console.log(`启动前 cloudflared 进程数：${before.length}`)

  const middle = spawn(process.execPath, ['-e', MIDDLE_SOURCE], {
    stdio: ['ignore', 'pipe', 'pipe'],
    env: { ...process.env, ELECTRON_RUN_AS_NODE: '1' },
  })

  let url = ''
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('中间人超时未就绪')), 150_000)
    middle.stdout.setEncoding('utf8')
    middle.stdout.on('data', (chunk) => {
      const match = /URL=(\S+)/.exec(chunk)
      if (match !== null && url === '') {
        url = match[1]
        console.log(`隧道已起：${url}`)
      }
      if (chunk.includes('READY')) {
        clearTimeout(timer)
        resolve()
      }
    })
    middle.stderr.setEncoding('utf8')
    middle.stderr.on('data', (chunk) => {
      const text = String(chunk).trim()
      if (text !== '') console.log(`  [middle:stderr] ${text.slice(0, 200)}`)
    })
    middle.on('exit', (code) => {
      clearTimeout(timer)
      reject(new Error(`中间人提前退出（code ${code}）`))
    })
  })

  const during = await listCloudflared()
  console.log(`运行中 cloudflared 进程数：${during.length}（应比启动前多 1）`)
  const startedExtra = during.length - before.length
  const okStarted = startedExtra >= 1

  // **强杀**中间人（模拟 DSH 崩溃 / 任务管理器结束进程）。注意不是 SIGTERM，
  // 因为我们就是要验证"连清理代码都没机会跑"的情况。
  console.log('强杀中间人进程 ...')
  middle.kill('SIGKILL')

  // 给 supervisor 反应时间（它靠 stdin EOF 感知，通常 < 2s）。
  await new Promise((resolve) => setTimeout(resolve, 8000))

  const after = await listCloudflared()
  console.log(`静置 8 秒后 cloudflared 进程数：${after.length}`)
  const leaked = after.filter((pid) => !before.includes(pid))
  const okCleaned = leaked.length === 0

  console.log('')
  console.log(`${okStarted ? 'PASS' : 'FAIL'}  中间人拉起了 cloudflared（+${startedExtra}）`)
  console.log(`${okCleaned ? 'PASS' : 'FAIL'}  强杀父进程后没有孤儿 cloudflared（泄漏 ${leaked.length} 个：${leaked.join(',') || '无'}）`)

  // 收尾：万一泄漏了，清理干净，别把测试痕迹留在这台机器上。
  if (!okCleaned) {
    const { execFileSync } = await import('node:child_process')
    for (const pid of leaked) {
      try {
        execFileSync('taskkill', ['/F', '/PID', pid])
      } catch {
        // 已经没了。
      }
    }
    console.log('已清理泄漏进程。')
  }

  if (url !== '') console.log(`（本次测试域名：${url}，隧道已随父进程关闭）`)
  process.exit(okStarted && okCleaned ? 0 : 1)
}

main().catch((error) => {
  console.error('探针异常：', error)
  process.exit(1)
})
