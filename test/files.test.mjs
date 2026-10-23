/**
 * `/m/api/file` 路径作用域单测：`lib/policy/files.js` 的判定顺序与 6 个 reason。
 *
 * 这台机器是 Windows，所以路径用 `C:\…` 写；`realpath` 全部注入假实现，
 * 不碰真实文件系统（唯一例外：lexical 回退用例也注入会抛 ENOENT 的假 realpath）。
 */

import assert from 'node:assert/strict'
import test from 'node:test'

import { checkFilePath } from '../lib/policy/files.js'

/** 假 realpath：默认原样返回。 */
const identityRealpath = async (value) => value

/**
 * 跑一次判定。
 * @param {string} filePath - 待测路径。
 * @param {object} [options] - 覆盖项。
 * @returns {Promise<object>} 结论。
 */
function check(filePath, options = {}) {
  return checkFilePath(filePath, { realpath: identityRealpath, ...options })
}

const WS = 'C:\\ws'

test('空路径 / 相对路径 → relative', async () => {
  assert.deepEqual((await check('')).ok, false)
  assert.equal((await check('')).reason, 'relative')
  assert.equal((await check('docs\\a.txt', { roots: [WS] })).reason, 'relative')
  assert.equal((await check('..\\a.txt', { roots: [WS] })).reason, 'relative')
})

test('UNC 路径 → unc（\\\\server\\share 与 //server/share 都拒）', async () => {
  assert.equal((await check('\\\\server\\share\\a.txt', { roots: [WS] })).reason, 'unc')
  assert.equal((await check('//server/share/a.txt', { roots: [WS] })).reason, 'unc')
})

test('.. 穿越 → traversal（字面路径，未到根判定）', async () => {
  const hit = await check('C:\\ws\\..\\secret.txt', { roots: [WS] })
  assert.equal(hit.ok, false)
  assert.equal(hit.reason, 'traversal')
})

test('根内文件放行', async () => {
  assert.deepEqual(await check('C:\\ws\\proj\\a.txt', { roots: [WS] }), {
    ok: true,
    path: 'C:\\ws\\proj\\a.txt',
  })
})

test('根目录本身放行（边界相等）', async () => {
  assert.equal((await check('C:\\ws', { roots: [WS] })).ok, true)
})

test('C:\\ws2 不匹配根 C:\\ws（带分隔符比较）', async () => {
  const hit = await check('C:\\ws2\\a.txt', { roots: [WS] })
  assert.equal(hit.ok, false)
  assert.equal(hit.reason, 'outside')
})

test('Windows 大小写不敏感', async () => {
  assert.equal((await check('c:\\WS\\Proj\\A.TXT', { roots: ['C:\\ws'] })).ok, true)
})

test('realpath 逃逸（junction/symlink 指向根外）→ outside', async () => {
  const fakeRealpath = async (value) => (value === 'C:\\ws\\link\\secret.txt' ? 'C:\\Windows\\secret.txt' : value)
  const hit = await check('C:\\ws\\link\\secret.txt', { roots: [WS], realpath: fakeRealpath })
  assert.equal(hit.ok, false)
  assert.equal(hit.reason, 'outside')
})

test('文件不存在（realpath ENOENT）时退回字面路径判断', async () => {
  const fakeRealpath = async () => {
    const error = new Error('ENOENT')
    error.code = 'ENOENT'
    throw error
  }
  assert.equal((await check('C:\\ws\\ghost.txt', { roots: [WS], realpath: fakeRealpath })).ok, true)
})

test('敏感目录：.ssh / .gnupg / .aws / .dsh 都拒（即使根内）', async () => {
  for (const home of ['C:\\ws\\.ssh', 'C:\\ws\\.gnupg', 'C:\\ws\\.aws', 'C:\\ws\\.dsh']) {
    const hit = await check(`${home}\\x.txt`, { roots: [WS] })
    assert.equal(hit.ok, false, home)
    assert.equal(hit.reason, 'sensitive', home)
  }
})

test('~/.ssh/id_rsa → sensitive（命中 .ssh 目录段）', async () => {
  const hit = await check('C:\\Users\\jijiu\\.ssh\\id_rsa', { roots: ['C:\\Users\\jijiu'] })
  assert.equal(hit.reason, 'sensitive')
})

test('~/.dsh/AGENTS.md 与 ~/.dsh/sessions/x.json → sensitive', async () => {
  assert.equal((await check('C:\\Users\\jijiu\\.dsh\\AGENTS.md', { roots: ['C:\\Users\\jijiu'] })).reason, 'sensitive')
  assert.equal((await check('C:\\Users\\jijiu\\.dsh\\sessions\\x.json', { roots: ['C:\\Users\\jijiu'] })).reason, 'sensitive')
})

test('敏感文件名：id_ed25519 / credentials.json / cookies', async () => {
  for (const name of ['id_ed25519', 'credentials.json', 'cookies']) {
    const hit = await check(`C:\\ws\\proj\\${name}`, { roots: [WS] })
    assert.equal(hit.reason, 'sensitive', name)
  }
})

test('.env.local 走前缀规则、x.pem 走扩展名规则', async () => {
  assert.equal((await check('C:\\ws\\.env.local', { roots: [WS] })).reason, 'sensitive')
  assert.equal((await check('C:\\ws\\x.pem', { roots: [WS] })).reason, 'sensitive')
  assert.equal((await check('C:\\ws\\keystore.jks', { roots: [WS] })).reason, 'sensitive')
})

test('extraDeny：段名与路径片段都能追加', async () => {
  assert.equal((await check('C:\\ws\\private-notes\\a.txt', { roots: [WS], extraDeny: ['private-notes'] })).reason, 'sensitive')
  assert.equal((await check('C:\\ws\\secret-folder\\a.txt', { roots: [WS], extraDeny: ['secret-folder'] })).reason, 'sensitive')
})

test('mode:any 跳过根限制，但敏感项仍然拒', async () => {
  assert.equal((await check('C:\\Windows\\win.ini', { mode: 'any', roots: [] })).ok, true)
  const hit = await check('C:\\Users\\x\\.ssh\\id_rsa', { mode: 'any', roots: [] })
  assert.equal(hit.reason, 'sensitive')
})

test('roots 为空 → no-root（fail-closed，不回退 homedir/cwd）', async () => {
  const hit = await check('C:\\ws\\proj\\a.txt', { roots: [] })
  assert.equal(hit.ok, false)
  assert.equal(hit.reason, 'no-root')
})

test('敏感项先于 no-root 报出（能明确说「这是受保护文件」）', async () => {
  const hit = await check('C:\\Users\\jijiu\\.ssh\\id_rsa', { roots: [] })
  assert.equal(hit.reason, 'sensitive')
})

test('多个根：命中任意一个即可', async () => {
  assert.equal((await check('D:\\work\\a.txt', { roots: ['C:\\ws', 'D:\\work'] })).ok, true)
})
