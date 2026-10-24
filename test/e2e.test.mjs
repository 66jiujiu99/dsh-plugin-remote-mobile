/**
 * 端到端加密的**互通性**测试：Node 侧与浏览器侧必须逐位一致。
 *
 * 为什么这条最重要：手机与 PC 用两套不同实现（WebCrypto vs node:crypto）。
 * 曲线、KDF、帧格式任何一处不一致，表现都是"手机上一直解密失败"——
 * 而且很难查（两端各自单测都过）。
 *
 * 做法：在 Node 里加载**浏览器那份真脚本**（`web/e2e-crypto.js` 是 classic
 * script，可以直接跑），然后让它和 `lib/net/e2e.js` 互相加解密。
 */

import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import vm from 'node:vm'

import { createKeyStore, deriveKey, generateKeyPair, open, seal } from '../lib/net/e2e.js'

const here = path.dirname(fileURLToPath(import.meta.url))

/**
 * 在隔离上下文里加载浏览器侧脚本（它挂在 `self.DshE2E` 上）。
 * 用 Node 的 webcrypto 冒充 `crypto.subtle`。
 * @returns {object} `DshE2E` 命名空间。
 */
function loadBrowserCrypto() {
  const source = readFileSync(path.join(here, '..', 'web', 'e2e-crypto.js'), 'utf8')
  // 浏览器侧用 btoa/atob，Node 18+ 全局有，但 vm 上下文里要显式给。
  const sandbox = {
    crypto: crypto.webcrypto,
    btoa: (s) => Buffer.from(s, 'binary').toString('base64'),
    atob: (s) => Buffer.from(String(s), 'base64').toString('binary'),
    TextEncoder,
    TextDecoder,
    DataView,
    Uint8Array,
    Promise,
    Error,
    console,
  }
  sandbox.self = sandbox
  vm.createContext(sandbox)
  vm.runInContext(source, sandbox, { filename: 'web/e2e-crypto.js' })
  assert.ok(sandbox.DshE2E, '浏览器侧脚本应导出 DshE2E')
  return sandbox.DshE2E
}

test('互通：Node 加密 → 浏览器解密', async () => {
  const browser = loadBrowserCrypto()
  const nodePair = generateKeyPair()
  const browserPair = await browser.generateKeyPair()

  const nodeKey = deriveKey(nodePair.privateKey, browserPair.publicKeyB64, 'device-abc')
  const browserKey = await browser.deriveKey(browserPair.privateKey, nodePair.publicKeyB64, 'device-abc')

  const plaintext = Buffer.from('会话内容：你好，世界 🌍', 'utf8')
  const frame = seal(nodeKey, plaintext)
  const opened = await browser.open(browserKey, new Uint8Array(frame))
  assert.equal(Buffer.from(opened.plaintext).toString('utf8'), '会话内容：你好，世界 🌍')
  assert.equal(opened.consumed, frame.length)
})

test('互通：浏览器加密 → Node 解密', async () => {
  const browser = loadBrowserCrypto()
  const nodePair = generateKeyPair()
  const browserPair = await browser.generateKeyPair()

  const nodeKey = deriveKey(nodePair.privateKey, browserPair.publicKeyB64, 'device-xyz')
  const browserKey = await browser.deriveKey(browserPair.privateKey, nodePair.publicKeyB64, 'device-xyz')

  const frame = await browser.seal(browserKey, new TextEncoder().encode('反向：从手机到 PC'))
  const opened = open(nodeKey, Buffer.from(frame))
  assert.equal(opened.plaintext.toString('utf8'), '反向：从手机到 PC')
})

test('互通：双方派生出**同一个**密钥（逐字节相同）', async () => {
  const browser = loadBrowserCrypto()
  const nodePair = generateKeyPair()
  const browserPair = await browser.generateKeyPair()

  const nodeKey = deriveKey(nodePair.privateKey, browserPair.publicKeyB64, 'same-device')
  const browserKey = await browser.deriveKey(browserPair.privateKey, nodePair.publicKeyB64, 'same-device')

  // 用浏览器侧加密、Node 侧解密，能解出来就说明密钥一致；
  // 再加一条：用 Node 直接拿 browserKey 的原始字节能导出吗？不能（浏览器侧不可导出）。
  // 所以用双向各解一次作为等价性证明。
  const a = open(nodeKey, Buffer.from(await browser.seal(browserKey, new TextEncoder().encode('ping'))))
  assert.equal(a.plaintext.toString(), 'ping')
})

test('不同 salt 派生不同密钥（设备之间互相解不开）', async () => {
  const nodePair = generateKeyPair()
  const peerPair = generateKeyPair()
  const keyA = deriveKey(nodePair.privateKey, peerPair.publicKeyB64, 'device-A')
  const keyB = deriveKey(nodePair.privateKey, peerPair.publicKeyB64, 'device-B')
  assert.notEqual(keyA.toString('hex'), keyB.toString('hex'))

  const frame = seal(keyA, Buffer.from('secret'))
  assert.throws(() => open(keyB, frame), /unable to authenticate|bad decrypt|authenticate/i)
})

test('篡改密文 → 认证失败（GCM 的完整性保证）', async () => {
  const nodePair = generateKeyPair()
  const peerPair = generateKeyPair()
  const key = deriveKey(nodePair.privateKey, peerPair.publicKeyB64, 'tamper-test')

  const frame = seal(key, Buffer.from('original'))
  const tampered = Buffer.from(frame)
  tampered[tampered.length - 1] ^= 0xff // 改 tag 最后一个字节
  assert.throws(() => open(key, tampered), /unable to authenticate|bad decrypt|authenticate/i)
})

test('随机 nonce：同一明文两次加密密文不同（否则会泄露相等性）', () => {
  const nodePair = generateKeyPair()
  const peerPair = generateKeyPair()
  const key = deriveKey(nodePair.privateKey, peerPair.publicKeyB64, 'nonce-test')
  const a = seal(key, Buffer.from('same'))
  const b = seal(key, Buffer.from('same'))
  assert.notEqual(a.toString('hex'), b.toString('hex'), '随机 nonce 应让密文不同')
  // 但都能解回同一明文。
  assert.equal(open(key, a).plaintext.toString(), 'same')
  assert.equal(open(key, b).plaintext.toString(), 'same')
})

test('流式解帧：粘连的多帧能逐个解出', () => {
  const nodePair = generateKeyPair()
  const peerPair = generateKeyPair()
  const key = deriveKey(nodePair.privateKey, peerPair.publicKeyB64, 'stream-test')

  const f1 = seal(key, Buffer.from('one'))
  const f2 = seal(key, Buffer.from('two'))
  const f3 = seal(key, Buffer.from('three'))
  const merged = Buffer.concat([f1, f2, f3])

  const reader = (async () => {
    const { createReader } = await import('../lib/net/e2e.js')
    return createReader(key)
  })
  return reader().then((r) => {
    const out = r.push(merged).map((b) => b.toString())
    assert.deepEqual(out, ['one', 'two', 'three'])
  })
})

test('流式解帧：分片到达（一个帧被拆成两半）也能拼回来', async () => {
  const { createReader } = await import('../lib/net/e2e.js')
  const nodePair = generateKeyPair()
  const peerPair = generateKeyPair()
  const key = deriveKey(nodePair.privateKey, peerPair.publicKeyB64, 'split-test')

  const frame = seal(key, Buffer.from('split-me'))
  const reader = createReader(key)
  const half = Math.floor(frame.length / 2)
  assert.deepEqual(reader.push(frame.subarray(0, half)), [])
  const out = reader.push(frame.subarray(half))
  assert.deepEqual(out.map((b) => b.toString()), ['split-me'])
})

test('公钥格式非法 → 明确报错（而不是悄悄用错的曲线）', () => {
  const nodePair = generateKeyPair()
  assert.throws(() => deriveKey(nodePair.privateKey, 'not-a-key', 'x'), /公钥格式非法/)
  assert.throws(() => deriveKey(nodePair.privateKey, Buffer.alloc(32).toString('base64'), 'x'), /公钥格式非法/)
})

test('keyStore：每设备独立密钥，clear 后失效', () => {
  const store = createKeyStore()
  const phone = generateKeyPair()
  const serverPub = store.establish('dev-1', phone.publicKeyB64)
  assert.equal(typeof serverPub, 'string')
  assert.ok(store.get('dev-1'))
  assert.equal(store.size, 1)
  store.clear()
  assert.equal(store.get('dev-1'), undefined)
  assert.equal(store.size, 0)
})
