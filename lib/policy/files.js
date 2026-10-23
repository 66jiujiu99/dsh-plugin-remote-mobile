/**
 * `/m/api/file` 的路径作用域判定（纯逻辑 + 注入 `realpath`，可单测）。
 *
 * 背景：上游 `GET /api/file?path=<绝对路径>` **不做目录包含限制**（DSH 文档原话：
 * "Neither directory containment nor MIME categories restrict access"），所以
 * 「手机能下什么」必须由插件自己把关。原来的实现只按 4 个文件名片段过滤，
 * `C:\Users\<user>\.ssh\id_rsa`、`~/.dsh/sessions/**` 这类都能下 —— 等于把整机
 * 可读文件交给已配对设备。
 *
 * 现在的规则（顺序即优先级）：
 *
 *   1. 相对路径 / 空                → `relative`
 *   2. UNC（`\\server\share` `//server/share`）→ `unc`
 *   3. 任何 `..` 片段               → `traversal`
 *   4. 命中敏感目录/文件/扩展名      → `sensitive`
 *   5. `mode:'any'`（逃生舱）        → 放行（第 4 步仍然生效）
 *   6. 没有 workspace 根            → `no-root`（fail-closed，绝不回退 homedir/cwd）
 *   7. 真实路径不在任何根内          → `outside`
 *
 * `realpath` 用来防 symlink/junction 逃逸；`ENOENT`（文件不存在）退回字面路径，
 * 交给上游自己 404。
 *
 * @module dsh-plugin-remote-mobile/policy/files
 */

import { realpath as fsRealpath } from 'node:fs/promises'
import path from 'node:path'

/** 敏感目录名（任一路径段命中即拒；大小写不敏感）。 */
export const SENSITIVE_DIRS = Object.freeze([
  '.ssh',
  '.gnupg',
  '.aws',
  '.azure',
  '.kube',
  '.docker',
  '.dsh',
  '.password-store',
  // 原 listener.js FILE_DENY 里的「凭据库目录名」并进来，全插件只有这一份表。
  'secret-vault',
])

/** 敏感文件名（basename 命中即拒；大小写不敏感）。 */
export const SENSITIVE_FILES = Object.freeze([
  'id_rsa',
  'id_dsa',
  'id_ecdsa',
  'id_ed25519',
  'credentials',
  'credentials.json',
  '.npmrc',
  '.pypirc',
  '.netrc',
  '.git-credentials',
  '.env',
  '.bash_history',
  '.zsh_history',
  'logins.json',
  'key4.db',
  'cookies',
  'login data',
  // 原 FILE_DENY 的「凭据文件名 / 设备表 / 审计日志」。
  '.credentials.yaml',
  'devices.json',
  'audit.jsonl',
])

/** 敏感文件名前缀（`.env.local` 这类逐个列不现实）。 */
export const SENSITIVE_PREFIXES = Object.freeze(['.env.'])

/** 敏感扩展名（小写，含点）。 */
export const SENSITIVE_EXTENSIONS = Object.freeze([
  '.pem',
  '.key',
  '.pfx',
  '.p12',
  '.kdbx',
  '.keystore',
  '.jks',
  '.ovpn',
  '.keychain',
])

/** 每个拒绝原因对应的中文提示（路由直接回给手机）。 */
export const FILE_DENY_MESSAGES = Object.freeze({
  relative: 'path 必须是从盘符/根开始的绝对路径',
  unc: '不支持 UNC 网络路径（\\\\server\\share）',
  traversal: 'path 不能包含 .. 片段',
  sensitive: '这个路径命中了受保护的文件/目录，不允许通过手机下载',
  outside: '这个路径不在 PC 端的工作区根目录内，不允许下载',
  'no-root': '没拿到 PC 端的工作区根目录，请在设置里填 fileAccess.roots',
})

/**
 * 把路径拆成段（兼容 `/` 与 `\`）。
 * @param {string} value - 路径。
 * @returns {string[]} 段。
 */
function segmentsOf(value) {
  return value.split(/[\\/]+/).filter((segment) => segment !== '' && segment !== '.')
}

/**
 * 是否 Windows（决定大小写敏感性与分隔符）。
 * @returns {boolean} 结论。
 */
const IS_WINDOWS = process.platform === 'win32'

/**
 * 统一大小写（仅 Windows）。
 * @param {string} value - 路径。
 * @returns {string} 归一化后的路径。
 */
function foldCase(value) {
  return IS_WINDOWS ? value.toLowerCase() : value
}

/**
 * `child` 是否等于 `root` 或在 `root` 之内（带分隔符比较，`C:\ws` 不匹配 `C:\ws2`）。
 * @param {string} child - 子路径（已 resolve）。
 * @param {string} root - 根路径（已 resolve）。
 * @returns {boolean} 结论。
 */
function isInside(child, root) {
  const a = foldCase(path.resolve(child))
  const b = foldCase(path.resolve(root))
  if (a === b) return true
  const prefix = b.endsWith(path.sep) ? b : `${b}${path.sep}`
  return a.startsWith(prefix)
}

/**
 * 命中敏感项则返回命中项，否则 `undefined`。
 * @param {string} resolvedPath - 已 resolve 的路径。
 * @param {string[]} extraDeny - 追加黑名单（含分隔符 = 全路径子串，否则 = 段/文件名）。
 * @returns {string|undefined} 命中项。
 */
function matchSensitive(resolvedPath, extraDeny) {
  const segments = segmentsOf(resolvedPath)
  const lowered = segments.map((segment) => segment.toLowerCase())
  const base = lowered.length > 0 ? lowered[lowered.length - 1] : ''
  const ext = base.includes('.') ? `.${base.split('.').pop()}` : ''

  for (const dir of SENSITIVE_DIRS) {
    if (lowered.includes(dir)) return dir
  }
  for (const name of SENSITIVE_FILES) {
    if (base === name) return name
  }
  for (const prefix of SENSITIVE_PREFIXES) {
    if (base.startsWith(prefix)) return `${prefix}*`
  }
  for (const suffix of SENSITIVE_EXTENSIONS) {
    if (ext === suffix) return suffix
  }
  const full = foldCase(resolvedPath.replace(/\\/g, '/'))
  for (const raw of extraDeny) {
    if (typeof raw !== 'string') continue
    const entry = raw.trim()
    if (entry === '') continue
    if (entry.includes('/') || entry.includes('\\')) {
      if (full.includes(foldCase(entry.replace(/\\/g, '/')))) return entry
      continue
    }
    const loweredEntry = entry.toLowerCase()
    if (lowered.includes(loweredEntry)) return entry
    if (base === loweredEntry) return entry
    if (loweredEntry.startsWith('.') && ext === loweredEntry) return entry
  }
  return undefined
}

/**
 * 检查一个手机请求的下载路径是否可以放行。
 *
 * @param {string} filePath - 手机给的 `?path=`。
 * @param {object} [options] - 依赖。
 * @param {'workspace'|'any'} [options.mode] - `workspace`（默认）只允许 workspace 根内；`any` 跳过根限制。
 * @param {string[]} [options.roots] - workspace 根（绝对路径）。
 * @param {(target: string) => Promise<string>} [options.realpath] - realpath 实现（测试注入）。
 * @param {string[]} [options.extraDeny] - 追加黑名单。
 * @returns {Promise<{ ok: true, path: string } | { ok: false, reason: string, detail: string }>} 结论。
 */
export async function checkFilePath(filePath, options = {}) {
  const {
    mode = 'workspace',
    roots = [],
    realpath = fsRealpath,
    extraDeny = [],
  } = options

  /**
   * 构造拒绝结果。
   * @param {string} reason - 原因。
   * @param {string} detail - 细节。
   * @returns {{ ok: false, reason: string, detail: string }} 结果。
   */
  const deny = (reason, detail) => ({ ok: false, reason, detail })

  // 1) 空 / 非字符串
  if (typeof filePath !== 'string' || filePath.trim() === '') return deny('relative', '路径为空')
  const raw = filePath.trim()

  // 2) 必须是绝对路径
  if (!path.isAbsolute(raw)) return deny('relative', raw)

  // 3) UNC 网络路径
  if (raw.startsWith('\\\\') || raw.startsWith('//')) return deny('unc', raw)

  // 4) .. 穿越（resolve 前后各查一遍）
  if (segmentsOf(raw).includes('..')) return deny('traversal', raw)
  const resolved = path.resolve(raw)
  if (segmentsOf(resolved).includes('..')) return deny('traversal', resolved)

  // 5) 敏感项（黑名单先于根判定：没根时也报得出「这是敏感文件」）
  const sensitiveHit = matchSensitive(resolved, Array.isArray(extraDeny) ? extraDeny : [])
  if (sensitiveHit !== undefined) return deny('sensitive', sensitiveHit)

  // 6) 逃生舱：只跳过根限制
  if (mode === 'any') return { ok: true, path: resolved }

  // 7) fail-closed：没有根就全部拒绝（绝不回退 homedir/cwd）
  const rootList = (Array.isArray(roots) ? roots : [])
    .filter((root) => typeof root === 'string' && root.trim() !== '' && path.isAbsolute(root.trim()))
    .map((root) => path.resolve(root.trim()))
  if (rootList.length === 0) return deny('no-root', '')

  // 8) 真实路径必须落在某个根内（防 symlink/junction 逃逸）
  /** @type {string} */
  let realFile = resolved
  try {
    realFile = await realpath(resolved)
  } catch {
    // 不存在/无权限：退回字面路径，让上游自己 404。
    realFile = resolved
  }
  for (const root of rootList) {
    /** @type {string} */
    let realRoot = root
    try {
      realRoot = await realpath(root)
    } catch {
      realRoot = root
    }
    if (isInside(realFile, realRoot)) return { ok: true, path: realFile }
  }
  return deny('outside', realFile)
}
