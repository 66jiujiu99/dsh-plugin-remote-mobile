/**
 * workspace 根目录发现（`/m/api/file` 的 allowlist 来源）。
 *
 * 顺序：
 *   1. 配置 `fileAccess.roots`（非空时直接用，管理员显式声明最可靠）；
 *   2. 自动：带插件内存里的上游 cookie 调 `POST /api/workspace/list`，**容忍多种
 *      响应形状**（`{roots:[{path}]}`、`{workspaces:[{path|root|rootPath}]}`、
 *      `{data|items:[…]}`、以及包在 `{result:…}` 里的变体），缓存 30 秒；
 *   3. 都拿不到 → 空数组。调用方必须 fail-closed（**不许**回退 `os.homedir()`
 *      或 `process.cwd()`，那等于把整机交给手机）。
 *
 * @module dsh-plugin-remote-mobile/net/workspace-roots
 */

import path from 'node:path'

/** 探测结果的缓存时长。 */
const CACHE_MS = 30_000

/** 一个 workspace 根最多接受的字符长度（防御畸形响应）。 */
const MAX_ROOT_LENGTH = 4096

/** 可能的数组字段名（递归时命中即收集）。 */
const ROOT_ARRAY_KEYS = Object.freeze(['roots', 'workspaces', 'workspaceRoots', 'items', 'data', 'result'])

/** 数组元素里可能是根路径的字段名。 */
const ROOT_VALUE_KEYS = Object.freeze(['path', 'root', 'rootPath', 'dir', 'cwd', 'absPath', 'directory', 'uri'])

/**
 * 是否是普通对象。
 * @param {unknown} value - 任意值。
 * @returns {boolean} 结论。
 */
function isRecord(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

/**
 * 从任意形状里尽力收集绝对路径。
 * @param {unknown} value - 响应 JSON 的某个节点。
 * @param {number} depth - 当前深度。
 * @returns {string[]} 绝对路径候选。
 */
function collectRoots(value, depth = 0) {
  if (depth > 5 || value === undefined || value === null) return []
  if (Array.isArray(value)) {
    /** @type {string[]} */
    const out = []
    for (const item of value) {
      if (typeof item === 'string') {
        if (path.isAbsolute(item.trim())) out.push(item.trim())
        continue
      }
      if (isRecord(item)) {
        for (const key of ROOT_VALUE_KEYS) {
          const candidate = item[key]
          if (typeof candidate === 'string' && candidate.trim() !== '' && path.isAbsolute(candidate.trim())) {
            out.push(candidate.trim())
            break
          }
        }
      }
    }
    return out
  }
  if (!isRecord(value)) return []
  /** @type {string[]} */
  const out = []
  for (const key of ROOT_ARRAY_KEYS) {
    if (key in value) out.push(...collectRoots(value[key], depth + 1))
  }
  return out
}

/**
 * 去重 + 清理。
 * @param {string[]} roots - 候选。
 * @returns {string[]} 干净的根列表。
 */
function normalizeRoots(roots) {
  /** @type {string[]} */
  const out = []
  for (const root of roots) {
    if (typeof root !== 'string') continue
    const value = root.trim()
    if (value === '' || value.length > MAX_ROOT_LENGTH) continue
    if (!path.isAbsolute(value)) continue
    const resolved = path.resolve(value)
    if (!out.includes(resolved)) out.push(resolved)
  }
  return out
}

/**
 * 建根目录提供者。
 *
 * @param {object} options - 依赖。
 * @param {import('../config.js').ResolvedConfig} options.config - 已解析配置。
 * @param {ReturnType<import('./upstream.js').createUpstream>} options.upstream - 上游适配器（带 cookie）。
 * @param {(level: 'debug'|'info'|'warn'|'error', message: string) => void} options.log - 日志出口。
 * @param {ReturnType<import('../audit.js').createAudit>} options.audit - 审计器（只写 debug）。
 * @returns {{ get: () => Promise<{ roots: string[], source: string, error?: string }>, invalidate: () => void }} API。
 */
export function createWorkspaceRoots({ config, upstream, log, audit }) {
  /** @type {{ at: number, roots: string[], source: string, error?: string }|undefined} */
  let cache
  /** 探测进行中的 Promise（并发文件请求只探一次）。 */
  let inflight

  /**
   * 调上游 `workspace/list` 发现根目录。
   * @returns {Promise<{ roots: string[], source: string, error?: string }>} 结果。
   */
  async function probe() {
    const configured = Array.isArray(config.fileAccess?.roots) ? normalizeRoots(config.fileAccess.roots) : []
    if (configured.length > 0) {
      return { roots: configured, source: 'config' }
    }
    const envelope = {
      type: 'client-request',
      rpcId: `rm-roots-${Date.now()}`,
      method: 'workspace/list',
      payload: { args: {} },
    }
    const body = Buffer.from(JSON.stringify(envelope), 'utf8')
    /** @type {import('node:http').IncomingMessage} */
    let response
    try {
      response = await upstream.send({
        path: '/api/workspace/list',
        method: 'POST',
        headers: {
          host: upstream.authority(),
          origin: upstream.origin(),
          'content-type': 'application/json',
          'content-length': String(body.length),
          connection: 'close',
        },
        body,
        // 401 由 upstream.send 内部重交换一次；这里不再放大重试。
      })
    } catch (error) {
      return { roots: [], source: 'none', error: String(error?.message ?? error) }
    }
    const status = response.statusCode ?? 0
    if (status < 200 || status >= 300) {
      response.resume()
      return { roots: [], source: 'none', error: `workspace/list HTTP ${status}` }
    }
    /** @type {Buffer[]} */
    const chunks = []
    try {
      for await (const chunk of response) chunks.push(Buffer.from(chunk))
    } catch (error) {
      return { roots: [], source: 'none', error: String(error?.message ?? error) }
    }
    let parsed
    try {
      parsed = JSON.parse(Buffer.concat(chunks).toString('utf8'))
    } catch {
      return { roots: [], source: 'none', error: 'workspace/list 返回的不是 JSON' }
    }
    const roots = normalizeRoots(collectRoots(parsed))
    if (roots.length === 0) {
      return { roots: [], source: 'upstream', error: 'workspace/list 响应里没有可识别的根路径' }
    }
    audit.debug('workspace-roots', { source: 'upstream', roots })
    return { roots, source: 'upstream' }
  }

  /**
   * 取当前 workspace 根（30s 缓存；失败也缓存，避免打爆上游）。
   * @returns {Promise<{ roots: string[], source: string, error?: string }>} 结果。
   */
  async function get() {
    if (cache !== undefined && Date.now() - cache.at < CACHE_MS) {
      return { roots: cache.roots, source: cache.source, ...(cache.error === undefined ? {} : { error: cache.error }) }
    }
    if (inflight !== undefined) return inflight
    inflight = probe()
      .then((result) => {
        cache = { at: Date.now(), roots: result.roots, source: result.source, ...(result.error === undefined ? {} : { error: result.error }) }
        if (result.roots.length === 0) {
          // 一条 warn 足够：文件请求会持续回 403 no-root，不是致命错误。
          log('warn', `remote-mobile: 没拿到工作区根目录（${result.error ?? '未知原因'}）——/m/api/file 将 fail-closed 回 403`)
        }
        return result
      })
      .finally(() => {
        inflight = undefined
      })
    return inflight
  }

  /**
   * 丢弃缓存（面板改配置 / 测试用）。
   * @returns {void}
   */
  function invalidate() {
    cache = undefined
  }

  return { get, invalidate }
}
