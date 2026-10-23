/**
 * `/m` 静态资源服务（`web/**` + 包根 `icon.svg` 回退）。
 *
 * 设计（PROTOCOL §1 的静态行）：内存缓存 + `ETag` + 手写 MIME 表，零依赖。
 * 缓存按 `mtimeMs` 失效，所以开发期改文件不用重启 Host；`Cache-Control` 一律
 * `no-cache`（要求浏览器带 `If-None-Match` 复验），这样配对页/调试期不会看到旧壳。
 *
 * 安全：只接受 `[A-Za-z0-9._-]+` 的单段文件名（无子目录、无 `..`、无 URL 解码
 * 后的路径穿越），不存在的名字一律 undefined（路由层回 404）。
 *
 * @module dsh-plugin-remote-mobile/static
 */

import { readFile, stat } from 'node:fs/promises'
import path from 'node:path'

/** 扩展名 → Content-Type。没有表里没有的扩展名一律 `application/octet-stream`。 */
const MIME_TYPES = Object.freeze({
  '.html': 'text/html; charset=utf-8',
  '.htm': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.webmanifest': 'application/manifest+json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.webp': 'image/webp',
  '.gif': 'image/gif',
  '.ico': 'image/x-icon',
  '.woff2': 'font/woff2',
  '.txt': 'text/plain; charset=utf-8',
  '.map': 'application/json; charset=utf-8',
})

/** 合法文件名：单段、只含安全字符。 */
const SAFE_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/

/**
 * 取一个文件名的 MIME。
 * @param {string} name - 文件名。
 * @returns {string} Content-Type。
 */
export function mimeFor(name) {
  const ext = path.extname(name).toLowerCase()
  return MIME_TYPES[ext] ?? 'application/octet-stream'
}

/**
 * 名字是否可安全地映射成 `web/` 下的文件。
 * @param {string} name - 请求里的文件名片段。
 * @returns {boolean} 结论。
 */
export function isSafeName(name) {
  if (typeof name !== 'string' || !SAFE_NAME.test(name)) return false
  // `.` / `..` 已被正则挡掉（首字符必须是字母数字），这里再兜一次。
  return name !== '.' && name !== '..'
}

/**
 * 建一个静态资源服务。
 *
 * @param {object} options - 依赖。
 * @param {string} options.dir - `web/` 目录绝对路径。
 * @param {string} [options.iconFallback] - `/m/icon.svg` 找不到时回退的包根图标。
 * @param {(level: 'debug'|'info'|'warn'|'error', message: string) => void} [options.log] - 日志出口。
 * @returns {{
 *   dir: string,
 *   get: (name: string) => Promise<{ bytes: Buffer, mime: string, etag: string, mtimeMs: number, file: string }|undefined>,
 *   clear: () => void,
 * }} 静态资源服务。
 */
export function createStatic({ dir, iconFallback, log }) {
  /** @type {Map<string, { bytes: Buffer, mime: string, etag: string, mtimeMs: number }>} */
  const cache = new Map()

  /**
   * 找出某个名字对应的磁盘文件（`web/` 优先，`icon.svg` 可回退包根）。
   * @param {string} name - 文件名。
   * @returns {Promise<string|undefined>} 绝对路径。
   */
  async function locate(name) {
    const primary = path.join(dir, name)
    try {
      const info = await stat(primary)
      if (info.isFile()) return primary
    } catch {
      // 落到下面的回退。
    }
    if (name === 'icon.svg' && typeof iconFallback === 'string') {
      try {
        const info = await stat(iconFallback)
        if (info.isFile()) return iconFallback
      } catch {
        // 没有回退图标。
      }
    }
    return undefined
  }

  return {
    dir,

    /**
     * 取一个静态文件（命中缓存时只有一次 `stat`）。
     * @param {string} name - 文件名（已由调用方保证来自路径单段）。
     * @returns {Promise<{ bytes: Buffer, mime: string, etag: string, mtimeMs: number, file: string }|undefined>} 文件内容。
     */
    async get(name) {
      if (!isSafeName(name)) return undefined
      const cached = cache.get(name)
      const file = await locate(name)
      if (file === undefined) {
        cache.delete(name)
        return undefined
      }
      let info
      try {
        info = await stat(file)
      } catch {
        cache.delete(name)
        return undefined
      }
      if (cached !== undefined && cached.mtimeMs === info.mtimeMs) {
        return { ...cached, file }
      }
      let bytes
      try {
        bytes = await readFile(file)
      } catch (error) {
        log?.('warn', `remote-mobile: 读取静态文件 ${name} 失败: ${String(error?.message ?? error)}`)
        return undefined
      }
      const entry = {
        bytes,
        mime: mimeFor(name),
        // 强 ETag 用内容大小 + mtime，够用且不用每次算哈希。
        etag: `"${info.size.toString(16)}-${Math.floor(info.mtimeMs).toString(16)}"`,
        mtimeMs: info.mtimeMs,
      }
      cache.set(name, entry)
      return { ...entry, file }
    },

    /** 清空缓存（`set.enabled` 切换/重新打包后可在调试时调用）。 */
    clear() {
      cache.clear()
    },
  }
}
