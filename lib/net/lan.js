/**
 * 局域网地址发现 + 「谁允许进」的判定（PROTOCOL §1 的 Host/Origin 自检与来源网段）。
 *
 * 这里只做**纯函数 + 一次性枚举**，不持有 socket：监听器每个请求都会问它
 * 「这个 Host 是不是本机地址」「这个对端地址是不是私有网段」。
 *
 * 判定规则（与 DSH 自己的 `isTrustedApiRequest` 同构，PLAN §3.5.4）：
 *   - `Host` 必须是 `<本机 LAN IP | hostname | localhost | 127.0.0.1 | [::1]>:<实际端口>`；
 *   - `Origin`（若有）必须与 `Host` 同 authority；
 *   - 对端地址默认只允许 RFC1918 / 链路本地 / loopback；`allowedNetworks` 非空时改为
 *     只认这些 CIDR（loopback 始终放行，方便 PC 本机自测）。
 *
 * @module dsh-plugin-remote-mobile/lan
 */

import net from 'node:net'
import os from 'node:os'

import { RmError } from '../config.js'

/** 枚举网卡的缓存时间：换网/DHCP 续租后最多 3 秒生效。 */
const CACHE_MS = 3_000

/** 默认允许的来源网段（PLAN §3.1.4）。 */
export const PRIVATE_NETWORKS = Object.freeze([
  '10.0.0.0/8',
  '172.16.0.0/12',
  '192.168.0.0/16',
  '169.254.0.0/16',
  '127.0.0.0/8',
  '::1/128',
  'fc00::/7',
  'fe80::/10',
])

/**
 * 把 CIDR 变成 BlockList 能吃的 `{ address, prefix, type }`。
 * @param {string} cidr - 例如 `192.168.0.0/16` 或 `fe80::/10`。
 * @returns {{ address: string, prefix: number, type: 'ipv4'|'ipv6' }} 解析结果。
 * @throws {RmError} CIDR 不合法时。
 */
export function parseCidr(cidr) {
  const text = typeof cidr === 'string' ? cidr.trim() : ''
  const slash = text.lastIndexOf('/')
  const address = slash >= 0 ? text.slice(0, slash) : text
  const bits = slash >= 0 ? Number(text.slice(slash + 1)) : NaN
  const family = net.isIP(address)
  if (family === 0 || !Number.isInteger(bits)) {
    throw new RmError('rm/bad-request', `allowedNetworks 里的 "${cidr}" 不是合法 CIDR（形如 192.168.0.0/16）`)
  }
  const maxBits = family === 4 ? 32 : 128
  if (bits < 0 || bits > maxBits) {
    throw new RmError('rm/bad-request', `allowedNetworks 里的 "${cidr}" 前缀长度必须在 0..${maxBits}`)
  }
  return { address, prefix: bits, type: family === 4 ? 'ipv4' : 'ipv6' }
}

/**
 * 把 IPv4-mapped IPv6（`::ffff:192.168.1.5`）压回 IPv4，其余原样返回。
 * @param {string} address - 对端/本机地址。
 * @returns {string} 规范化地址。
 */
export function normalizeAddress(address) {
  if (typeof address !== 'string') return ''
  const text = address.trim()
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(text)
  if (mapped !== null) return mapped[1]
  return text
}

/**
 * 查一个地址是否落在 BlockList 里。
 * @param {net.BlockList} list - 规则表。
 * @param {string} address - 待查地址。
 * @returns {boolean} 结论。
 */
function inList(list, address) {
  const normalized = normalizeAddress(address)
  const family = net.isIP(normalized)
  if (family === 0) return false
  try {
    return list.check(normalized, family === 4 ? 'ipv4' : 'ipv6')
  } catch {
    return false
  }
}

/**
 * 建一张 BlockList。
 * @param {readonly string[]} cidrs - CIDR 列表。
 * @returns {net.BlockList} 规则表。
 */
export function buildBlockList(cidrs) {
  const list = new net.BlockList()
  for (const cidr of cidrs) {
    const parsed = parseCidr(cidr)
    list.addSubnet(parsed.address, parsed.prefix, parsed.type)
  }
  return list
}

/** 默认私有网段规则表（模块级只建一次）。 */
const PRIVATE_BLOCK_LIST = buildBlockList(PRIVATE_NETWORKS)

/**
 * 地址是否属于「本机局域网/链路本地/loopback」。
 * @param {string} address - 对端地址（可能是 `::ffff:` 形式）。
 * @returns {boolean} 结论。
 */
export function isPrivateAddress(address) {
  return inList(PRIVATE_BLOCK_LIST, address)
}

/**
 * 来源是否允许（监听器入口的网段闸门）。
 * @param {string|undefined} address - socket 的 remoteAddress。
 * @param {readonly string[]} allowedNetworks - 非空时只认这些 CIDR（loopback 仍放行）。
 * @returns {boolean} 结论。
 */
export function isAllowedSource(address, allowedNetworks) {
  if (typeof address !== 'string' || address === '') return false
  const normalized = normalizeAddress(address)
  if (normalized === '::1' || normalized === '127.0.0.1') return true
  if (normalized.startsWith('127.')) return true
  if (!Array.isArray(allowedNetworks) || allowedNetworks.length === 0) return isPrivateAddress(normalized)
  try {
    return inList(buildBlockList(allowedNetworks), normalized)
  } catch {
    // 配置非法时 fail-closed（配置校验阶段已经会拒绝，这里是兜底）。
    return false
  }
}

/**
 * 把地址包成 URL 里的 host 形式（IPv6 加方括号）。
 * @param {string} address - IP。
 * @returns {string} URL host。
 */
export function urlHost(address) {
  return net.isIP(address) === 6 ? `[${address}]` : address
}

/** @type {{ at: number, addresses: Array<{ address: string, family: string, iface: string }> }|undefined} */
let cachedAddresses

/**
 * 枚举本机「可给手机用」的地址：私有 IPv4 + 链路本地 IPv6。
 * @returns {Array<{ address: string, family: string, iface: string }>} 地址列表（IPv4 在前）。
 */
export function listLanAddresses() {
  const now = Date.now()
  if (cachedAddresses !== undefined && now - cachedAddresses.at < CACHE_MS) return cachedAddresses.addresses
  /** @type {Array<{ address: string, family: string, iface: string }>} */
  const result = []
  let interfaces
  try {
    interfaces = os.networkInterfaces()
  } catch {
    interfaces = {}
  }
  for (const [iface, entries] of Object.entries(interfaces)) {
    for (const entry of entries ?? []) {
      if (entry.internal === true) continue
      const family = net.isIP(entry.address) === 6 ? 'IPv6' : 'IPv4'
      if (family === 'IPv4' && !isPrivateAddress(entry.address)) continue
      // IPv6 只放链路本地与 ULA（手机一般拿不到全局 v6 的入站）。
      if (family === 'IPv6' && !isPrivateAddress(entry.address)) continue
      result.push({ address: entry.address, family, iface })
    }
  }
  result.sort((left, right) => (left.family === right.family ? 0 : left.family === 'IPv4' ? -1 : 1))
  cachedAddresses = { at: now, addresses: result }
  return result
}

/**
 * 本机主机名（小写）。Windows 上可能是 `DESKTOP-XXX`，局域网内靠 mDNS/NetBIOS 才解析得到。
 * @returns {string} 主机名。
 */
export function hostName() {
  try {
    return os.hostname().trim().toLowerCase()
  } catch {
    return ''
  }
}

/**
 * 解析 `Host` 头成 `{ hostname, port }`。
 * @param {string} hostHeader - `Host` 头原文（如 `192.168.1.5:17890`、`[::1]:17890`）。
 * @returns {{ hostname: string, port: number|undefined }|undefined} 解析结果。
 */
export function parseAuthority(hostHeader) {
  if (typeof hostHeader !== 'string' || hostHeader.trim() === '') return undefined
  const text = hostHeader.trim()
  // 带方括号的 IPv6。
  const bracket = /^\[([^\]]+)\](?::(\d{1,5}))?$/.exec(text)
  if (bracket !== null) {
    const port = bracket[2] === undefined ? undefined : Number(bracket[2])
    return { hostname: bracket[1].toLowerCase(), port }
  }
  const lastColon = text.lastIndexOf(':')
  if (lastColon >= 0 && text.indexOf(':') !== lastColon) {
    // 裸 IPv6（没有方括号）不允许出现在 Host 里。
    return undefined
  }
  const hostname = (lastColon >= 0 ? text.slice(0, lastColon) : text).toLowerCase()
  const portText = lastColon >= 0 ? text.slice(lastColon + 1) : ''
  if (hostname === '') return undefined
  if (portText !== '' && !/^\d{1,5}$/.test(portText)) return undefined
  return { hostname, port: portText === '' ? undefined : Number(portText) }
}

/**
 * 计算本监听器允许的 Host 集合（小写 `host:port`，IPv6 带方括号）。
 *
 * 每请求调用，内部靠 {@link listLanAddresses} 的 3 秒缓存兜住开销。
 *
 * @param {number} port - 实际监听端口。
 * @param {string} [bindAddress] - 配置里的监听地址；是字面量 IP 时也一并允许。
 * @param {string} [publicHost] - 隧道的公网主机名（如 `xxx.trycloudflare.com`）。
 *   **必须放行**，否则经过隧道转发进来的请求（`Host: xxx.trycloudflare.com`）
 *   会被 Host 栅栏判为非法而 400。这是隧道能用起来的前提条件。
 * @returns {Set<string>} 允许的 authority 集合。
 */
export function allowedAuthorities(port, bindAddress, publicHost) {
  const allowed = new Set()
  const add = (hostname) => {
    if (typeof hostname !== 'string' || hostname === '') return
    allowed.add(`${urlHost(hostname)}:${port}`.toLowerCase())
  }
  add('127.0.0.1')
  add('::1')
  const name = hostName()
  if (name !== '') {
    add(name)
    const short = name.split('.')[0]
    if (short !== '' && short !== name) add(short)
  }
  for (const entry of listLanAddresses()) add(entry.address)
  if (typeof bindAddress === 'string' && net.isIP(bindAddress) !== 0 && bindAddress !== '0.0.0.0' && bindAddress !== '::') {
    add(bindAddress)
  }
  // 隧道的公网主机名：Cloudflare → 本机是明文 HTTP，所以 Host 头**不带端口**。
  // 这里两种写法都收（有端口/无端口），因为隧道客户端转发时通常省略默认端口。
  if (typeof publicHost === 'string' && publicHost !== '') {
    const host = publicHost.toLowerCase()
    allowed.add(host)
    allowed.add(`${host}:443`)
    allowed.add(`${host}:80`)
  }
  return allowed
}

/**
 * 手机侧可用的 URL 列表（配对二维码/面板展示用）。
 * @param {number} port - 实际监听端口。
 * @param {string} [pathname] - 路径，默认 `/m`。
 * @returns {string[]} URL 列表（IPv4 优先，最后是主机名）。
 */
export function buildUrls(port, pathname = '/m') {
  /** @type {string[]} */
  const urls = []
  const suffix = typeof pathname === 'string' && pathname.startsWith('/') ? pathname : `/${pathname ?? 'm'}`
  for (const entry of listLanAddresses()) {
    urls.push(`http://${urlHost(entry.address)}:${port}${suffix}`)
  }
  const name = hostName()
  if (name !== '') urls.push(`http://${name}:${port}${suffix}`)
  return urls
}

/**
 * 判断 `Origin` 是否与 `Host` 同 authority（PROTOCOL §1）。
 *
 * 两种部署形态要同时支持：
 *   - **局域网直连**：手机访问 `http://192.168.x.x:17890`，Origin 也是 http。
 *   - **公网隧道**：手机访问 `https://xxx.trycloudflare.com`，Origin 是 https，
 *     而转发到本机后 `Host` 头**不带端口**（Cloudflare → 源站是明文 HTTP）。
 *
 * 所以不能"只接受 http"：那样隧道下的每个带 Origin 的请求都会被判成跨源
 * （真机上表现为配对提交被拒、提示"Origin 与 Host 不同源"）。
 *
 * 判断口径：把两边的默认端口按**各自协议**补齐后再比 host:port。
 *
 * @param {string} origin - `Origin` 头原文。
 * @param {string} hostHeader - `Host` 头原文。
 * @returns {boolean} 结论。
 */
export function isSameAuthorityOrigin(origin, hostHeader) {
  let parsed
  try {
    parsed = new URL(origin)
  } catch {
    return false
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return false
  const host = parseAuthority(hostHeader)
  if (host === undefined) return false
  if (parsed.hostname.toLowerCase() !== host.hostname) return false

  // Origin 侧：缺端口时按它自己的协议补默认端口（https→443，http→80）。
  const originDefault = parsed.protocol === 'https:' ? 443 : 80
  const originPort = parsed.port === '' ? originDefault : Number(parsed.port)

  // Host 侧：缺端口时**不能**假定 80——隧道转发过来的 Host 是无端口的公网域名，
  // 它对应的是外部的 443。允许「无端口 Host」匹配 80 或 443，
  // 因为这两个都是浏览器默认端口，且此时 hostname 已经严格相等。
  if (host.port === undefined) return originPort === 80 || originPort === 443
  return originPort === host.port
}
