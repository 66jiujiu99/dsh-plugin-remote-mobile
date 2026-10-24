/**
 * remote-mobile — Client 半边（PC 控制面板）。
 *
 * 入口形态与 dsh-plugin-browser-hands/client.js 一致：由宿主 Client 模块加载器
 * 按包名惰性加载，React 从宿主模块表 require，不 import 任何 @deepseek-ai/* 包。
 *
 * 挂载点：`settings.section`（设置页左侧导航里的一节，id `remote-mobile`）。
 *   - 该 slot 由 @deepseek-ai/dsh-client-ui-settings 声明、ui-settings-general 渲染，
 *     多个官方插件（agent-preset / settings-plugins / settings-account …）都用它，
 *     因此是**真实存在**的公开扩展点，语义也比右栏 tab 更贴合「设备管理」。
 *   - 若该 slot 在当前构建里不可用，退回 browser-hands 已验证的右侧栏 tab 方案
 *     （sidebarRightTabs.register + slots.inject('sidebar.right.pane.tab')），
 *     两种情况共用同一个 Panel 组件。
 *
 * 与 Host 的唯一契约是 remote-mobile/PROTOCOL.md §2：POST /plugin/remote-mobile/rpc
 * {op, payload} → {ok:true,data} | {ok:false,error:{code,message}}。
 * Host 未实现时全部请求失败 → 面板显示「Host 未就绪」，不白屏。
 */

window.__ModuleLoader__.load({
  id: 'dsh-plugin-remote-mobile',
  factory(require) {
    const React = require('react');
    const h = React.createElement;

    const RPC_PATH = '/plugin/remote-mobile/rpc';
    const NS = 'remoteMobile';
    const SECTION_ID = 'remote-mobile';
    const TAB_KIND = 'remote-mobile';

    // ───────────────────────────── 文案 ─────────────────────────────
    /** 面板上的空闲时长档位（秒）。0 = 永不主动关。 */
    const IDLE_OPTIONS = [
      { value: 0 }, { value: 300 }, { value: 900 }, { value: 1800 },
      { value: 3600 }, { value: 10800 }, { value: 86400 },
    ]

    const ZH = {
      nav: '手机同步',
      title: '手机同步',
      description: '在同一 Wi-Fi 下用手机打开链接，查看会话、发消息、处理审批。',
      on: '已开启',
      off: '已关闭',
      killed: '已断开',
      killedHint: '监听已停（你手动断开），再次打开开关即可恢复，设备无需重新配对。',
      toggleOn: '开启手机访问',
      toggleOff: '关闭手机访问',
      hostDown: 'Host 未就绪：Host 半边尚未实现或插件未加载。',
      retry: '重试',
      loading: '读取中…',
      listen: '监听',
      port: '端口',
      upstream: '上游',
      cookie: '上游凭据',
      ok: '正常',
      bad: '异常',
      urls: '手机打开这些地址',
      noUrls: '还没有可用地址：先开启手机访问。',
      copy: '复制',
      copied: '已复制',
      lanIps: '本机地址',
      recommended: '推荐',
      sameSubnetHint: '手机上打开和 PC 处在同一网段的那个地址（多网卡/VPN 会有多个）。',
      allUrls: '全部地址',
      pair: '配对新设备',
      pairCreate: '生成配对码',
      pairCancel: '取消',
      pairHint: '在手机浏览器打开上面的地址，输入这 6 位数字（60 秒内有效，只能用一次）。',
      pairUrlHint: '或直接扫码 / 打开带配对码的链接：',
      expiresIn: '剩余',
      seconds: '秒',
      expired: '已过期，请重新生成',
      devices: '已配对设备',
      noDevices: '还没有配对设备。',
      deviceName: '名称',
      deviceSeen: '最后活跃',
      deviceCreated: '配对时间',
      online: '在线',
      offline: '离线',
      readonly: '只读',
      readonlyHint: '只读设备不能发消息、不能审批。',
      revoke: '撤销',
      revokeConfirm: '确认撤销？',
      rename: '改名',
      renameSave: '保存',
      never: '从未',
      approvals: '审批',
      pendingApprovals: '个审批正在等手机',
      noPending: '当前没有待裁决审批',
      approvalsRouting: '手机优先：有在线且可审批的设备时，审批最多等手机 12 秒，超时交还 PC。',
      danger: '危险操作',
      kill: '立即断开',
      killConfirm: '确认断开？',
      killHint: '关闭监听端口并断开所有手机连接。已配对设备保留，重新开启后不用重新配对。',
      revokeAll: '撤销所有设备',
      revokeAllConfirm: '确认撤销全部？',
      revokeAllHint: '清空设备表并断开所有手机连接：每台手机都会被踢出，必须重新配对才能再连。',
      revokeAllDone: '已撤销 {n} 台设备',
      audit: '审计预览',
      auditShow: '查看最近记录',
      auditHide: '收起',
      auditEmpty: '还没有审计记录。',
      selftest: '自检',
      selftestRun: '运行自检',
      selftestResult: '上游 {upstream} · 凭据{cookie} · 上游{cookieOk} · {ms}ms',
      firewall: 'Windows 防火墙（首次开启时可能需要）',
      firewallHint: '以管理员身份运行 PowerShell，只放行「专用网络」：',
      firewallPortNote: '端口取面板上方显示的实际值；关闭状态下按默认 17890 给出，实际端口以开启后为准。',
      notListening: '未监听',
      error: '操作失败',
      actionFailed: '操作失败',
      deviceOnlineWindow: '在线 = 最近 45 秒内有请求',
      tunnel: '公网隧道',
      tunnelOff: '未开启',
      tunnelStarting: '正在启动…',
      tunnelPublic: '公网可达',
      tunnelStart: '开启隧道',
      tunnelStop: '关闭隧道',
      tunnelHint: '开启后手机可以用任意网络访问（不限于同一个 WiFi）。域名每次启动都不同，' +
        '长时间无操作会自动断开。',
      tunnelNeedListener: '请先开启手机同步，隧道才有可指向的端口。',
      tunnelWarn: '⚠ 当前 /m 可从公网访问。请确保配对码没有外传；不用时请关掉。',
      tunnelOpened: '隧道已开启',
      tunnelClosed: '隧道已关闭',
      tunnelIdle: '已空闲 {n} 秒',
      tunnelIdleLabel: '空闲断开',
      tunnelIdleNever: '永不主动关',
      tunnelIdleMin: '{n} 分钟',
      tunnelIdleHour: '{n} 小时',
      tunnelIdleHint: '超过这个时间没有手机请求就自动关隧道（省电、少暴露）。' +
        '「永不主动关」适合长期挂着；注意 DSH 一关隧道必然失效。',
      tunnelIdleSaved: '空闲断开已设为 {v}',
    };

    const EN = {
      nav: 'Phone Sync',
      title: 'Phone Sync',
      description: 'Open the link on a phone in the same Wi-Fi to read sessions, send messages and answer approvals.',
      on: 'On',
      off: 'Off',
      killed: 'Disconnected',
      killedHint: 'The listener is stopped (you disconnected it). Flip the switch back on to resume; devices stay paired.',
      toggleOn: 'Enable phone access',
      toggleOff: 'Disable phone access',
      hostDown: 'Host not ready: the Host half is missing or the plugin is not loaded.',
      retry: 'Retry',
      loading: 'Loading…',
      listen: 'Listening',
      port: 'Port',
      upstream: 'Upstream',
      cookie: 'Upstream credential',
      ok: 'OK',
      bad: 'Failing',
      urls: 'Open these on the phone',
      noUrls: 'No address yet — enable phone access first.',
      copy: 'Copy',
      copied: 'Copied',
      lanIps: 'Local addresses',
      recommended: 'Recommended',
      sameSubnetHint: 'Open the address on the same subnet as the phone (multi-NIC/VPN hosts list several).',
      allUrls: 'All addresses',
      pair: 'Pair a new device',
      pairCreate: 'Create pairing code',
      pairCancel: 'Cancel',
      pairHint: 'Open the address above on the phone and enter these 6 digits (valid 60s, single use).',
      pairUrlHint: 'Or open the pre-filled link directly:',
      expiresIn: 'expires in',
      seconds: 's',
      expired: 'Expired — create a new code',
      devices: 'Paired devices',
      noDevices: 'No paired devices yet.',
      deviceName: 'Name',
      deviceSeen: 'Last seen',
      deviceCreated: 'Paired at',
      online: 'Online',
      offline: 'Offline',
      readonly: 'Read-only',
      readonlyHint: 'A read-only device cannot send messages or approve.',
      revoke: 'Revoke',
      revokeConfirm: 'Revoke?',
      rename: 'Rename',
      renameSave: 'Save',
      never: 'Never',
      approvals: 'Approvals',
      pendingApprovals: 'approvals waiting on a phone',
      noPending: 'No approvals pending',
      approvalsRouting: 'Phone-first: while an online approvable device exists, an approval waits up to 12s for the phone, then falls back to the PC.',
      danger: 'Danger zone',
      kill: 'Disconnect now',
      killConfirm: 'Confirm disconnect?',
      killHint: 'Closes the listener and drops every phone connection. Paired devices are kept, so re-enabling needs no re-pairing.',
      revokeAll: 'Revoke all devices',
      revokeAllConfirm: 'Revoke every device?',
      revokeAllHint: 'Clears the device table and drops every phone connection: each phone is kicked out and must pair again.',
      revokeAllDone: 'Revoked {n} device(s)',
      audit: 'Audit preview',
      auditShow: 'Show recent entries',
      auditHide: 'Hide',
      auditEmpty: 'No audit entries yet.',
      selftest: 'Self-test',
      selftestRun: 'Run self-test',
      selftestResult: 'Upstream {upstream} · credential {cookie} · upstream {cookieOk} · {ms}ms',
      firewall: 'Windows firewall (may be needed on first enable)',
      firewallHint: 'Run PowerShell as administrator, allow private networks only:',
      firewallPortNote: 'Uses the live port shown above; while disabled it shows the default 17890 — confirm after enabling.',
      notListening: 'not listening',
      error: 'Action failed',
      actionFailed: 'Action failed',
      deviceOnlineWindow: 'Online = a request within the last 45 seconds',
      tunnel: 'Public tunnel',
      tunnelOff: 'Off',
      tunnelStarting: 'Starting…',
      tunnelPublic: 'Publicly reachable',
      tunnelStart: 'Open tunnel',
      tunnelStop: 'Close tunnel',
      tunnelHint: 'Once open, the phone can reach this DSH from any network, not just the same Wi-Fi. ' +
        'The URL changes on every start, and an idle tunnel closes itself.',
      tunnelNeedListener: 'Enable Phone sync first — the tunnel needs a listening port to point at.',
      tunnelWarn: '⚠ /m is currently reachable from the public internet. Keep the pairing code private and close the tunnel when done.',
      tunnelOpened: 'Tunnel opened',
      tunnelClosed: 'Tunnel closed',
      tunnelIdle: 'Idle for {n}s',
      tunnelIdleLabel: 'Idle timeout',
      tunnelIdleNever: 'Never close',
      tunnelIdleMin: '{n} min',
      tunnelIdleHour: '{n} h',
      tunnelIdleHint: 'Closes the tunnel after this long without a phone request (less exposure, less battery). ' +
        '"Never close" suits long-running setups; note the tunnel still dies when DSH quits.',
      tunnelIdleSaved: 'Idle timeout set to {v}',
    };

    // ───────────────────────────── RPC ─────────────────────────────
    async function call(op, payload) {
      let response;
      try {
        response = await fetch(RPC_PATH, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify(payload === undefined ? { op } : { op, payload }),
          cache: 'no-store',
        });
      } catch (error) {
        const failure = new Error(String(error && error.message ? error.message : error));
        failure.hostDown = true;
        throw failure;
      }
      const text = await response.text();
      let body = null;
      try { body = text ? JSON.parse(text) : null; } catch { body = null; }
      if (!body) {
        const failure = new Error('HTTP ' + response.status + (text ? ': ' + text.slice(0, 200) : ''));
        if (response.status === 404) failure.hostDown = true;
        throw failure;
      }
      if (body.ok === true) return body.data;
      const error = body.error || {};
      const failure = new Error(error.message || error.code || 'rpc failed');
      failure.code = error.code;
      if (error.code === 'rm/not-found' || error.code === 'rm/internal') failure.hostDown = false;
      throw failure;
    }

    async function copyText(text) {
      try {
        await navigator.clipboard.writeText(text);
        return true;
      } catch { /* 回退到 execCommand */ }
      try {
        const area = document.createElement('textarea');
        area.value = text;
        area.setAttribute('readonly', '');
        area.style.position = 'fixed';
        area.style.opacity = '0';
        document.body.appendChild(area);
        area.select();
        const ok = document.execCommand('copy');
        document.body.removeChild(area);
        return ok;
      } catch {
        return false;
      }
    }

    function fmtWhen(value, neverLabel) {
      if (!value) return neverLabel;
      const ms = typeof value === 'number' ? value : Date.parse(value);
      if (!Number.isFinite(ms)) return neverLabel;
      const diff = Date.now() - ms;
      if (diff < 60_000) return '刚刚';
      if (diff < 3_600_000) return Math.floor(diff / 60_000) + 'm';
      if (diff < 86_400_000) return Math.floor(diff / 3_600_000) + 'h';
      return Math.floor(diff / 86_400_000) + 'd';
    }

    // ───────────────────────────── 样式 ─────────────────────────────
    const STYLE = `
      .rm-root { display: flex; flex-direction: column; gap: 14px; padding: 2px 2px 28px; color: var(--dsw-alias-label-primary); font: var(--dsw-font-xs-13); }
      .rm-head { display: flex; align-items: flex-start; gap: 12px; }
      .rm-head-text { flex: 1; min-width: 0; }
      .rm-title { font-size: 15px; font-weight: 600; }
      .rm-desc { margin-top: 3px; color: var(--dsw-alias-label-secondary); font: var(--dsw-font-xxs-12); line-height: 1.6; }
      .rm-badge { flex: none; display: inline-flex; align-items: center; gap: 6px; padding: 3px 9px; border-radius: 999px; border: .5px solid var(--dsw-alias-border-l2); color: var(--dsw-alias-label-secondary); font: var(--dsw-font-xxs-12); }
      .rm-badge.on { color: var(--dsw-alias-state-business-primary); border-color: var(--dsw-alias-state-business-primary); }
      .rm-badge.err { color: var(--dsw-alias-state-error-primary); border-color: var(--dsw-alias-state-error-primary); }
      .rm-badge.warn { color: var(--dsw-alias-state-warning-primary, #b8860b); border-color: var(--dsw-alias-state-warning-primary, #b8860b); }
      /* 公网可达的强提示：一眼就能看到，不靠颜色辨别能力也能读。 */
      .rm-tunnel-warn { padding: 8px 10px; border-radius: var(--dsw-radius-sm); background: var(--dsw-alias-bg-warning, rgba(184,134,11,.12)); border: .5px solid var(--dsw-alias-state-warning-primary, #b8860b); font: var(--dsw-font-xxs-12); line-height: 1.5; }
      .rm-row { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
      .rm-select { font: var(--dsw-font-xxs-12); padding: 4px 8px; border-radius: var(--dsw-radius-sm); border: .5px solid var(--dsw-alias-border-l2); background: var(--dsw-alias-bg-layer-1); color: inherit; }
      .rm-dot { width: 6px; height: 6px; border-radius: 50%; background: currentColor; }

      .rm-card { border: .5px solid var(--dsw-alias-border-l3); border-radius: var(--dsw-radius-sm); background: var(--dsw-alias-bg-layer-1); padding: 12px; display: flex; flex-direction: column; gap: 10px; }
      .rm-card-title { font-size: 13px; font-weight: 600; display: flex; align-items: center; gap: 8px; }
      .rm-card-title .rm-spacer { flex: 1; }
      .rm-row { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
      .rm-kv { display: flex; gap: 6px; align-items: baseline; color: var(--dsw-alias-label-secondary); font: var(--dsw-font-xxs-12); }
      .rm-kv b { color: var(--dsw-alias-label-primary); font-weight: 600; }
      .rm-sep { height: 1px; background: var(--dsw-alias-border-l3); opacity: .6; }

      .rm-btn { border: .5px solid var(--dsw-alias-border-l2); background: var(--dsw-alias-bg-layer-1); color: var(--dsw-alias-label-primary); border-radius: var(--dsw-radius-sm); font: var(--dsw-font-xxs-12); padding: 5px 10px; cursor: pointer; }
      .rm-btn:hover { border-color: var(--dsw-alias-label-quaternary); }
      .rm-btn.primary { background: var(--dsw-alias-state-business-primary); border-color: transparent; color: #fff; }
      .rm-btn.danger { color: var(--dsw-alias-state-error-primary); border-color: var(--dsw-alias-state-error-primary); background: transparent; }
      .rm-btn.danger.solid { background: var(--dsw-alias-state-error-primary); border-color: transparent; color: #fff; }
      .rm-btn:disabled { opacity: .5; cursor: default; }
      .rm-btn.ghost { border-color: transparent; background: transparent; color: var(--dsw-alias-label-secondary); }

      .rm-switch { display: inline-flex; align-items: center; gap: 8px; cursor: pointer; user-select: none; }
      .rm-switch-track { width: 38px; height: 22px; border-radius: 999px; background: rgba(120, 120, 128, .28); border: none; position: relative; transition: background .15s; }
      .rm-switch-track i { position: absolute; top: 2px; left: 2px; width: 18px; height: 18px; border-radius: 50%; background: #fff; box-shadow: 0 1px 2px rgba(0, 0, 0, .25); transition: transform .15s, background .15s; }
      .rm-switch[data-on="1"] .rm-switch-track { background: var(--dsw-alias-state-business-primary); border-color: transparent; }
      .rm-switch[data-on="1"] .rm-switch-track i { transform: translateX(16px); background: #fff; }

      .rm-url { display: flex; align-items: center; gap: 8px; padding: 6px 8px; border-radius: var(--dsw-radius-sm); background: var(--dsw-alias-bg-base); border: .5px solid var(--dsw-alias-border-l3); }
      .rm-url code { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font: var(--dsw-font-xxs-12); }
      .rm-muted { color: var(--dsw-alias-label-tertiary, var(--dsw-alias-label-quaternary)); font: var(--dsw-font-xxs-12); line-height: 1.6; }
      .rm-tag { flex: none; font: var(--dsw-font-xxs-11); color: var(--dsw-alias-state-business-primary); border: .5px solid var(--dsw-alias-state-business-primary); border-radius: 999px; padding: 1px 7px; }

      .rm-code { display: flex; align-items: center; gap: 14px; flex-wrap: wrap; }
      .rm-code-digits { font: 700 30px/1.1 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; letter-spacing: .16em; }
      .rm-code-side { display: flex; flex-direction: column; gap: 4px; }
      .rm-countdown { color: var(--dsw-alias-state-business-primary); font: var(--dsw-font-xxs-12); font-variant-numeric: tabular-nums; }

      .rm-devices { display: flex; flex-direction: column; gap: 8px; }
      .rm-device { border: .5px solid var(--dsw-alias-border-l3); border-radius: var(--dsw-radius-sm); padding: 9px 10px; display: flex; flex-direction: column; gap: 6px; }
      .rm-device-top { display: flex; align-items: center; gap: 8px; }
      .rm-device-name { font-size: 13px; font-weight: 600; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
      .rm-device-name input { font: inherit; font-size: 13px; font-weight: 600; padding: 2px 6px; border-radius: 4px; border: .5px solid var(--dsw-alias-border-l2); background: var(--dsw-alias-bg-base); color: var(--dsw-alias-label-primary); width: 100%; }
      .rm-online { display: inline-flex; align-items: center; gap: 5px; font: var(--dsw-font-xxs-11); color: var(--dsw-alias-label-tertiary, var(--dsw-alias-label-quaternary)); }
      .rm-online i { width: 6px; height: 6px; border-radius: 50%; background: var(--dsw-alias-label-quaternary); }
      .rm-online.on i { background: var(--dsw-alias-state-business-primary); }
      .rm-device-meta { color: var(--dsw-alias-label-tertiary, var(--dsw-alias-label-quaternary)); font: var(--dsw-font-xxs-11); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
      .rm-device-actions { display: flex; gap: 6px; align-items: center; flex-wrap: wrap; }

      .rm-error { border: .5px solid var(--dsw-alias-state-error-primary); color: var(--dsw-alias-state-error-primary); border-radius: var(--dsw-radius-sm); padding: 8px 10px; font: var(--dsw-font-xxs-12); background: color-mix(in srgb, var(--dsw-alias-state-error-primary) 8%, transparent); }
      .rm-notice { border: .5px solid var(--dsw-alias-state-business-primary); color: var(--dsw-alias-state-business-primary); border-radius: var(--dsw-radius-sm); padding: 8px 10px; font: var(--dsw-font-xxs-12); background: color-mix(in srgb, var(--dsw-alias-state-business-primary) 8%, transparent); }
      .rm-action { display: flex; align-items: center; gap: 12px; padding: 8px 0; border-top: .5px dashed var(--dsw-alias-border-l3); }
      .rm-action-text { flex: 1; min-width: 0; display: flex; flex-direction: column; gap: 3px; }
      .rm-action-name { font: var(--dsw-font-xxs-12); font-weight: 600; }
      .rm-action-strong { border-top: .5px solid var(--dsw-alias-state-error-primary); padding-top: 10px; }
      .rm-action-strong .rm-action-name { color: var(--dsw-alias-state-error-primary); }
      .rm-pre { margin: 0; max-height: 220px; overflow: auto; padding: 8px; border-radius: var(--dsw-radius-sm); background: var(--dsw-alias-bg-base); border: .5px solid var(--dsw-alias-border-l3); font: var(--dsw-font-xxs-11); white-space: pre-wrap; word-break: break-all; color: var(--dsw-alias-label-secondary); }
      details.rm-details { border: .5px solid var(--dsw-alias-border-l3); border-radius: var(--dsw-radius-sm); padding: 8px 10px; }
      details.rm-details summary { cursor: pointer; font: var(--dsw-font-xxs-12); color: var(--dsw-alias-label-secondary); }
      .rm-cols { display: flex; gap: 14px; flex-wrap: wrap; }
    `;

    // ───────────────────────────── 面板 ─────────────────────────────
    function Panel(props) {
      const t = props && typeof props.t === 'function' ? props.t : (key) => ZH[key] || key;

      const [status, setStatus] = React.useState(null);
      const [devices, setDevices] = React.useState(null);
      const [hostDown, setHostDown] = React.useState(false);
      const [error, setError] = React.useState(null);
      const [busy, setBusy] = React.useState('');
      const [pair, setPair] = React.useState(null);
      const [tick, setTick] = React.useState(0);
      const [audit, setAudit] = React.useState(null);
      const [selftest, setSelftest] = React.useState(null);
      const [dangerAction, setDangerAction] = React.useState('');
      const [notice, setNotice] = React.useState('');
      const [revoking, setRevoking] = React.useState('');
      const [renaming, setRenaming] = React.useState(null);
      /** 隧道状态（`{ok, provider, tunnel:{phase, publicUrl, lastError, idleSec}}`）。 */
      const [tunnelState, setTunnel] = React.useState(null);
      const alive = React.useRef(true);
      const pollTimer = React.useRef(0);
      const noticeTimer = React.useRef(0);

      const flash = React.useCallback((message) => {
        setNotice(message);
        clearTimeout(noticeTimer.current);
        noticeTimer.current = setTimeout(() => { if (alive.current) setNotice(''); }, 4000);
      }, []);

      const refresh = React.useCallback(async () => {
        try {
          const next = await call('status');
          if (!alive.current) return;
          setStatus(next || {});
          setHostDown(false);
          setError(null);
          const listed = Array.isArray(next && next.devices) ? next.devices : null;
          if (listed && listed.length) setDevices(listed);
          else {
            try {
              const listValue = await call('devices.list');
              if (alive.current) setDevices(Array.isArray(listValue && listValue.devices) ? listValue.devices : []);
            } catch { /* 保留上一份列表 */ }
          }
          // 隧道状态单独取：它比 status 更慢变，且**失败不影响主面板**
          // （老版本 Host 没有这个 op 时，面板照常能用）。
          try {
            const tunnelValue = await call('tunnel.status');
            if (alive.current) setTunnel(tunnelValue || null);
          } catch { /* Host 未提供 tunnel.status，保持未知 */ }
        } catch (failure) {
          if (!alive.current) return;
          if (failure.hostDown) setHostDown(true);
          else setError(String(failure.message || failure));
        }
      }, []);

      React.useEffect(() => {
        alive.current = true;
        refresh();
        const loop = () => {
          if (!alive.current) return;
          if (document.visibilityState === 'visible') refresh();
          pollTimer.current = setTimeout(loop, 2500);
        };
        pollTimer.current = setTimeout(loop, 2500);
        const beat = setInterval(() => { if (alive.current) setTick((value) => value + 1); }, 1000);
        return () => {
          alive.current = false;
          clearTimeout(pollTimer.current);
          clearInterval(beat);
        };
      }, [refresh]);

      // Host 的 status.pair 是 {active: {code, expiresAt, urls}}：有 active 就直接展示。
      React.useEffect(() => {
        const active = status && status.pair && status.pair.active;
        if (active && active.code) setPair(active);
        else if (status && status.pair && !status.pair.active) setPair(null);
      }, [status && status.pair && status.pair.active]);

      const run = React.useCallback(async (label, action) => {
        setBusy(label);
        setError(null);
        try {
          const value = await action();
          await refresh();
          return value;
        } catch (failure) {
          if (failure.hostDown) setHostDown(true);
          else setError(String(failure.message || failure));
          return null;
        } finally {
          if (alive.current) setBusy('');
        }
      }, [refresh]);

      const enabled = !!(status && status.enabled);
      // killSwitch = 用户主动「立即断开」：监听已停但 enabled 仍是 true，
      // 所以开关与按钮一律按「实际是否在监听」显示，避免面板说自己在监听。
      const killed = !!(status && status.killSwitch);
      const effectiveOn = enabled && !killed;
      const urls = (status && Array.isArray(status.urls) ? status.urls : []).filter(Boolean);
      const lanIps = (status && Array.isArray(status.lanIps) ? status.lanIps : []).filter(Boolean);
      // 多网卡机器会拿到 9+ 个地址（含 IPv6 链路本地）：IPv4 直接列出，
      // 主机名与 IPv6 折叠起来，避免面板变成一张 URL 清单。
      const isIPv4Url = (url) => /\/\/\d{1,3}(\.\d{1,3}){3}(:|[/?#])/.test(url);
      const shownUrls = urls.filter(isIPv4Url);
      const foldedUrls = urls.filter((url) => !isIPv4Url(url));
      const pending = (status && typeof status.pendingApprovals === 'number') ? status.pendingApprovals : 0;
      // kill / 关闭状态下列表器不再监听：端口一律按 status 显示，绝不硬编码。
      // 停止监听时不再报一个“看起来在监听”的端口号（Host 侧 kill 后 port 可能仍是旧值，
      // 但 urls 一定为空、killSwitch 一定为 true），这里以“是否真的在监听”为准。
      const listening = !!status && enabled && !killed && urls.length > 0 && Number(status.port) > 0;
      const portText = status ? (listening ? String(status.port) : t('notListening')) : '…';
      // 防火墙规则按实际端口给：未监听时退回默认 17890，并在文案里说明。
      const firewallPort = (status && Number(status.port) > 0) ? status.port : 17890;
      const firewallCommand = String(firewallPort);
      const ipUrls = lanIps.map((item) => (typeof item === 'string' ? item : (item && (item.url || item.address)) || '')).filter(Boolean);

      const toggleEnabled = () => run('toggle', () => call('set.enabled', { enabled: !(enabled && !killed) }));

      // ── 隧道 ──────────────────────────────────────────────────
      const tunnelPhase = (tunnelState && tunnelState.tunnel && tunnelState.tunnel.phase) || 'idle';
      const tunnelUrl = (tunnelState && tunnelState.tunnel && tunnelState.tunnel.publicUrl) || '';
      const tunnelLastError = (tunnelState && tunnelState.tunnel && tunnelState.tunnel.lastError) || '';
      const tunnelIdleSec = Number(tunnelState && tunnelState.tunnel && tunnelState.tunnel.idleSec);
      // 空闲多久会断——从 Host 拿不到配置，就用状态里给的 idleSec 做正计时。
      const idleText = tunnelPhase === 'running' && Number.isFinite(tunnelIdleSec)
        ? t('tunnelIdle').replace('{n}', String(tunnelIdleSec))
        : '';

      // 面板上可选的空闲时长（秒）。0 = 永不主动关。
      // 只给常见档位，避免用户对着数字框发呆；当前值不在档位里也能显示。
      const idleChoice = (tunnelState && tunnelState.tunnel && typeof tunnelState.tunnel.idleTimeoutSec === 'number')
        ? tunnelState.tunnel.idleTimeoutSec
        : 1800;
      const idleLabelOf = (sec) => {
        if (sec === 0) return t('tunnelIdleNever');
        if (sec < 3600) return t('tunnelIdleMin').replace('{n}', String(Math.round(sec / 60)));
        return t('tunnelIdleHour').replace('{n}', String(Math.round(sec / 3600)));
      };

      const saveIdle = (seconds) => run('tunnelIdle', async () => {
        const value = await call('tunnel.setIdle', { idleTimeoutSec: seconds });
        flash(t('tunnelIdleSaved').replace('{v}', idleLabelOf(seconds)));
        return value;
      });

      const startTunnel = () => run('tunnelStart', async () => {
        const value = await call('tunnel.start');
        if (value && value.url) flash(t('tunnelOpened'));
        return value;
      });

      const stopTunnel = () => run('tunnelStop', async () => {
        const value = await call('tunnel.stop');
        flash(t('tunnelClosed'));
        return value;
      });

      const createPair = () => run('pair', async () => {
        const value = await call('pair.create', {});
        setPair(value || null);
        return value;
      });

      const cancelPair = () => run('pairCancel', async () => {
        await call('pair.cancel');
        setPair(null);
      });

      // 两个语义分开的危险操作（PROTOCOL §2 / Lead 2026-10-23 拍板）：
      //   kill       = 只关监听并断开在途连接，设备表保留；
      //   revokeAll  = 清空设备表 + 断开连接，之后每台手机都要重新配对。
      const killNow = () => run('kill', async () => {
        const value = await call('kill');
        setDangerAction('');
        setPair(null);
        return value;
      });

      const revokeAllNow = () => run('revokeAll', async () => {
        const value = await call('devices.revokeAll');
        setDangerAction('');
        setPair(null);
        const count = value && typeof value.revoked === 'number' ? value.revoked : 0;
        setError(null);
        flash(t('revokeAllDone').replace('{n}', String(count)));
        return value;
      });

      const loadAudit = () => run('audit', async () => {
        const value = await call('audit.head', { n: 60 });
        const lines = Array.isArray(value && value.lines) ? value.lines : [];
        setAudit(lines);
      });

      const runSelftest = () => run('selftest', async () => {
        const value = await call('selftest');
        setSelftest(value || {});
        return value;
      });

      const toggleReadonly = (device) => run('ro:' + device.id, () => call('devices.readonly', { id: device.id, readonly: !device.readonly }));
      const revoke = (device) => run('rv:' + device.id, async () => {
        const value = await call('devices.revoke', { id: device.id });
        setRevoking('');
        return value;
      });
      const saveRename = (device) => {
        const name = renaming && renaming.id === device.id ? renaming.value.trim() : '';
        setRenaming(null);
        if (!name || name === device.name) return Promise.resolve();
        return run('rn:' + device.id, () => call('devices.rename', { id: device.id, name }));
      };

      const copy = async (text) => {
        const ok = await copyText(text);
        if (ok) setError(null);
        return ok;
      };

      const secondsLeft = pair && pair.expiresAt ? Math.max(0, Math.ceil((pair.expiresAt - Date.now()) / 1000)) : 0;
      // Host 给的 pair.urls 按网卡顺序排，可能第一个是虚拟网卡：优先挑 IPv4 那条，
      // 和上面列出的地址保持一致。
      const pairUrls = pair && Array.isArray(pair.urls) ? pair.urls.filter(Boolean) : [];
      const pairUrl = pairUrls.find(isIPv4Url)
        || pairUrls[0]
        || (urls[0] ? urls[0].replace(/\/$/, '') + '/m/pair' : '');

      const head = h('div', { className: 'rm-head' },
        h('div', { className: 'rm-head-text' },
          h('div', { className: 'rm-title' }, t('title')),
          h('div', { className: 'rm-desc' }, t('description')),
        ),
        h('span', { className: 'rm-badge' + (hostDown ? ' err' : killed ? ' err' : enabled ? ' on' : '') },
          h('i', { className: 'rm-dot' }),
          hostDown ? t('hostDown').split('：')[0] : killed ? t('killed') : enabled ? t('on') : t('off'),
        ),
      );

      if (hostDown) {
        return h('div', { className: 'rm-root' },
          h('style', null, STYLE),
          head,
          h('div', { className: 'rm-error' }, t('hostDown')),
          h('div', { className: 'rm-row' },
            h('button', { className: 'rm-btn', type: 'button', onClick: () => { setHostDown(false); refresh(); } }, t('retry')),
          ),
        );
      }

      return h('div', { className: 'rm-root' },
        h('style', null, STYLE),
        head,

        error ? h('div', { className: 'rm-error' }, t('actionFailed') + '：' + error) : null,
        notice ? h('div', { className: 'rm-notice' }, notice) : null,

        // 总开关 + 状态
        h('div', { className: 'rm-card' },
          h('div', { className: 'rm-card-title' },
            h('span', null, t('toggleOn')),
            h('span', { className: 'rm-spacer' }),
            h('button', {
              className: 'rm-switch',
              type: 'button',
              'data-on': effectiveOn ? '1' : '0',
              disabled: busy === 'toggle',
              onClick: toggleEnabled,
              title: effectiveOn ? t('toggleOff') : t('toggleOn'),
              style: { border: 0, background: 'transparent', padding: 0 },
            },
              h('span', { className: 'rm-switch-track' }, h('i')),
            ),
          ),
          killed ? h('div', { className: 'rm-muted', style: { marginBottom: '6px' } }, t('killedHint')) : null,
          h('div', { className: 'rm-row rm-cols' },
            h('span', { className: 'rm-kv' }, t('port'), h('b', null, portText)),
            h('span', { className: 'rm-kv' }, t('upstream'),
              // 监听没开时上游根本没被探测过：显示 —，别报假警。
              h('b', null, status ? (listening ? (status.upstreamOk === false ? t('bad') : t('ok')) : '—') : '…')),
            h('span', { className: 'rm-kv' }, t('cookie'),
              h('b', null, status ? (status.cookieOk === false ? t('bad') : t('ok')) : '…')),
            h('span', { className: 'rm-kv' }, t('approvals'),
              h('b', null, String(pending))),
          ),
          h('div', { className: 'rm-sep' }),
          h('div', { className: 'rm-muted' }, t('urls')),
          urls.length
            ? h('div', { style: { display: 'flex', flexDirection: 'column', gap: '6px' } },
              (shownUrls.length ? shownUrls : urls).map((url) => h('div', { className: 'rm-url', key: url },
                h('code', { title: url }, url),
                h('button', { className: 'rm-btn ghost', type: 'button', onClick: () => copy(url) }, t('copy')),
              )),
              h('div', { className: 'rm-muted' }, t('sameSubnetHint')),
              foldedUrls.length
                ? h('details', { className: 'rm-details' },
                  h('summary', null, t('allUrls') + '（' + urls.length + '）'),
                  h('div', { style: { display: 'flex', flexDirection: 'column', gap: '6px', marginTop: '8px' } },
                    foldedUrls.map((url) => h('div', { className: 'rm-url', key: url },
                      h('code', { title: url }, url),
                      h('button', { className: 'rm-btn ghost', type: 'button', onClick: () => copy(url) }, t('copy')),
                    )),
                  ),
                )
                : null,
            )
            : h('div', { className: 'rm-muted' }, t('noUrls')),
          ipUrls.length && !urls.length
            ? h('div', { className: 'rm-muted' }, t('lanIps') + '：' + ipUrls.join('、'))
            : null,
        ),

        // 配对
        h('div', { className: 'rm-card' },
          h('div', { className: 'rm-card-title' },
            h('span', null, t('pair')),
            h('span', { className: 'rm-spacer' }),
            pair
              ? h('button', { className: 'rm-btn ghost', type: 'button', disabled: busy === 'pairCancel', onClick: cancelPair }, t('pairCancel'))
              : h('button', { className: 'rm-btn primary', type: 'button', disabled: busy === 'pair' || !effectiveOn, onClick: createPair }, busy === 'pair' ? t('loading') : t('pairCreate')),
          ),
          pair
            ? h('div', null,
              h('div', { className: 'rm-code' },
                h('div', { className: 'rm-code-digits' }, String(pair.code || '').split('').join(' ')),
                h('div', { className: 'rm-code-side' },
                  h('div', { className: 'rm-countdown' }, secondsLeft > 0 ? t('expiresIn') + ' ' + secondsLeft + t('seconds') : t('expired')),
                  h('button', {
                    className: 'rm-btn',
                    type: 'button',
                    onClick: () => copy(String(pair.code || '')),
                  }, t('copy')),
                ),
              ),
              h('div', { className: 'rm-muted', style: { marginTop: '6px' } }, t('pairHint')),
              pairUrl
                ? h('div', { className: 'rm-url', style: { marginTop: '8px' } },
                  h('code', { title: pairUrl }, pairUrl),
                  h('button', { className: 'rm-btn ghost', type: 'button', onClick: () => copy(pairUrl) }, t('copy')),
                )
                : null,
            )
            : h('div', { className: 'rm-muted' }, t('pairHint')),
          !enabled ? h('div', { className: 'rm-muted' }, t('noUrls')) : null,
        ),

        // 公网隧道（手动开关）
        h('div', { className: 'rm-card' },
          h('div', { className: 'rm-card-title' },
            h('span', null, t('tunnel')),
            h('span', { className: 'rm-spacer' }),
            tunnelPhase === 'running'
              ? h('span', { className: 'rm-badge warn' }, t('tunnelPublic'))
              : tunnelPhase === 'starting'
                ? h('span', { className: 'rm-badge' }, t('tunnelStarting'))
                : h('span', { className: 'rm-badge' }, t('tunnelOff')),
          ),

          // 公网可达时最要紧的是让用户「看得见」——这一行是刻意的强提示。
          tunnelPhase === 'running'
            ? h('div', { className: 'rm-tunnel-warn' }, t('tunnelWarn'))
            : null,

          tunnelPhase === 'running' && tunnelUrl
            ? h('div', { className: 'rm-url', style: { marginTop: '2px' } },
              h('code', { title: tunnelUrl }, tunnelUrl),
              h('button', { className: 'rm-btn ghost', type: 'button', onClick: () => copy(tunnelUrl) }, t('copy')),
            )
            : null,

          tunnelLastError && tunnelPhase !== 'running'
            ? h('div', { className: 'rm-muted', style: { color: 'var(--dsw-alias-danger, #c0392b)' } }, tunnelLastError)
            : null,

          h('div', { className: 'rm-row' },
            tunnelPhase === 'running'
              ? h('button', { className: 'rm-btn', type: 'button', disabled: busy === 'tunnelStop', onClick: stopTunnel }, busy === 'tunnelStop' ? t('loading') : t('tunnelStop'))
              : h('button', {
                className: 'rm-btn primary',
                type: 'button',
                disabled: busy === 'tunnelStart' || !listening,
                onClick: startTunnel,
                title: listening ? '' : t('tunnelNeedListener'),
              }, busy === 'tunnelStart' ? t('loading') : t('tunnelStart')),
          ),

          h('div', { className: 'rm-muted' }, listening ? t('tunnelHint') : t('tunnelNeedListener')),
          idleText ? h('div', { className: 'rm-muted' }, idleText) : null,

          // ── 空闲断开时长（可改，立即生效，不用去改配置文件）──────────
          h('div', { className: 'rm-row', style: { marginTop: '2px' } },
            h('span', { className: 'rm-muted', style: { minWidth: '86px' } }, t('tunnelIdleLabel')),
            h('select', {
              className: 'rm-select',
              value: String(idleChoice),
              disabled: busy === 'tunnelIdle',
              onChange: (event) => saveIdle(Number(event.currentTarget.value)),
            },
              IDLE_OPTIONS.map((option) => h('option', { key: option.value, value: String(option.value) }, idleLabelOf(option.value))),
            ),
            busy === 'tunnelIdle' ? h('span', { className: 'rm-muted' }, t('loading')) : null,
          ),
          h('div', { className: 'rm-muted' }, t('tunnelIdleHint')),
        ),

        // 设备
        h('div', { className: 'rm-card' },
          h('div', { className: 'rm-card-title' },
            h('span', null, t('devices')),
            h('span', { className: 'rm-spacer' }),
            h('span', { className: 'rm-muted' }, t('deviceOnlineWindow')),
          ),
          !devices || !devices.length
            ? h('div', { className: 'rm-muted' }, t('noDevices'))
            : h('div', { className: 'rm-devices' },
              devices.map((device) => {
                const isRenaming = renaming && renaming.id === device.id;
                const isRevoking = revoking === device.id;
                return h('div', { className: 'rm-device', key: device.id },
                  h('div', { className: 'rm-device-top' },
                    isRenaming
                      ? h('div', { className: 'rm-device-name', style: { flex: 1 } },
                        h('input', {
                          autoFocus: true,
                          value: renaming.value,
                          onChange: (event) => setRenaming({ id: device.id, value: event.currentTarget.value }),
                          onKeyDown: (event) => {
                            if (event.key === 'Enter') { event.preventDefault(); saveRename(device); }
                            if (event.key === 'Escape') setRenaming(null);
                          },
                          onBlur: () => saveRename(device),
                        }),
                      )
                      : h('div', { className: 'rm-device-name', title: device.name || device.id }, device.name || device.id),
                    h('span', { className: 'rm-spacer', style: { flex: 1 } }),
                    h('span', { className: 'rm-online' + (device.online ? ' on' : '') },
                      h('i'), device.online ? t('online') : t('offline')),
                  ),
                  h('div', { className: 'rm-device-meta', title: device.ua || '' },
                    (device.ua ? String(device.ua).slice(0, 90) : '') || '—'),
                  h('div', { className: 'rm-device-meta' },
                    t('deviceSeen') + ' ' + fmtWhen(device.lastSeenAt, t('never')) + ' · '
                    + t('deviceCreated') + ' ' + fmtWhen(device.createdAt, t('never'))
                    + (device.revoked ? ' · ' + t('killed') : '')),
                  h('div', { className: 'rm-device-actions' },
                    h('button', {
                      className: 'rm-btn',
                      type: 'button',
                      disabled: busy === 'ro:' + device.id,
                      onClick: () => toggleReadonly(device),
                      title: t('readonlyHint'),
                    }, t('readonly') + (device.readonly ? ' ✓' : '')),
                    isRenaming
                      ? h('button', { className: 'rm-btn', type: 'button', onClick: () => saveRename(device) }, t('renameSave'))
                      : h('button', { className: 'rm-btn', type: 'button', onClick: () => setRenaming({ id: device.id, value: device.name || '' }) }, t('rename')),
                    isRevoking
                      ? h('span', { style: { display: 'inline-flex', gap: '6px' } },
                        h('button', {
                          className: 'rm-btn danger',
                          type: 'button',
                          disabled: busy === 'rv:' + device.id,
                          onClick: () => revoke(device),
                        }, t('revokeConfirm')),
                        h('button', { className: 'rm-btn ghost', type: 'button', onClick: () => setRevoking('') }, t('pairCancel')),
                      )
                      : h('button', { className: 'rm-btn danger', type: 'button', onClick: () => setRevoking(device.id) }, t('revoke')),
                  ),
                );
              }),
            ),
        ),

        // 审批
        h('div', { className: 'rm-card' },
          h('div', { className: 'rm-card-title' },
            h('span', null, t('approvals')),
            h('span', { className: 'rm-spacer' }),
            h('span', { className: 'rm-muted' }, pending > 0 ? pending + ' ' + t('pendingApprovals') : t('noPending')),
          ),
          h('div', { className: 'rm-muted' }, t('approvalsRouting')),
        ),

        // 自检 + 审计 + 熔断
        h('div', { className: 'rm-card' },
          h('div', { className: 'rm-card-title' },
            h('span', null, t('selftest')),
            h('span', { className: 'rm-spacer' }),
            h('button', { className: 'rm-btn', type: 'button', disabled: busy === 'selftest', onClick: runSelftest }, busy === 'selftest' ? t('loading') : t('selftestRun')),
          ),
          selftest
            ? h('div', { className: 'rm-muted' },
              t('selftestResult')
                .replace('{upstream}', String(selftest.upstream || '—'))
                .replace('{cookie}', selftest.cookieOk === false ? t('bad') : t('ok'))
                .replace('{cookieOk}', selftest.upstreamOk === false ? t('bad') : t('ok'))
                .replace('{ms}', String(selftest.ms === undefined ? '—' : selftest.ms)))
            : null,
          h('div', { className: 'rm-sep' }),
          h('div', { className: 'rm-card-title' },
            h('span', null, t('audit')),
            h('span', { className: 'rm-spacer' }),
            h('button', {
              className: 'rm-btn ghost',
              type: 'button',
              disabled: busy === 'audit',
              onClick: () => (audit ? setAudit(null) : loadAudit()),
            }, audit ? t('auditHide') : t('auditShow')),
          ),
          audit
            ? (audit.length
              ? h('pre', { className: 'rm-pre' }, audit.join('\n'))
              : h('div', { className: 'rm-muted' }, t('auditEmpty')))
            : null,
          h('div', { className: 'rm-sep' }),
          h('div', { className: 'rm-card-title' }, h('span', null, t('danger'))),
          // 「立即断开」：只关监听 + 断连接，设备表保留。
          h('div', { className: 'rm-action' },
            h('div', { className: 'rm-action-text' },
              h('div', { className: 'rm-action-name' }, t('kill')),
              h('div', { className: 'rm-muted' }, t('killHint')),
            ),
            dangerAction === 'kill'
              ? h('span', { style: { display: 'inline-flex', gap: '6px', flex: 'none' } },
                h('button', { className: 'rm-btn danger', type: 'button', disabled: busy === 'kill', onClick: killNow }, t('killConfirm')),
                h('button', { className: 'rm-btn ghost', type: 'button', onClick: () => setDangerAction('') }, t('pairCancel')),
              )
              : h('button', { className: 'rm-btn danger', type: 'button', disabled: !effectiveOn || busy === 'kill', onClick: () => setDangerAction('kill') }, t('kill')),
          ),
          // 「撤销所有设备」：清空设备表，每台手机都必须重新配对 —— 比 kill 更重，单独一段 + 更强的红色。
          h('div', { className: 'rm-action rm-action-strong' },
            h('div', { className: 'rm-action-text' },
              h('div', { className: 'rm-action-name' }, t('revokeAll')),
              h('div', { className: 'rm-muted' }, t('revokeAllHint')),
            ),
            dangerAction === 'revokeAll'
              ? h('span', { style: { display: 'inline-flex', gap: '6px', flex: 'none' } },
                h('button', { className: 'rm-btn danger solid', type: 'button', disabled: busy === 'revokeAll', onClick: revokeAllNow }, t('revokeAllConfirm')),
                h('button', { className: 'rm-btn ghost', type: 'button', onClick: () => setDangerAction('') }, t('pairCancel')),
              )
              : h('button', {
                className: 'rm-btn danger solid',
                type: 'button',
                disabled: busy === 'revokeAll' || !(devices && devices.length),
                onClick: () => setDangerAction('revokeAll'),
              }, t('revokeAll')),
          ),
          h('details', { className: 'rm-details' },
            h('summary', null, t('firewall')),
            h('div', { className: 'rm-muted', style: { marginTop: '6px' } }, t('firewallHint')),
            h('pre', { className: 'rm-pre', style: { marginTop: '6px' } },
              'netsh advfirewall firewall add rule name="DSH Mobile (LAN)" dir=in action=allow protocol=TCP localport='
              + firewallCommand + ' profile=private'),
            h('div', { className: 'rm-muted', style: { marginTop: '4px' } }, t('firewallPortNote')),
            h('div', { className: 'rm-row', style: { marginTop: '6px' } },
              h('button', {
                className: 'rm-btn ghost',
                type: 'button',
                onClick: () => copy('netsh advfirewall firewall add rule name="DSH Mobile (LAN)" dir=in action=allow protocol=TCP localport='
                  + firewallCommand + ' profile=private'),
              }, t('copy')),
            ),
          ),
        ),
      );
    }

    // ───────────────────────────── 入口 ─────────────────────────────
    function apply(ctx) {
      let localeReady = false;
      try {
        ctx.effect(() => ctx.locale.register(NS, { zh: ZH, en: EN }), 'remote-mobile.copy');
        localeReady = true;
      } catch (error) {
        console.warn('[remote-mobile] locale registration failed', error);
      }

      const boundT = () => {
        try { return ctx.locale.bind(NS); } catch { return (key) => ZH[key] || key; }
      };

      // 1) 首选：设置页的一节（settings.section）
      let mounted = false;
      try {
        ctx.effect(() => ctx.slots.inject('settings.section', () => ctx.slots.register({
          name: 'settings.section',
          id: SECTION_ID,
          order: 60,
          label: () => boundT()('nav'),
          ...(localeReady ? { locale: NS } : {}),
          inject: () => ({}),
        }, Panel)), 'remote-mobile.settings-section');
        mounted = true;
      } catch (error) {
        console.warn('[remote-mobile] settings.section unavailable; falling back to sidebar tab', error);
      }

      // 2) 回退：右侧栏 tab（browser-hands 已验证的挂载方式）
      if (!mounted) {
        try {
          const tabs = ctx.get ? ctx.get('sidebarRightTabs') : ctx.sidebarRightTabs;
          if (tabs && typeof tabs.register === 'function') {
            ctx.effect(() => tabs.register({
              id: 'dsh-plugin-remote-mobile',
              kind: TAB_KIND,
              priority: 'extension',
              title: () => boundT()('nav'),
              keepMounted: true,
              guide: [{ id: 'remote-mobile', title: () => boundT()('nav'), description: () => boundT()('description') }],
            }), 'remote-mobile.tab-type');
            ctx.effect(() => ctx.slots.inject('sidebar.right.pane.tab', () => ctx.slots.register({
              name: 'sidebar.right.pane.tab',
              key: 'dsh-plugin-remote-mobile',
              ...(localeReady ? { locale: NS } : {}),
            }, Panel)), 'remote-mobile.tab-body');
            mounted = true;
          }
        } catch (error) {
          console.error('[remote-mobile] sidebar tab fallback failed', error);
        }
      }

      if (!mounted) console.error('[remote-mobile] no mount point available (settings.section / sidebar.right.pane.tab)');
    }

    return {
      inject: ['slots', 'locale'],
      apply,
    };
  },
});
