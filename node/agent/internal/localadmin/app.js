'use strict';
// Everything lives inside one function so that no name here can collide with
// a property of window (status, history, ...).
(() => {
// Standalone device console. One file, no build step, no dependency and no
// request to anywhere but this device.

// ---------------------------------------------------------------------------
// Strings. Every sentence the page can show is in T, so a translation is one
// object and nothing else. index.html refers to these by data-t="key".
// ---------------------------------------------------------------------------
const T = {
  system: {
    title: '用户与 SSH', hint: 'Linux 账户与网页管理密码独立。删除账户保留家目录；维护服务不受此开关影响。安装程序建议用 systemd 管理。',
    ssh: '远程登录', enabled: '开启 SSH（开机保持）', port: '端口', passwordLogin: '允许普通用户密码登录', rootLogin: '允许 root 公钥登录',
    current: '确认网页管理密码', saveSSH: '保存 SSH 设置', users: '系统账户', action: '操作', create: '创建普通用户', password: '设置账户密码', keys: '替换 SSH 公钥', sudo: '设置 sudo 权限', lock: '锁定 / 解锁账户', delete: '删除账户，保留文件', user: '账户名（root 可设置密码和公钥）',
    newPassword: '账户新密码（至少 12 位）', confirm: '确认新密码', keyHelp: 'Ed25519 公钥，每行一条；留空清除本服务的公钥', toggle: '授予 sudo / 锁定账户（取消则撤销 / 解锁）', apply: '执行操作',
    running: 'SSH 正在运行', stopped: 'SSH 未运行', changed: '设置已保存', mismatch: '两次密码不一致或不足 12 位', needCurrent: '请确认网页管理密码', removeConfirm: '删除此账户？家目录和文件会保留。', locked: '密码锁定或账户过期', ready: '可登录账户',
  },
  skip: '跳到主要内容',
  brandSub: '独立设备管理',
  railFoot: '运行在棒子上，无需 NAS 或云服务',
  footer: 'NasSimHub · 本机管理',
  unknown: '未知',
  none: '无',
  notReported: '尚未上报',
  yes: '是',
  no: '否',
  usbAddress: 'https://10.55.0.2:7581',
  title: { signedOut: '棒子管理', signedIn: '设备管理' },
  connecting: '正在连接设备…',
  connection: { ok: '设备已连接', bad: '连接异常', https: 'HTTPS' },
  nav: { system: '系统管理', label: '管理功能', overview: '设备概览', wifi: '无线网络', sms: '短信管理', security: '安全', update: '更新', diagnostics: '诊断日志', settings: '管理设置' },
  action: { refresh: '刷新', logout: '退出登录' },
  state: { loading: '正在读取…', empty: '暂无数据。', unsupported: '此设备或此版本不支持该功能。' },
  error: {
    timeout: '设备响应超时，请确认 USB 或 Wi-Fi 连接。',
    network: '无法联系设备，请确认 USB 或 Wi-Fi 连接。',
    http: '设备请求失败（{status}）',
    unreachable: '无法访问棒子管理服务：{message}',
  },
  // Codes of the device API, which answers in English; the page leads with
  // what the code means and keeps the device's own sentence in brackets.
  apiCode: {
    invalid_argument: '请求内容无效', not_found: '未找到', conflict: '当前状态不允许此操作', not_supported: '此设备不支持该功能',
    failed_precondition: '当前条件不满足', network_rejected: '运营商网络拒绝了请求', unavailable: '设备暂时无法完成', internal: '设备内部错误',
    permission_denied: '没有权限', unauthenticated: '需要登录', other: '设备返回错误',
  },
  session: {
    expired: '会话已过期，请重新登录。为保护数据，页面内容已清除。',
    loggedOut: '已退出登录，页面内容已清除。',
    policy: '闲置 {idle} 分钟或登录满 {absolute} 小时后，会话自动失效；页面自身的定时刷新不算作操作。',
    locked: '尝试次数过多，请在 {seconds} 秒后重试。',
  },
  login: {
    welcome: '欢迎回来', create: '设置管理密码',
    help: '输入本机管理密码，访问设备后台。',
    helpProof: '设备已确认，只需设置至少 12 位管理密码并再次输入确认。',
    helpNoProof: '请使用设备专用的「设置棒子管理密码」入口。高级维护也可手动输入设备初始化码。',
    setupCode: '设备初始化码（高级维护）', password: '管理密码', confirm: '确认管理密码',
    submit: '登录设备', submitCreate: '设置密码并登录',
    independent: '此密码独立于 NAS 登录和设备配对。',
    needProof: '请在 NAS 的 SIM 节点页点击「打开棒子后台」，进入后直接设置密码。高级维护也可填写设备初始化码。',
    needPassword: '请输入管理密码',
    tooShort: '管理密码至少需要 12 位',
    tooLong: '管理密码最多 256 位',
    mismatch: '两次输入的密码不一致',
  },
  overview: {
    title: '设备运行状态', processesAndInterfaces: '进程与网络接口', localOnly: '仅本机数据', topProcesses: '内存占用较高的进程',
    process: '进程', memory: '内存', interfaces: '接口累计流量', sampled: '采样 {time}', notSampled: '未上报',
    stale: '设备当前没有应答，以下仍是 {time} 的数据，不是当前状态', processesTruncated: '进程数量超过了单次扫描的上限：进程数是下限，列表只来自已扫描的部分。',
    cpu: 'CPU 负载', cpuLocal: '本机 CPU', cpuTemp: 'CPU 温度', coresProcesses: '核心 / 进程', cores: '{cores} 核 / {processes}',
    memoryCard: '内存', used: '已用', free: '可用', storage: '持久存储', deviceStorage: '设备存储', total: '总容量', remaining: '剩余',
    modem: '4G 模组', sim: 'SIM 卡', phone: '手机号', phoneMissing: 'SIM 未提供', wifi: '无线网络', wifiAddress: 'Wi-Fi 地址', saved: '已保存网络', notConfigured: '未配置',
    system: '系统运行', version: '软件版本', pairing: 'NAS 配对', voice: '通话与短信', voiceSource: '能力来自实际后端',
    audioReady: '音频已就绪', audioNotReady: '音频尚未就绪', smsCapability: '短信能力', available: '可用', unavailable: '不可用', volte: 'IMS / VoLTE', trend: '{title}趋势',
    days: '{d} 天 {h} 小时', hours: '{h} 小时 {m} 分', minutes: '{m} 分',
  },
  // Telemetry the device samples itself. A field the device did not send is
  // shown as unknown: never as 0, and never as what an earlier sample said.
  tele: {
    title: '系统遥测', hint: '设备没有上报的项目显示为「未知」，不会显示为 0，也不会沿用之前的数值。',
    cpu: '处理器', model: '型号', coreCount: '核心数', load: '负载均值（1 / 5 / 15 分钟）', loadHint: '运行队列均值，不是百分比', cores: '各核心', core: '核心 {index}',
    online: '在线', offline: '离线', stateUnknown: '状态未知', frequency: '{current}（范围 {min} – {max}）', utilisation: '利用率 {percent}',
    thermal: '温度区', zoneTyped: '{type}（{zone}）', zoneUntyped: '{zone}（类型未知）', zones: '温度区',
    memory: '内存明细', memTotal: '总量', memAvailable: '可用', memFree: '空闲', memBuffers: '缓冲区', memCached: '页缓存（仅内核的 Cached 一项）', swapTotal: '交换区总量', swapFree: '交换区空闲',
    storage: '存储', roles: { state: '状态目录', root: '根文件系统' }, roleOther: '其他（{role}）',
    storageValue: '已用 {used} / 共 {total} · 普通进程可用 {available} · 空闲 {free}', storageWhere: '{role} {path}（{fs}）', fsUnknown: '文件系统类型未知',
    emmc: 'eMMC 寿命（厂商自报的原始寄存器）', emmcDevice: '设备', lifeA: '寿命估计 A（LIFE_TIME_EST_TYP_A）', lifeB: '寿命估计 B（LIFE_TIME_EST_TYP_B）', preEol: '预留块状态（PRE_EOL_INFO）',
    lifeUsed: '{code}：已用额定寿命的 {from}–{to}%', lifeExceeded: '{code}：已超过额定寿命', notReportedCode: '{code}：设备未上报', reservedCode: '{code}：保留值，含义未知',
    preEolCodes: { 1: '{code}：正常', 2: '{code}：警告（预留块已消耗约 80%）', 3: '{code}：紧急' },
    agent: 'Agent 进程', pid: 'PID', rss: '常驻内存（RSS）', agentCpu: 'CPU 占用（占全部核心的份额）',
    cell: '服务小区', band: '频段', earfcn: 'EARFCN', pci: 'PCI', tac: 'TAC', cellId: 'Cell ID', cellTime: '小区信息的采样时间', cellHint: '小区信息由模组上报，有自己的采样时间，可能早于本页其他数据。',
    system: '系统', threads: '线程数', bootId: '本次启动标识（boot_id）',
    ifaceRate: '速率 ↓ {rx} / ↑ {tx}', ifaceTotal: '累计 ↓ {rx} / ↑ {tx}', ifacePackets: '包 ↓ {rx} / ↑ {tx}', ifaceErrors: '错误 ↓ {rx} / ↑ {tx}',
  },
  names: {
    inbound: '收到', outbound: '发出', received: '已接收', sending: '发送中', sent: '已发送', ready: '就绪', missing: '未插 SIM', offline: '离线', unknown: '未知', failed: '失败',
    registered: '已注册', unregistered: '未注册', searching: '搜网中', denied: '注册被拒绝', roaming: '漫游', paired: '已配对', unpaired: '未配对', PAIRED: '已配对', UNPAIRED: '未配对',
    CONNECTED: '已连接', CONNECTING: '连接中', PROVISIONING_AP: '配网热点', NO_WIFI_CONFIG: '未连接', FAILED: '连接失败', yes: '是', no: '否', lte: 'LTE', umts: '3G', gsm: '2G',
  },
  operators: { 'CHN-CT': '中国电信', 'China Telecom': '中国电信', 'CHN-UNICOM': '中国联通', 'CHN-CU': '中国联通', 'China Unicom': '中国联通', 'CHN-CM': '中国移动', 'China Mobile': '中国移动' },
  wifi: {
    title: 'Wi-Fi 配置', scan: '扫描附近网络', ssid: '网络名称（SSID）', security: '加密方式', wpa2: 'WPA2 / 混合 WPA2-WPA3', wpa3: 'WPA3', open: '开放网络', psk: 'Wi-Fi 密码',
    submit: '连接并保存', forget: '忘记已保存网络', noNetworks: '暂未发现可见网络。', channel: '信道 {channel}', unsupported: '此设备的 Wi-Fi 不能从这里配置。',
    safety: '提交前请确认：USB 管理地址 https://10.55.0.2:7581 不受 Wi-Fi 变更影响，始终可用。已保存的网络只有在新网络连接成功后才会被替换；如果最长约 90 秒内连不上，新配置会被丢弃。设备上已有保存的网络时，切换失败后设备回到已保存的网络，而不是回到配网热点；没有已保存的网络时才回到配网热点（前提是热点没有在配置中关闭）。本页会告诉你设备实际回到了原网络、回到了配网热点，还是仍未连接。密码只用于本次连接，不保存在浏览器。',
    confirm: '连接到「{ssid}」？\n\n连接期间通过 Wi-Fi 的访问会中断，成功后设备的 Wi-Fi 地址可能改变。\nUSB 管理地址 https://10.55.0.2:7581 不受影响。\n如果新网络连不上，已保存的配置不会被替换：有已保存的网络时设备回到已保存的网络，而不是回到配网热点。本页会显示设备实际的恢复结果。',
    provisioning: '配网状态：{state}', provisioningUnknown: '未知（设备没有给出配网状态）', provisioningOther: '{state}（本页面不认识这个状态）', reason: '（原因：{reason}）',
    provisioningSaved: '已保存的网络「{saved}」仍保留在设备上。',
    // One label per state of netbackend.States; a Go test fails when the
    // backend gains a state this table has no words for.
    provisioningStates: {
      UNCONFIGURED: '尚未配置：没有已保存的网络，配网热点还没有启动',
      AP_STARTING: '正在启动配网热点',
      AP_READY: '配网热点已启动，连接热点后可以打开配网页面',
      AP_FAILED: '配网热点启动失败，设备会隔一段时间自动重试；USB 管理不受影响',
      JOINING: '已提交凭据，正在加入网络',
      JOINED: '已作为客户端连上网络',
      JOIN_FAILED: '加入失败，设备正在回到原来的位置',
      SAVED_NETWORK_SEARCHING: '已保存的网络当前连不上，正在等待它恢复',
      SAVED_NETWORK_LOST: '已保存的网络持续连不上，即将提供配网热点；已保存的网络仍然保留',
      DISABLED: '配网热点已关闭：通过 USB 配置 Wi-Fi',
    },
    // What is known about joining a network of this kind. It reports testing,
    // not a prediction, so no label here promises that a join will work.
    support: {
      verified: '此类网络已验证过', unverified: '未验证：可能可用，也可能不可用', unsupported: '不支持：无法从本设备加入', unknown: '支持情况未知',
      band5: '5 GHz', wpa3: '纯 WPA3', open: '开放网络', enterprise: '企业级（802.1X）',
    },
    cached: '射频正在提供配网热点，无法重新扫描。下面是 {time} 的扫描结果，不是当前结果。', cachedTimeUnknown: '较早时候',
    notSelectable: '不能从本设备加入，无法选择',
    ap: {
      title: '配网热点', ssid: '热点名称（SSID）', state: '热点状态', passphrase: '热点口令（WPA2）',
      hint: '热点口令只在已登录的本后台显示，并且需要再次输入管理密码；输错会计入登录锁定。口令不会写入日志或诊断包，也不会保存在浏览器。',
      noSource: '此设备的 Wi-Fi 后端没有带口令的配网热点，没有可显示的口令。',
      off: '配网热点已关闭：通过 USB 配置 Wi-Fi。没有可显示的口令。',
      unavailable: '设备暂时无法读取配网热点的信息。',
      show: '显示口令', password: '再次输入管理密码', confirm: '确认并显示', hide: '隐藏口令', needPassword: '请输入管理密码',
      shown: '口令已显示。点击「隐藏口令」、离开本页、退出登录或 {seconds} 秒后，口令会从页面清除。', cleared: '口令已从页面清除。',
    },
    confirmForget: '忘记当前保存的 Wi-Fi？\n\n设备将断开 Wi-Fi；USB 管理地址 https://10.55.0.2:7581 继续可用。',
    submitted: '配置已提交，正在等待设备连接…',
    error: {
      ssidEmpty: '请填写网络名称（SSID）', ssidLong: '网络名称过长：SSID 最多 32 字节（一个汉字占 3 字节），当前 {bytes} 字节', ssidControl: '网络名称不能包含控制字符',
      pskEmpty: '请填写 Wi-Fi 密码', pskShort: 'Wi-Fi 密码至少 8 位', pskLong: 'Wi-Fi 密码最多 63 位（或 64 位十六进制密钥）', pskHex: '64 位的 Wi-Fi 密钥必须全部是十六进制字符（0-9、a-f）',
      pskHexWpa3: '64 位十六进制密钥仅适用于 WPA2；WPA3 请填写 8 至 63 位密码', pskControl: 'Wi-Fi 密码不能包含控制字符',
    },
    outcome: {
      pending: '正在连接「{target}」…已等待 {elapsed} 秒（最长约 {window} 秒）。USB 管理不受影响。',
      connected: '已连接到「{target}」，新配置已保存。如果你通过 Wi-Fi 访问，设备地址可能已经改变。',
      restored: '新网络「{target}」未能连上。设备已回到原来的网络「{previous}」，原配置没有改动。',
      provisioning_ap: '新网络「{target}」未能连上。设备已回到配网热点「{ap}」{address}。{saved}',
      provisioning_ap_forgotten: '已忘记保存的网络。设备已回到配网热点「{ap}」{address}。',
      failed: '新网络「{target}」连接失败{reason}。设备正在恢复，请稍候…',
      not_connected_waiting: '新网络「{target}」未能连上，设备当前没有连接 Wi-Fi，正在等待它恢复…{saved}',
      not_connected: '新网络「{target}」未能连上，设备当前没有连接任何 Wi-Fi。{saved}请通过 USB 地址 https://10.55.0.2:7581 继续管理。',
      forgotten: '已忘记保存的网络，设备当前没有连接 Wi-Fi。请通过 USB 地址 https://10.55.0.2:7581 管理。',
      unknown: '无法确认 Wi-Fi 的最终状态。请通过 USB 地址 https://10.55.0.2:7581 查看。',
      savedKept: '原先保存的网络「{saved}」仍保留在设备上。', savedNone: '设备上没有已保存的网络。',
      lost: '暂时联系不上设备。如果你正通过 Wi-Fi 访问，设备可能已切换网络、地址已改变；USB 地址 https://10.55.0.2:7581 不受影响。仍在重试…',
      lostFinal: '一直联系不上设备，无法确认结果。请改用设备的新 Wi-Fi 地址，或 USB 地址 https://10.55.0.2:7581 。',
    },
  },
  sms: {
    title: '本机短信', refresh: '刷新短信', compose: '发送短信', to: '收件号码', text: '短信内容', send: '发送短信',
    hint: '通过当前 SIM 发送，可能按运营商资费计费。这里显示棒子上的短信，不是 NAS 的历史消息。',
    empty: '棒子上暂时没有短信。', unsupported: '此设备当前不能收发短信。', unknownPeer: '未知号码', remove: '删除', confirmRemove: '删除棒子上的这条短信？',
    confirmSend: '通过当前 SIM 向 {to} 发送这条短信？', submitted: '短信已提交给模组。', count: '{bytes} / 4096 字节',
    // Why this page's own send is refused by the usage policy on the device.
    // Keyed by what the device answers (code, then the NAS's trust state for a
    // denial); nothing here is decided by the page.
    block: {
      recheck: '重新检查',
      draftKept: '草稿已保留：这条短信没有发出，页面也不会自动重试。恢复后请您自己再点一次「发送短信」。',
      draftNone: '这是设备当前的状态；现在发送会被设备拒绝。',
      cleared: '设备现在允许从本页发送短信。草稿未改动，如需发送请再点一次「发送短信」。',
      unknownNow: '暂时读不到设备的使用策略，无法确认是否已恢复；是否允许发送以设备对下一次发送的答复为准。',
      trust_stale_restart: {
        title: '设备重启后，等待 NAS 确认',
        text: '设备重启后无法确认停机时长及策略是否仍有效，需要已配对的 NAS 再确认一次使用策略。',
        recover: '恢复方法：让已配对的 NAS 连上这台设备（USB 线，或同一 Wi-Fi）。NAS 连接后会自动确认，不需要在本页或 NAS 上做任何操作；然后点「重新检查」。',
      },
      trust_stale: {
        title: '使用策略已过期',
        text: 'NAS 上次确认的策略已超过有效期，设备在 NAS 再次确认前不放行外发。',
        recover: '恢复方法：让已配对的 NAS 连上这台设备，NAS 会自动下发新的策略；然后点「重新检查」。如果 NAS 已连接仍然如此，请在 NAS 的「SIM 节点」页查看这台设备的状态。',
      },
      OBSERVATION: {
        title: '观察期：只接收，不外发',
        text: 'NAS 正在观察这台设备（新配对、更换 SIM 或管理员恢复之后都会进入观察期）。观察期内可以接电话、收短信，不能从设备发短信或拨号。',
        recover: '恢复方法：观察期由 NAS 计时，期满后自动允许外发，无需操作；剩余时间可在 NAS 的「设置 → 安全」查看。本页不能缩短或跳过观察期。',
      },
      RESTRICTED: {
        title: '设备已被限制外发',
        text: 'NAS 已停用这台设备的外发（发短信、拨号）。接电话、收短信不受影响。',
        recover: '恢复方法：由管理员在 NAS 的「设置 → 安全」中查看原因并执行「恢复」；恢复后设备先进入观察期，期满才允许外发。本页不能解除。',
      },
      QUARANTINE: {
        title: '设备已被隔离',
        text: 'NAS 已隔离这台设备：不能外发，只保留更新与诊断。',
        recover: '恢复方法：需要管理员在 NAS 的「设置 → 安全」中复核并执行「恢复」；恢复后设备先进入观察期。本页不能解除。',
      },
      trust_damaged: {
        title: '保存的使用策略校验失败',
        text: '设备上保存的策略文件没有通过校验，设备按最严格的方式处理，暂时不放行外发。',
        recover: '恢复方法：让已配对的 NAS 连上这台设备，NAS 会重新下发策略；然后点「重新检查」。',
      },
      trust_denied: {
        title: 'NAS 限制了这台设备的外发',
        text: '已配对的 NAS 当前不允许从这台设备发短信。',
        recover: '恢复方法：在 NAS 的「设置 → 安全」查看这台设备的状态和原因。本页不能解除。',
      },
    },
    uncertain: '设备没有及时答复，这条短信是否已发出尚不确定。页面不会自动重发。内容未改动时再次点击「发送短信」会使用同一个请求编号，由设备判断是否已经发过，不会重复发送。',
    error: {
      toEmpty: '请填写收件号码', toInvalid: '收件号码只能包含 3 至 20 位数字，可以 + 开头',
      textEmpty: '请填写短信内容', textLong: '短信内容过长：最多 4096 字节（一个汉字占 3 字节），当前 {bytes} 字节',
    },
  },
  security: {
    title: '安全', readOnly: '只读 · 来自设备当前状态',
    hint: '这里只显示公开的指纹和状态，不包含任何密钥。指纹用于和 NAS 上显示的内容逐位核对。没有依据的项目显示为「未知」。',
    identity: '设备身份', deviceId: '设备 ID', algorithm: '身份算法', fingerprint: '公钥指纹',
    protection: '安全等级与后量子身份', level: '安全等级', pqStatus: '后量子身份', pqAlgorithm: '后量子算法', pqFingerprint: '后量子公钥指纹', pqDetail: '说明', pqPolicy: '对 NAS 的后量子身份要求',
    owner: '配对的 NAS（Core）', paired: '是否已配对', coreId: 'Core ID', coreFingerprint: 'Core 公钥指纹', corePq: 'Core 后量子密钥已固定', corePqAlgorithm: 'Core 后量子算法', corePqFingerprint: 'Core 后量子公钥指纹', notPaired: '未配对',
    certificate: '本后台的 HTTPS 证书', certFingerprint: 'SHA-256 指纹', certKey: '密钥算法', certFrom: '生效时间', certUntil: '到期时间', certLeft: '（剩余 {days} 天）', certExpired: '（已过期）',
    levels: { STANDARD: 'STANDARD（标准）', PQ: 'PQ（后量子）', PQ_EXTREME: 'PQ_EXTREME（后量子 · 最高）' },
    pq: { active: '已启用', unavailable: '此版本不支持', disabled: '已在配置中关闭', damaged: '密钥文件损坏，未自动重建' },
    policies: { optional: '可选', preferred: '优先', required: '必须' },
    notActive: '未启用',
    trust: {
      title: '信任 / 使用限制', owner: '由已配对的 NAS 决定；本页不能解除',
      status: '当前状态', state: 'NAS 给出的信任状态', denied: '被拒绝的操作', reason: 'NAS 给出的原因', generation: '策略代次', expires: '策略有效期至', mode: '执行方式', sms: '本页发送短信',
      unsupported: '此版本不在设备上执行使用限制（not supported）', notInstalled: '已配对的 NAS 尚未下发策略，设备本身不作限制', readFailed: '未知（读取失败）',
      enforcing: '设备正在执行此策略', monitoring: '仅观察：只记录本应拒绝的操作，不拒绝', stale: '策略已过期：限制继续有效，其余外发操作需连接 NAS 刷新后才可使用', staleRestart: '设备重启后需由 NAS 重新确认策略；连接 NAS 后自动恢复。限制继续有效，其余外发操作在此之前不可使用', damaged: '保存的策略校验失败：外发操作已全部停用，请连接已配对的 NAS 恢复',
      nothingDenied: '无', smsAllowed: '允许', smsRefused: '不允许', expired: '（已过期）',
      states: { UNBOUND: 'UNBOUND（未建立信任记录）', OBSERVATION: 'OBSERVATION（观察期：只接收，不外发）', TRUSTED: 'TRUSTED（可信）', RESTRICTED: 'RESTRICTED（受限：外发已停用）', QUARANTINE: 'QUARANTINE（隔离：需管理员在 NAS 上处理）' },
      actions: { dial: '拨打电话', send_sms: '发送短信', dtmf: '通话中按键（DTMF）', forward_otp: '转发验证码' },
      modes: { enforce: '执行', monitor: '仅观察' },
    },
  },
  update: {
    title: '更新', readOnly: '只读 · 仅可回滚未确认的更新',
    nasOnly: '上传、应用和确认更新都由已配对的 NAS 完成，本后台不提供这些操作，也不能上传固件。这里只显示更新状态，并允许回滚「已应用但尚未确认」的更新。',
    unsupportedBuild: '此版本没有更新服务（not supported in this build）。',
    unsupported: '此设备不支持更新：{reason}', unsupportedNoReason: '此设备不支持更新，设备没有说明原因。',
    running: '运行版本', factory: '出厂版本', active: '当前发布', factoryAgent: '出厂 Agent（未安装发布）', state: '状态', target: '目标版本', release: '发布编号', previous: '上一版本',
    transfer: '传输进度', transferText: '{received} / {expected}（{percent}%）', deadline: '确认期限', lastError: '最近错误', restartReason: '重启原因', attempts: '尝试次数', supported: '是否支持更新',
    policy: '签名策略', outcome: '最近一次验证结果', pqAvailable: '可验证后量子签名', toolchain: '需要的工具链', keys: '发布密钥数量', keysText: '经典 {classical} 个，后量子 {pq} 个', restartPending: '等待重启', updatedAt: '状态更新时间',
    rollback: '回滚此更新', rollbackHelp: '回滚会恢复更新前的 Agent 并重启它，页面会短暂断开。',
    rollbackConfirm: '回滚更新 {release}（{version}）？\n\n设备会恢复到更新前的 Agent{previous} 并重启，本页面会断开，稍后需要重新登录。\n此操作不能在这里撤销；重新更新需要从 NAS 发起。',
    rollbackDone: '已请求回滚，Agent 即将重启。页面会断开，请稍后重新登录。',
    states: {
      IDLE: '空闲', CHECKING: '检查中', AVAILABLE: '有可用更新', DOWNLOADING: '接收中', STAGED: '已接收', VALIDATING: '校验中', READY: '已校验，等待应用',
      APPLYING: '应用中', PENDING_CONFIRM: '已应用，等待确认', ROLLING_BACK: '回滚中', FAILED: '失败', ROLLED_BACK: '已回滚',
    },
    reasons: { expected_restart: '按计划重启', unexpected_restart: '意外重启', wrong_version: '重启后版本不符', confirm_timeout: '超时未确认，已自动回滚', health_failed: '健康检查失败' },
    policies: { preferred: '优先使用后量子签名', required: '必须有后量子签名' },
    outcomes: { classical_only: '仅经典签名', dual_signed: '经典 + 后量子双签名' },
  },
  diag: {
    title: '诊断与日志', refresh: '刷新日志', download: '下载诊断包', logLabel: '设备日志',
    hint: '日志在写入时已脱敏；诊断包通过设备的脱敏导出接口生成，不包含管理密码、会话令牌、Wi-Fi 密码、短信内容、完整号码或设备私钥。',
    empty: '暂时没有日志。', downloaded: '诊断包已生成并开始下载。',
  },
  settings: {
    title: '管理设置', thisDevice: '仅此设备', changePassword: '修改管理密码', oldPassword: '原密码', newPassword: '新密码（至少 12 位）', confirmPassword: '确认新密码', savePassword: '保存新密码',
    passwordHint: '保存后其他管理会话全部失效。设备身份、NAS 配对和 SIM 数据保持不变。',
    deviceAndSoftware: '设备与软件', maintenance: '维护说明',
    maintenance1: '本后台常驻在设备的 HTTPS 服务上，通过 USB 或本机 Wi-Fi 地址均可访问。管理账户在持久存储中保存，重启后继续有效。',
    maintenance2: '通话和数据转发由 NAS 负责。Agent 更新由 NAS 推送，本后台只显示状态并可回滚未确认的更新。这里没有刷机、格式化、NV 修改或恢复出厂功能。',
    edl: 'UFI003 开机长按约 5 秒仍进入 Qualcomm 9008 / EDL，不作为恢复后台密码的手势。',
    deviceId: '设备 ID', model: '型号', agentVersion: 'Agent 版本', protocol: '协议', pairing: 'NAS 配对', address: '当前管理地址',
    changed: '管理密码已更新，其他管理会话已退出。',
    error: { oldEmpty: '请输入原密码', newShort: '新密码至少需要 12 位', newLong: '新密码最多 256 位', mismatch: '两次输入的新密码不一致' },
  },
};

const lookup = key => key.split('.').reduce((o, k) => (o == null ? undefined : o[k]), T);
function t(key, vars) {
  const s = lookup(key);
  if (typeof s !== 'string') return key;
  return vars ? s.replace(/\{(\w+)\}/g, (m, k) => (vars[k] === undefined ? m : String(vars[k]))) : s;
}
const $ = id => document.getElementById(id);
function applyStrings() {
  for (const e of document.querySelectorAll('[data-t]')) e.textContent = t(e.dataset.t);
  for (const e of document.querySelectorAll('[data-t-label]')) e.setAttribute('aria-label', t(e.dataset.tLabel));
  for (const e of document.querySelectorAll('[data-t-placeholder]')) e.setAttribute('placeholder', t(e.dataset.tPlaceholder));
}

// ---------------------------------------------------------------------------
// State. Nothing here is written to browser storage.
// ---------------------------------------------------------------------------
const REQUEST_TIMEOUT_MS = 45000;
const POLL_MS = 10000;
const SESSION_CHECK_MS = 60000;
const WIFI_WATCH_MS = 200000;
const SVG_NS = 'http://www.w3.org/2000/svg';

// The private setup shortcut carries ownership proof in the fragment. Remove
// it before any requests; never store it in browser storage or send it as a URL.
let setupCode = '';
if (location.hash) {
  const token = new URLSearchParams(location.hash.slice(1)).get('setup');
  if (token && /^[A-Za-z0-9_-]{43}$/.test(token)) setupCode = token;
  window.history.replaceState(null, '', location.pathname + location.search);
}
// pendingSMS keeps the request id of a send whose result is not known. It is
// reused only when the user sends the SAME message again by hand; nothing in
// this file ever repeats a send by itself.
let pendingSMS = null;
let auth = null, tab = 'overview', refreshing = false, poll = null, status = null, wifi = null, node = null, caps = null;
let wifiWatch = 0, updateShown = null;
// The setup access point passphrase is never held in a variable: it goes from
// the response into one element and is removed from there by hideSetupAP.
const AP_SHOWN_MS = 180000;
let apTimer = null, apRequest = 0;
const series = { cpu: [], memory: [], signal: [] };

const text = v => (v === undefined || v === null || v === '' ? '—' : String(v));
const known = v => (v === undefined || v === null || v === '' || v === 'unknown' ? T.unknown : String(v));
const bytes = v => {
  if (v === null || v === undefined || !Number.isFinite(Number(v))) return '—';
  const n = Number(v);
  return n < 1024 ? n.toFixed(0) + ' B' : n < 1048576 ? (n / 1024).toFixed(1) + ' KiB' : n < 1073741824 ? (n / 1048576).toFixed(1) + ' MiB' : (n / 1073741824).toFixed(2) + ' GiB';
};
const percent = v => (v == null ? '—' : Number(v).toFixed(1) + '%');
const age = v => {
  if (v == null) return '—';
  const n = Math.floor(v);
  return n >= 86400 ? t('overview.days', { d: Math.floor(n / 86400), h: Math.floor(n % 86400 / 3600) }) : n >= 3600 ? t('overview.hours', { h: Math.floor(n / 3600), m: Math.floor(n % 3600 / 60) }) : t('overview.minutes', { m: Math.floor(n / 60) });
};
const label = v => T.names[v] || text(v);
const operator = v => T.operators[v] || text(v);
const utf8Length = s => new TextEncoder().encode(s).length;
const hasControl = s => /[\u0000-\u001f\u007f-\u009f]/.test(s);
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
// present tells a value the device sent from one it left out. 0 and false are
// values; undefined, null and '' are not.
const present = v => v !== undefined && v !== null && v !== '' && !(typeof v === 'number' && !Number.isFinite(v));
// orUnknown formats what was sent and says "unknown" for what was not.
const orUnknown = (v, format) => (present(v) ? (format ? format(v) : String(v)) : T.unknown);
const size = v => orUnknown(v, bytes);
const rate = v => orUnknown(v, n => bytes(n) + '/s');
const mhz = v => orUnknown(v, n => (Number(n) / 1000).toFixed(0) + ' MHz');
const hexCode = v => '0x' + Number(v).toString(16).toUpperCase().padStart(2, '0');
// A zero Go time means "not set"; showing year 1 as a date would be a lie.
function when(value) {
  if (!value) return null;
  const d = new Date(value);
  return Number.isNaN(d.getTime()) || d.getFullYear() < 2000 ? null : d;
}

// ---------------------------------------------------------------------------
// DOM helpers. Text only: nothing from the device is ever parsed as markup.
// ---------------------------------------------------------------------------
function el(tag, content, className) {
  const e = document.createElement(tag);
  if (content !== undefined) e.textContent = text(content);
  if (className) e.className = className;
  return e;
}
function row(container, key, value, className) {
  const r = el('div', undefined, 'row');
  r.append(el('span', key), el('span', value, className));
  container.append(r);
}
function detail(container, key, value) {
  const d = el('div');
  d.append(el('small', key), el('b', value));
  container.append(d);
}
function notice(message, error = false) {
  if (!auth || !auth.authenticated) {
    $('login-error').textContent = message;
    $('login-error').hidden = !message || !error;
  }
  const n = $('notice');
  n.textContent = message;
  n.classList.toggle('error', error);
  // An error interrupts a screen reader; a confirmation waits its turn.
  n.setAttribute('role', error ? 'alert' : 'status');
  n.hidden = !message;
}
// setState gives a panel its loading / empty / error / unsupported line.
function setState(id, kind, message) {
  const e = $(id);
  e.className = 'state' + (kind ? ' ' + kind : '');
  e.textContent = kind ? message || t('state.' + kind) : '';
  e.setAttribute('role', kind === 'error' ? 'alert' : 'status');
  e.hidden = !kind;
  const page = e.closest('.page');
  if (page) page.setAttribute('aria-busy', kind === 'loading' ? 'true' : 'false');
}
async function load(stateId, fn) {
  setState(stateId, 'loading');
  try {
    await fn();
  } catch (err) {
    if (err.code === 'session_expired') return;
    setState(stateId, err.code === 'not_supported' || err.status === 501 ? 'unsupported' : 'error', err.message);
  }
}
function fieldError(id, message) {
  const input = $(id), box = $(id + '-error');
  if (box) {
    box.textContent = message || '';
    box.hidden = !message;
  }
  if (message) input.setAttribute('aria-invalid', 'true');
  else input.removeAttribute('aria-invalid');
  return !message;
}
// check runs every rule, marks every field, and focuses the first bad one.
function check(rules) {
  let first = null;
  for (const [id, message] of rules) {
    if (!fieldError(id, message) && !first) first = id;
  }
  if (first) $(first).focus();
  return !first;
}

// ---------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------
class ApiError extends Error {
  constructor(message, httpStatus, code) {
    super(message);
    this.status = httpStatus;
    this.code = code;
  }
}
// request sends exactly one request. There is no retry anywhere in this file:
// a timeout is reported to the person, who decides what to do next.
async function request(path, options = {}) {
  const controller = new AbortController(), timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  const headers = {};
  if (options.body !== undefined) headers['Content-Type'] = 'application/json';
  if (auth && auth.csrf) headers['X-CSRF-Token'] = auth.csrf;
  // Timer-driven requests say so, and the device does not count them as
  // activity: an unattended tab must not keep its own session alive.
  if (options.passive) headers['X-NSH-Passive'] = '1';
  try {
    const res = await fetch(path, {
      method: options.method || (options.body === undefined ? 'GET' : 'POST'), headers,
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
      credentials: 'same-origin', cache: 'no-store', redirect: 'error', referrerPolicy: 'no-referrer', signal: controller.signal,
    });
    if (res.ok && options.blob) return { blob: await res.blob(), disposition: res.headers.get('Content-Disposition') || '' };
    let data = {};
    try { data = await res.json(); } catch (ignored) { data = {}; }
    if (res.ok) return data || {};
    const inner = data && data.error;
    const code = inner && typeof inner === 'object' ? inner.code : data && data.code;
    let message = typeof inner === 'string' ? inner : (inner && inner.message) || '';
    if (code === 'session_expired') {
      expire(t('session.expired'));
      throw new ApiError(t('session.expired'), res.status, code);
    }
    if (inner && typeof inner === 'object') message = (T.apiCode[code] || T.apiCode.other) + (message ? '（' + message + '）' : '');
    const failure = new ApiError(message || t('error.http', { status: res.status }), res.status, code);
    // The trust state the device reported with a refusal, when it gave one.
    failure.state = data && typeof data.state === 'string' ? data.state : '';
    throw failure;
  } catch (err) {
    if (err instanceof ApiError) throw err;
    throw new ApiError(t(err && err.name === 'AbortError' ? 'error.timeout' : 'error.network'), 0, err && err.name === 'AbortError' ? 'timeout' : 'network');
  } finally {
    clearTimeout(timer);
  }
}
const api = (path, options) => request('/admin/api/v1/' + path, options);
// busy disables the control for the whole operation, so a second click or a
// second Enter cannot submit twice.
async function busy(button, fn) {
  if (!button || button.disabled) return;
  button.disabled = true;
  button.setAttribute('aria-busy', 'true');
  try {
    await fn();
  } catch (err) {
    if (err.code !== 'session_expired') notice(err.message, true);
  } finally {
    button.disabled = false;
    button.removeAttribute('aria-busy');
  }
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------
// wipe removes everything the device told us from memory and from the page.
// It runs on logout and on expiry, so a signed-out tab shows nothing.
let systemGeneration = 0;
function wipe() {
  systemGeneration++;
  $('system-users').replaceChildren();
  $('system-fingerprint').textContent = '';
  $('system-ssh-form').reset();
  $('system-account-form').reset();
  status = wifi = node = caps = pendingSMS = updateShown = null;
  wifiWatch++;
  clearTimeout(poll);
  for (const key of Object.keys(series)) series[key] = [];
  hideSetupAP();
  hideSMSBlock();
  for (const id of ['cards', 'telemetry', 'processes', 'interfaces', 'device-info', 'messages', 'networks', 'security-body', 'update-body', 'setup-ap-info']) $(id).replaceChildren();
  for (const id of ['logs', 'wifi-state', 'wifi-provisioning', 'scan-note', 'process-note', 'wifi-outcome', 'sample-time', 'sms-count', 'update-progress-text', 'session-policy', 'setup-ap-note']) $(id).textContent = '';
  for (const id of ['wifi-form', 'sms-form', 'password-form', 'login-form', 'setup-ap-form']) $(id).reset();
  for (const e of document.querySelectorAll('.field-error')) { e.textContent = ''; e.hidden = true; }
  for (const e of document.querySelectorAll('[aria-invalid]')) e.removeAttribute('aria-invalid');
  for (const e of document.querySelectorAll('.state')) { e.textContent = ''; e.hidden = true; }
  $('wifi-outcome').hidden = true;
  $('scan-note').hidden = true;
  $('setup-ap-body').hidden = true;
  $('update-card').hidden = true;
  $('rollback').hidden = true;
  notice('');
}
function showAuth() {
  const yes = !!(auth && auth.authenticated), configured = !!(auth && auth.configured);
  $('login').hidden = yes;
  $('workspace').hidden = !yes;
  $('nav').hidden = !yes;
  $('logout').hidden = !yes;
  $('refresh').hidden = !yes;
  $('title').textContent = t(yes ? 'title.signedIn' : 'title.signedOut');
  $('identity').textContent = auth ? [auth.model, auth.device_id].filter(Boolean).join(' · ') : t('connecting');
  $('footer-id').textContent = auth ? text(auth.device_id) : '';
  $('connection').textContent = t('connection.https');
  if (configured) setupCode = '';
  $('setup-label').hidden = configured || !!setupCode;
  $('setup-confirm-label').hidden = configured;
  $('setup-confirm').required = !configured;
  $('login-password').autocomplete = configured ? 'current-password' : 'new-password';
  $('login-title').textContent = t(configured ? 'login.welcome' : 'login.create');
  $('login-help').textContent = t(configured ? 'login.help' : setupCode ? 'login.helpProof' : 'login.helpNoProof');
  $('login-submit').textContent = t(configured ? 'login.submit' : 'login.submitCreate');
  if (auth && auth.idle_timeout_seconds) $('session-policy').textContent = yes ? t('session.policy', { idle: Math.round(auth.idle_timeout_seconds / 60), absolute: Math.round(auth.absolute_timeout_seconds / 3600) }) : '';
}
// expire is what the page does when the device says the session is gone.
function expire(message) {
  if (!auth || !auth.authenticated) return;
  auth = Object.assign({}, auth, { authenticated: false, csrf: '' });
  wipe();
  showAuth();
  const banner = $('session-ended');
  banner.textContent = message;
  banner.hidden = false;
  $('login-password').focus();
}
async function session() {
  auth = await request('/admin/session');
  if (!auth.authenticated) wipe();
  showAuth();
  if (auth.locked_seconds > 0) notice(t('session.locked', { seconds: auth.locked_seconds }), true);
  if (auth.authenticated) {
    $('session-ended').hidden = true;
    await switchTab(tab, false);
    await refresh(false);
  }
}
// The page asks now and then whether it is still signed in, so that an
// expired session clears the screen even if nobody touches it.
async function checkSession() {
  if (!auth || !auth.authenticated) return;
  try {
    const now = await request('/admin/session', { passive: true });
    if (!now.authenticated) expire(t('session.expired'));
  } catch (err) {
    $('connection').textContent = t('connection.bad');
  }
}

// ---------------------------------------------------------------------------
// Overview
// ---------------------------------------------------------------------------
function card(title, subtitle, value, details, series) {
  const c = el('article', undefined, 'card'), h = el('div', undefined, 'card-title');
  h.append(el('strong', title), el('span', subtitle));
  c.append(h, el('div', value, 'big'));
  if (series) {
    const svg = document.createElementNS(SVG_NS, 'svg');
    svg.setAttribute('viewBox', '0 0 300 65');
    svg.setAttribute('role', 'img');
    svg.setAttribute('aria-label', t('overview.trend', { title }));
    svg.classList.add('chart');
    for (const y of [10, 32, 55]) {
      const l = document.createElementNS(SVG_NS, 'line');
      l.setAttribute('x1', '0'); l.setAttribute('x2', '300'); l.setAttribute('y1', y); l.setAttribute('y2', y);
      svg.append(l);
    }
    const p = document.createElementNS(SVG_NS, 'polyline');
    p.setAttribute('points', series.map((n, i) => `${i * 300 / Math.max(1, series.length - 1)},${60 - Math.max(0, Math.min(100, n)) * .55}`).join(' '));
    svg.append(p);
    c.append(svg);
  }
  const ds = el('div', undefined, 'details');
  for (const [key, v] of details) detail(ds, key, v);
  c.append(ds);
  return c;
}
function push(key, v) {
  if (v == null) return;
  series[key].push(Number(v));
  if (series[key].length > 60) series[key].shift();
}
// provisioningText puts the backend's provisioning state into words. A state
// the device did not send is unknown; it is not assumed to be any of them.
function provisioningText(d) {
  const w = T.wifi, state = d && d.provisioning_state;
  let words = !state ? w.provisioningUnknown : w.provisioningStates[state] || t('wifi.provisioningOther', { state });
  if (d && d.provisioning_reason) words += t('wifi.reason', { reason: d.provisioning_reason });
  return words;
}
function renderWiFi() {
  $('wifi-state').textContent = wifi ? [label(wifi.state), wifi.ssid || wifi.ap_ssid, wifi.ipv4 || wifi.ap_address].filter(Boolean).join(' · ') : '';
  // The access point is offered beside a saved network, never instead of it.
  const kept = wifi && wifi.saved_ssid && wifi.provisioning_state && wifi.provisioning_state !== 'JOINED' ? ' ' + t('wifi.provisioningSaved', { saved: wifi.saved_ssid }) : '';
  $('wifi-provisioning').textContent = wifi ? t('wifi.provisioning', { state: provisioningText(wifi) }) + kept : '';
}
// eMMC wear registers are passed through as the manufacturer's codes, with
// what each code means beside it; they are not turned into a percentage the
// hardware never stated.
function lifeText(v) {
  if (!present(v)) return T.unknown;
  const n = Number(v), code = hexCode(n);
  if (n === 0) return t('tele.notReportedCode', { code });
  if (n >= 1 && n <= 10) return t('tele.lifeUsed', { code, from: (n - 1) * 10, to: n * 10 });
  if (n === 11) return t('tele.lifeExceeded', { code });
  return t('tele.reservedCode', { code });
}
function preEolText(v) {
  if (!present(v)) return T.unknown;
  const n = Number(v), code = hexCode(n);
  if (n === 0) return t('tele.notReportedCode', { code });
  return T.tele.preEolCodes[n] ? T.tele.preEolCodes[n].replace('{code}', code) : t('tele.reservedCode', { code });
}
function renderTelemetry(r, m) {
  const e = T.tele, cpu = r.cpu || {}, memory = r.memory || {}, emmc = r.emmc || {}, agent = r.agent || {}, cell = r.cell || {};
  const fixed = digits => n => Number(n).toFixed(digits);
  const cpuRows = [
    [e.model, orUnknown(cpu.model)], [e.coreCount, orUnknown(cpu.core_count)],
    [e.load, [cpu.load_1, cpu.load_5, cpu.load_15].map(v => orUnknown(v, fixed(2))).join(' / ') + '（' + e.loadHint + '）'],
  ];
  for (const core of cpu.cores || []) {
    cpuRows.push([t('tele.core', { index: core.index }), [
      core.online === true ? e.online : core.online === false ? e.offline : e.stateUnknown,
      t('tele.frequency', { current: mhz(core.current_khz), min: mhz(core.min_khz), max: mhz(core.max_khz) }),
      t('tele.utilisation', { percent: orUnknown(core.percent, n => fixed(1)(n) + '%') }),
    ].join(' · ')]);
  }
  if (!(cpu.cores || []).length) cpuRows.push([e.cores, T.unknown]);
  // A zone is named by the kernel's own type for it. Nothing here decides
  // which zone is "the CPU".
  const zoneRows = (r.thermal_zones || []).map(z => [z.type ? t('tele.zoneTyped', { type: z.type, zone: z.zone }) : t('tele.zoneUntyped', { zone: z.zone }), orUnknown(z.celsius, n => fixed(1)(n) + ' °C')]);
  if (!zoneRows.length) zoneRows.push([e.zones, T.unknown]);
  const memoryRows = [[e.memTotal, size(memory.total_bytes)], [e.memAvailable, size(memory.available_bytes)], [e.memFree, size(memory.free_bytes)], [e.memBuffers, size(memory.buffers_bytes)],
    [e.memCached, size(memory.cached_bytes)], [e.swapTotal, size(memory.swap_total_bytes)], [e.swapFree, size(memory.swap_free_bytes)]];
  const storage = r.storage || [], storageRows = [];
  const storageRow = s => [t('tele.storageWhere', { role: e.roles[s.role] || t('tele.roleOther', { role: s.role }), path: orUnknown(s.path), fs: s.fs_type || e.fsUnknown }),
    t('tele.storageValue', { used: size(s.used_bytes), total: size(s.total_bytes), available: size(s.available_bytes), free: size(s.free_bytes) })];
  for (const role of ['state', 'root']) {
    const found = storage.filter(s => s.role === role);
    if (!found.length) storageRows.push([e.roles[role], T.unknown]);
    for (const s of found) storageRows.push(storageRow(s));
  }
  for (const s of storage) if (s.role !== 'state' && s.role !== 'root') storageRows.push(storageRow(s));
  const observed = when(cell.observed_at);
  $('telemetry').replaceChildren(
    panel(e.cpu, cpuRows), panel(e.thermal, zoneRows), panel(e.memory, memoryRows), panel(e.storage, storageRows),
    panel(e.emmc, [[e.emmcDevice, orUnknown(emmc.device)], [e.lifeA, lifeText(emmc.life_time_est_a)], [e.lifeB, lifeText(emmc.life_time_est_b)], [e.preEol, preEolText(emmc.pre_eol)]]),
    panel(e.agent, [[e.pid, orUnknown(agent.pid)], [e.rss, size(agent.rss_bytes)], [e.agentCpu, orUnknown(agent.cpu_percent, n => fixed(1)(n) + '%')]]),
    panel(e.cell, [[e.band, orUnknown(cell.band)], [e.earfcn, orUnknown(cell.earfcn)], [e.pci, orUnknown(cell.pci)], [e.tac, orUnknown(cell.tac)], [e.cellId, orUnknown(cell.cell_id)],
      [e.cellTime, r.cell && observed ? observed.toLocaleString() : T.unknown]]),
    panel(e.system, [[e.threads, orUnknown(r.thread_count)], [e.bootId, orUnknown(r.boot_id), true]]),
  );
  $('process-note').textContent = r.process_scan_truncated === true ? T.overview.processesTruncated : '';
  // Interfaces: the typed list carries rates; an older agent sends only the
  // totals in the free-form map, and then the rates are unknown, not zero.
  const ni = $('interfaces');
  ni.replaceChildren();
  for (const i of r.interfaces || m.interfaces || []) {
    row(ni, i.name, [
      t('tele.ifaceRate', { rx: rate(i.rx_bytes_per_second), tx: rate(i.tx_bytes_per_second) }), t('tele.ifaceTotal', { rx: size(i.rx_bytes), tx: size(i.tx_bytes) }),
      t('tele.ifacePackets', { rx: orUnknown(i.rx_packets), tx: orUnknown(i.tx_packets) }), t('tele.ifaceErrors', { rx: orUnknown(i.rx_errors), tx: orUnknown(i.tx_errors) }),
    ].join(' · '));
  }
  if (!ni.children.length) ni.append(el('p', T.unknown, 'hint'));
}
function render() {
  if (!auth || !auth.authenticated) return;
  const s = status || {}, r = s.resources || {}, m = r.metrics || {}, sig = s.signal || {}, sim = s.sim || {}, n = s.network || {};
  const memory = r.memory_total_bytes ? 100 * (1 - r.memory_available_bytes / r.memory_total_bytes) : null;
  const o = T.overview;
  push('cpu', r.cpu_percent); push('memory', memory); push('signal', sig.known ? (sig.bars || 0) * 20 : null);
  $('sample-time').textContent = t('overview.sampled', { time: r.observed_at ? new Date(r.observed_at).toLocaleTimeString() : o.notSampled });
  $('identity').textContent = [(node && node.model) || auth.model, auth.device_id, operator(n.operator_name || sim.operator_name)].filter(v => v && v !== '—').join(' · ');
  const cards = $('cards');
  cards.replaceChildren();
  cards.append(card(o.cpu, m.cpu_model_name || o.cpuLocal, percent(r.cpu_percent), [[o.cpuTemp, m.cpu_temp_celsius == null ? T.notReported : Number(m.cpu_temp_celsius).toFixed(1) + ' °C'], [o.coresProcesses, t('overview.cores', { cores: text(m.cores), processes: text(r.process_count) })]], series.cpu));
  cards.append(card(o.memoryCard, bytes(r.memory_total_bytes), percent(memory), [[o.used, r.memory_total_bytes ? bytes(r.memory_total_bytes - r.memory_available_bytes) : '—'], [o.free, bytes(r.memory_available_bytes)]], series.memory));
  cards.append(card(o.storage, m.flash_fs_type || o.deviceStorage, percent(m.flash_used_percent), [[o.total, bytes(m.flash_total_bytes)], [o.remaining, bytes(m.flash_free_bytes)]]));
  cards.append(card(o.modem, [n.operator_code, label(n.access_technology)].filter(v => v && v !== '—').join(' · '), label(n.registration), [['RSRP', sig.rsrp == null ? '—' : sig.rsrp + ' dBm'], ['SINR', sig.snr == null ? '—' : sig.snr + ' dB']], series.signal));
  cards.append(card(o.sim, operator(sim.operator_name), label(sim.state), [[o.phone, sim.phone_number || o.phoneMissing], ['ICCID', sim.iccid ? '••••' + sim.iccid.slice(-4) : '—']]));
  cards.append(card(o.wifi, (wifi && (wifi.ssid || wifi.ap_ssid)) || 'Wi-Fi', wifi ? label(wifi.state) : T.unknown, [[o.wifiAddress, (wifi && (wifi.ipv4 || wifi.ap_address)) || '—'], [o.saved, (wifi && wifi.saved_ssid) || o.notConfigured]]));
  cards.append(card(o.system, auth.device_id, age(r.uptime_seconds), [[o.version, auth.version], [o.pairing, node ? label(node.pairing_state) : T.unknown]]));
  cards.append(card(o.voice, o.voiceSource, !caps ? T.unknown : caps.voice_audio ? o.audioReady : o.audioNotReady, [[o.smsCapability, !caps ? T.unknown : caps.sms ? o.available : o.unavailable], [o.volte, caps ? label(caps.volte) : T.unknown]]));
  const p = $('processes');
  p.replaceChildren();
  for (const proc of r.processes || []) {
    const tr = el('tr');
    tr.append(el('td', proc.pid), el('td', proc.name), el('td', bytes(proc.rss_bytes)));
    p.append(tr);
  }
  if (!p.children.length) {
    const tr = el('tr'), td = el('td', T.notReported);
    td.colSpan = 3;
    tr.append(td);
    p.append(tr);
  }
  renderTelemetry(r, m);
  const info = $('device-info'), st = T.settings;
  info.replaceChildren();
  for (const [k, v] of [[st.deviceId, auth.device_id], [st.model, auth.model], [st.agentVersion, auth.version], [st.protocol, node ? node.protocol : T.unknown], [st.pairing, node ? label(node.pairing_state) : T.unknown], [st.address, location.origin]]) row(info, k, v);
  renderWiFi();
}
// refresh reads the overview. Each optional document fails by itself: a
// device with no Wi-Fi backend still shows its modem.
async function refresh(passive) {
  if (refreshing || !auth || !auth.authenticated) return;
  refreshing = true;
  if (!status) setState('overview-state', 'loading');
  try {
    status = await api('status', { passive });
    const optional = async (current, path) => { if (current) return current; try { return await api(path, { passive }); } catch (err) { if (err.code === 'session_expired') throw err; return null; } };
    wifi = await optional(wifi, 'wifi');
    node = await optional(node, 'node');
    caps = await optional(caps, 'capabilities');
    setState('overview-state', status.resources ? null : 'empty', T.notReported);
    setState('settings-state', null);
    render();
    $('connection').textContent = t('connection.ok');
  } catch (err) {
    if (err.code !== 'session_expired') {
      setState('overview-state', 'error', err.message);
      setState('settings-state', 'error', err.message);
      // What is still on the page is the last answer, and is labelled as such.
      if (status) {
        const sampled = when(status.resources && status.resources.observed_at);
        $('sample-time').textContent = t('overview.stale', { time: sampled ? sampled.toLocaleTimeString() : T.unknown });
      }
      $('connection').textContent = t('connection.bad');
    }
  } finally {
    refreshing = false;
    clearTimeout(poll);
    if (auth && auth.authenticated) poll = setTimeout(tick, POLL_MS);
  }
}
function tick() {
  if (!auth || !auth.authenticated) return;
  if (!document.hidden && tab === 'overview') refresh(true);
  else poll = setTimeout(tick, POLL_MS);
}

// ---------------------------------------------------------------------------
// Tabs
// ---------------------------------------------------------------------------
async function switchTab(next, focus = true) {
  tab = next;
  // Leaving the Wi-Fi page closes the access point section, and with it the
  // passphrase if it was showing.
  hideSetupAP();
  for (const page of document.querySelectorAll('.page')) page.hidden = page.id !== next;
  for (const b of document.querySelectorAll('[data-tab]')) {
    const selected = b.dataset.tab === next;
    b.classList.toggle('selected', selected);
    if (selected) b.setAttribute('aria-current', 'page');
    else b.removeAttribute('aria-current');
  }
  notice('');
  const heading = document.querySelector('#' + next + ' h2');
  if (focus && heading) heading.focus();
  if (next === 'system') await loadSystem();
  if (next === 'wifi') await loadWiFi();
  if (next === 'sms') await loadSMS();
  if (next === 'security') await loadSecurity();
  if (next === 'update') await loadUpdate();
  if (next === 'diagnostics') await loadLogs();
}

// ---------------------------------------------------------------------------
// Wi-Fi
// ---------------------------------------------------------------------------
function wifiProblems() {
  const ssid = $('ssid').value, security = $('wifi-security').value, psk = $('psk').value, e = T.wifi.error;
  let ssidError = '', pskError = '';
  if (!ssid.trim()) ssidError = e.ssidEmpty;
  else if (utf8Length(ssid) > 32) ssidError = t('wifi.error.ssidLong', { bytes: utf8Length(ssid) });
  else if (hasControl(ssid)) ssidError = e.ssidControl;
  if (security !== 'open') {
    const length = utf8Length(psk);
    if (!psk) pskError = e.pskEmpty;
    else if (hasControl(psk)) pskError = e.pskControl;
    else if (length === 64) pskError = security !== 'wpa2' ? e.pskHexWpa3 : /^[0-9A-Fa-f]{64}$/.test(psk) ? '' : e.pskHex;
    else if (length < 8) pskError = e.pskShort;
    else if (length > 63) pskError = e.pskLong;
  }
  return [['ssid', ssidError], ['psk', pskError]];
}
function showOutcome(o) {
  const banner = $('wifi-outcome'), w = T.wifi.outcome;
  if (!o || o.outcome === 'none') { banner.hidden = true; banner.textContent = ''; return; }
  const saved = o.saved_ssid ? t('wifi.outcome.savedKept', { saved: o.saved_ssid }) : w.savedNone;
  const vars = {
    target: o.target_ssid || '', previous: o.previous_ssid || T.unknown, ap: o.ap_ssid || T.unknown, address: o.ap_address ? '（' + o.ap_address + '）' : '',
    reason: o.failure_reason ? '（' + o.failure_reason + '）' : '', elapsed: o.elapsed_seconds, window: o.window_seconds, saved,
  };
  let key = o.outcome;
  if (key === 'not_connected' && !o.settled) key = 'not_connected_waiting';
  if (key === 'provisioning_ap' && !o.target_ssid) key = 'provisioning_ap_forgotten';
  let message = t('wifi.outcome.' + (w[key] ? key : 'unknown'), vars);
  // Where the device says it stands, when it says so and the join is over.
  if (o.provisioning_state && !['pending', 'connected'].includes(key)) message += ' ' + t('wifi.provisioning', { state: provisioningText(o) });
  banner.textContent = message;
  banner.classList.toggle('error', !['pending', 'connected', 'forgotten', 'provisioning_ap_forgotten'].includes(key));
  banner.hidden = false;
}
function outcomeBanner(message, error) {
  const banner = $('wifi-outcome');
  banner.textContent = message;
  banner.classList.toggle('error', !!error);
  banner.hidden = false;
}
// watchWiFi follows a change until the device says what became of it. It only
// reads; it never submits the change again.
async function watchWiFi() {
  const token = ++wifiWatch, started = Date.now();
  let lost = false;
  while (token === wifiWatch && auth && auth.authenticated) {
    await sleep(3000);
    if (token !== wifiWatch || !auth || !auth.authenticated) return;
    try {
      const o = await api('wifi/change', { passive: true });
      lost = false;
      showOutcome(o);
      if (o.settled) {
        try { wifi = await api('wifi', { passive: true }); render(); } catch (ignored) { /* the banner already says what happened */ }
        return;
      }
    } catch (err) {
      if (err.code === 'session_expired') return;
      lost = true;
      outcomeBanner(T.wifi.outcome.lost, true);
    }
    if (Date.now() - started > WIFI_WATCH_MS) {
      outcomeBanner(lost ? T.wifi.outcome.lostFinal : T.wifi.outcome.unknown, true);
      return;
    }
  }
}
// hideSetupAP removes the passphrase from the page and closes the form. It
// also abandons a reveal that is still on its way, so an answer that arrives
// after the section was closed is dropped instead of displayed.
function hideSetupAP(message) {
  apRequest++;
  clearTimeout(apTimer);
  apTimer = null;
  $('setup-ap-passphrase').textContent = '';
  $('setup-ap-secret').hidden = true;
  $('setup-ap-hide').hidden = true;
  $('setup-ap-form').hidden = true;
  $('setup-ap-form').reset();
  fieldError('setup-ap-password', '');
  $('setup-ap-show').hidden = false;
  $('setup-ap-note').textContent = message || '';
}
async function loadSetupAP() {
  const a = T.wifi.ap, info = $('setup-ap-info');
  hideSetupAP();
  $('setup-ap-body').hidden = true;
  info.replaceChildren();
  await load('setup-ap-state', async () => {
    const d = await api('wifi/setup-ap');
    if (!d.available) {
      if (d.reason === 'unavailable') setState('setup-ap-state', 'error', a.unavailable);
      else setState('setup-ap-state', 'unsupported', d.reason === 'access_point_off' ? a.off : a.noSource);
      return;
    }
    row(info, a.ssid, orUnknown(d.ssid), 'mono');
    row(info, a.state, provisioningText(d));
    $('setup-ap-body').hidden = false;
    setState('setup-ap-state', null);
  });
}
async function revealSetupAP() {
  const password = $('setup-ap-password').value;
  if (!check([['setup-ap-password', password ? '' : T.wifi.ap.needPassword]])) return;
  // The management password leaves the page as soon as it has been read.
  $('setup-ap-form').reset();
  const mine = ++apRequest;
  let d;
  try {
    d = await api('wifi/setup-ap/reveal', { body: { current_password: password } });
  } catch (err) {
    if (err.code === 'session_expired' || mine !== apRequest) return;
    if (err.code === 'not_supported' || err.code === 'access_point_off') { await loadSetupAP(); return; }
    fieldError('setup-ap-password', err.message);
    $('setup-ap-password').focus();
    return;
  }
  // Closed, signed out or expired while the device was answering.
  if (mine !== apRequest || tab !== 'wifi' || !auth || !auth.authenticated) return;
  $('setup-ap-form').hidden = true;
  $('setup-ap-show').hidden = true;
  $('setup-ap-passphrase').textContent = d.passphrase;
  $('setup-ap-secret').hidden = false;
  $('setup-ap-hide').hidden = false;
  $('setup-ap-note').textContent = t('wifi.ap.shown', { seconds: AP_SHOWN_MS / 1000 });
  apTimer = setTimeout(() => hideSetupAP(T.wifi.ap.cleared), AP_SHOWN_MS);
  $('setup-ap-hide').focus();
}
async function loadWiFi() {
  $('wifi-card').hidden = false;
  await load('wifi-state-panel', async () => {
    try {
      wifi = await api('wifi');
    } catch (err) {
      if (err.code === 'not_supported' || err.status === 501) $('wifi-card').hidden = true;
      throw err;
    }
    setState('wifi-state-panel', null);
    renderWiFi();
    const o = await api('wifi/change');
    showOutcome(o);
    if (!o.settled) watchWiFi();
  });
  // The access point section answers by itself: a device whose Wi-Fi cannot
  // be configured from here still says that it has no access point.
  await loadSetupAP();
}
function togglePSK() {
  const open = $('wifi-security').value === 'open';
  $('psk-label').hidden = open;
  if (open) { $('psk').value = ''; fieldError('psk', ''); }
}

// ---------------------------------------------------------------------------
// SMS
// ---------------------------------------------------------------------------
const smsNumber = () => $('sms-number').value.replace(/[\s\-()]/g, '');
function smsProblems() {
  const to = smsNumber(), body = $('sms-text').value, e = T.sms.error;
  return [
    ['sms-number', !to ? e.toEmpty : /^\+?[0-9]{3,20}$/.test(to) ? '' : e.toInvalid],
    ['sms-text', !body.trim() ? e.textEmpty : utf8Length(body) > 4096 ? t('sms.error.textLong', { bytes: utf8Length(body) }) : ''],
  ];
}
function newRequestID() {
  if (crypto.randomUUID) return crypto.randomUUID();
  const raw = crypto.getRandomValues(new Uint8Array(16));
  return Array.from(raw, b => b.toString(16).padStart(2, '0')).join('');
}
// The explanation shown when the device refuses this page's own send.
//
// It is filled only from what the device said: the code of a refused send, or
// send_sms_block from the trust page, plus the trust state the NAS gave. The
// page never decides that sending is or is not allowed, never disables the
// send button on its own judgement, and never sends again by itself: the
// draft stays where it is and the person presses the button.
function smsBlockEntry(code, state) {
  const b = T.sms.block;
  if (code === 'trust_denied' && b[state] && typeof b[state] === 'object') return b[state];
  return b[code] && typeof b[code] === 'object' ? b[code] : b.trust_denied;
}
function showSMSBlock(code, state, afterSend) {
  const entry = smsBlockEntry(code, state);
  $('sms-block-title').textContent = entry.title;
  $('sms-block-text').textContent = entry.text;
  $('sms-block-recover').textContent = entry.recover;
  $('sms-block-draft').textContent = afterSend || $('sms-text').value ? T.sms.block.draftKept : T.sms.block.draftNone;
  $('sms-block').dataset.code = code;
  $('sms-block').dataset.state = state || '';
  $('sms-block').hidden = false;
}
function hideSMSBlock() {
  for (const id of ['sms-block-title', 'sms-block-text', 'sms-block-recover', 'sms-block-draft']) $(id).textContent = '';
  delete $('sms-block').dataset.code;
  delete $('sms-block').dataset.state;
  $('sms-block').hidden = true;
}
// refreshSMSBlock asks the device for its policy and shows or clears the
// explanation accordingly. It reports 'blocked', 'clear' or 'unknown'. When
// the policy cannot be read an explanation already on screen is left alone:
// "could not ask" is not "allowed".
async function refreshSMSBlock() {
  let d;
  try {
    d = await api('trust');
  } catch (err) {
    return 'unknown';
  }
  if (d && d.send_sms_allowed === false && typeof d.send_sms_block === 'string' && d.send_sms_block) {
    showSMSBlock(d.send_sms_block, typeof d.state === 'string' ? d.state : '', false);
    return 'blocked';
  }
  if (d && d.send_sms_allowed === true) {
    hideSMSBlock();
    return 'clear';
  }
  return 'unknown';
}
async function loadSMS() {
  const list = $('messages');
  $('sms-card').hidden = !!(caps && caps.sms === false);
  await refreshSMSBlock();
  await load('sms-state', async () => {
    const data = await api('sms');
    list.replaceChildren();
    for (const msg of [...(data.messages || [])].reverse()) {
      const c = el('article', undefined, 'card'), head = el('div', undefined, 'message-head'), left = el('div');
      left.append(el('strong', msg.peer || T.sms.unknownPeer), el('small', label(msg.direction) + ' · ' + (msg.timestamp ? new Date(msg.timestamp).toLocaleString() : label(msg.state))));
      const del = el('button', T.sms.remove, 'quiet');
      del.type = 'button';
      del.addEventListener('click', () => busy(del, async () => {
        if (!confirm(T.sms.confirmRemove)) return;
        await api('sms/' + encodeURIComponent(msg.id), { method: 'DELETE' });
        await loadSMS();
      }));
      head.append(left, del);
      c.append(head, el('div', msg.text || msg.body || '', 'message'));
      list.append(c);
    }
    setState('sms-state', list.children.length ? null : 'empty', caps && caps.sms === false ? T.sms.unsupported : T.sms.empty);
  });
}

// ---------------------------------------------------------------------------
// Security (read-only)
// ---------------------------------------------------------------------------
function panel(title, rows) {
  const c = el('article', undefined, 'card');
  c.append(el('h3', title));
  for (const [key, value, mono] of rows) row(c, key, value, mono ? 'mono' : undefined);
  return c;
}
const tri = v => (v === 'yes' ? T.yes : v === 'no' ? T.no : T.unknown);
async function loadSecurity() {
  const body = $('security-body'), s = T.security;
  await load('security-state', async () => {
    const d = await api('security');
    const pq = d.pq_identity || {}, owner = d.owner || {}, cert = d.admin_tls || {};
    const active = pq.status === 'active', paired = owner.paired === 'yes', pinned = owner.pq_pinned === 'yes';
    // "Not paired" and "not active" are answers. Anything else missing is unknown.
    const ownerValue = v => (paired ? known(v) : owner.paired === 'no' ? s.notPaired : T.unknown);
    const pqValue = v => (active ? known(v) : pq.status && pq.status !== 'unknown' ? s.notActive : T.unknown);
    const pinValue = v => (pinned ? known(v) : owner.pq_pinned === 'no' ? T.none : T.unknown);
    const until = when(cert.not_after), from = when(cert.not_before);
    let untilText = T.unknown;
    if (until) {
      const days = Math.floor((until.getTime() - Date.now()) / 86400000);
      untilText = until.toLocaleString() + (days < 0 ? s.certExpired : t('security.certLeft', { days }));
    }
    body.replaceChildren(
      panel(s.identity, [[s.deviceId, known(d.device_id), true], [s.algorithm, known(d.identity_algorithm)], [s.fingerprint, known(d.identity_fingerprint), true]]),
      panel(s.protection, [
        [s.level, s.levels[d.security_level] || known(d.security_level)], [s.pqStatus, s.pq[pq.status] || known(pq.status)],
        [s.pqAlgorithm, pqValue(pq.algorithm)], [s.pqFingerprint, pqValue(pq.fingerprint), true],
        ...(pq.detail ? [[s.pqDetail, pq.detail]] : []), [s.pqPolicy, s.policies[pq.policy] || known(pq.policy)],
      ]),
      panel(s.owner, [
        [s.paired, tri(owner.paired)], [s.coreId, ownerValue(owner.core_id), true], [s.coreFingerprint, ownerValue(owner.core_fingerprint), true],
        [s.corePq, paired ? tri(owner.pq_pinned) : ownerValue('')], [s.corePqAlgorithm, paired ? pinValue(owner.pq_algorithm) : ownerValue('')], [s.corePqFingerprint, paired ? pinValue(owner.pq_fingerprint) : ownerValue(''), true],
      ]),
      panel(s.certificate, [[s.certFingerprint, known(cert.fingerprint_sha256), true], [s.certKey, known(cert.key_algorithm)], [s.certFrom, from ? from.toLocaleString() : T.unknown], [s.certUntil, untilText]]),
    );
    setState('security-state', null);
  });
  // Appended separately: a failure to read the trust state must not blank the
  // identity panels above, and must not read as "unrestricted" either.
  const fresh = await trustPanel(), previous = body.querySelector('[data-panel="trust"]');
  fresh.dataset.panel = 'trust';
  if (previous) previous.remove();
  body.append(fresh);
}
async function trustPanel() {
  const s = T.security.trust;
  let d;
  try { d = await api('trust'); } catch (err) { return panel(s.title, [[s.status, s.readFailed], ['', s.owner]]); }
  if (!d || d.supported !== true) return panel(s.title, [[s.status, s.unsupported]]);
  if (!d.installed) return panel(s.title, [[s.status, s.notInstalled], ['', s.owner]]);
  const until = when(d.expires_at);
  const denied = Array.isArray(d.deny) && d.deny.length ? d.deny.map(a => s.actions[a] || text(a)).join('、') : s.nothingDenied;
  const status = d.damaged ? s.damaged : d.stale ? (d.freshness === 'stale_restart' ? s.staleRestart : s.stale) : d.enforcing ? s.enforcing : s.monitoring;
  return panel(s.title, [
    [s.status, status], [s.state, d.damaged && !d.state ? T.unknown : s.states[d.state] || known(d.state)], [s.denied, denied],
    [s.reason, d.reason ? d.reason : T.none], [s.mode, s.modes[d.mode] || known(d.mode)], [s.generation, known(d.generation)],
    [s.expires, until ? until.toLocaleString() + (d.stale && !d.damaged && d.freshness !== 'stale_restart' ? s.expired : '') : T.unknown],
    [s.sms, d.send_sms_allowed === true ? s.smsAllowed : d.send_sms_allowed === false ? s.smsRefused : T.unknown], ['', s.owner],
  ]);
}

// ---------------------------------------------------------------------------
// Updates (read-only, plus rollback of an unconfirmed update)
// ---------------------------------------------------------------------------
function renderUpdate(d) {
  const u = T.update, body = $('update-body'), s = d.status || {};
  updateShown = null;
  body.replaceChildren();
  $('rollback').hidden = true;
  $('rollback-help').hidden = true;
  $('update-progress-wrap').hidden = true;
  $('update-card').hidden = true;
  if (!d.available) { setState('update-state', 'unsupported', u.unsupportedBuild); return; }
  $('update-card').hidden = false;
  // An unsupported device still has versions worth showing, so the rows stay.
  setState('update-state', s.supported ? null : 'unsupported', s.unsupported_reason ? t('update.unsupported', { reason: s.unsupported_reason }) : u.unsupportedNoReason);
  const sig = s.signatures || {}, keys = s.keys || {}, deadline = when(s.confirm_deadline), updated = when(s.updated_at);
  const rows = [
    [u.running, known(s.current_version)], [u.factory, known(s.factory_version)], [u.active, s.active_release || u.factoryAgent],
    [u.state, u.states[s.state] || known(s.state)], [u.target, s.target_version || T.none], [u.release, s.release_id || T.none], [u.previous, s.previous_version || T.none],
    [u.deadline, deadline ? deadline.toLocaleString() : T.none], [u.lastError, s.error || T.none], [u.restartReason, s.restart_reason ? u.reasons[s.restart_reason] || s.restart_reason : T.none],
    [u.attempts, text(s.attempts)], [u.restartPending, s.restart_pending ? T.yes : T.no],
    [u.supported, s.supported ? T.yes : T.no + (s.unsupported_reason ? '（' + s.unsupported_reason + '）' : '')],
    [u.policy, u.policies[sig.policy] || known(sig.policy)], [u.outcome, sig.outcome ? u.outcomes[sig.outcome] || sig.outcome : T.none],
    [u.pqAvailable, sig.pq_available === true ? T.yes : sig.pq_available === false ? T.no : T.unknown], ...(sig.requires_toolchain ? [[u.toolchain, sig.requires_toolchain]] : []),
    [u.keys, t('update.keysText', { classical: text(keys.classical), pq: text(keys.post_quantum) })], [u.updatedAt, updated ? updated.toLocaleString() : T.unknown],
  ];
  for (const [key, value] of rows) row(body, key, value);
  if (s.expected_bytes > 0) {
    const pct = Math.max(0, Math.min(100, Math.floor(100 * s.received_bytes / s.expected_bytes)));
    $('update-progress').value = pct;
    $('update-progress-text').textContent = t('update.transferText', { received: bytes(s.received_bytes), expected: bytes(s.expected_bytes), percent: pct });
    $('update-progress-wrap').hidden = false;
  }
  if (d.can_rollback) {
    updateShown = { release: s.release_id, version: s.target_version || s.current_version || '', previous: s.previous_version || '' };
    $('rollback').hidden = false;
    $('rollback-help').hidden = false;
  }
}
async function loadUpdate() {
  await load('update-state', async () => renderUpdate(await api('update')));
}

// ---------------------------------------------------------------------------
// Diagnostics
// ---------------------------------------------------------------------------
async function loadLogs() {
  await load('diagnostics-state', async () => {
    const data = await api('logs?limit=200'), records = data.records || [];
    $('logs').textContent = records.map(r => new Date(r.time).toLocaleTimeString() + '  ' + String(r.level).toUpperCase() + '  ' + r.source + '  ' + r.message).join('\n');
    setState('diagnostics-state', records.length ? null : 'empty', T.diag.empty);
  });
}
async function downloadDiagnostics() {
  // Fetched rather than navigated to, so an expired session is noticed here
  // instead of saving an error message as a .tar.gz.
  const got = await api('diagnostics/archive', { blob: true });
  const named = /filename="([A-Za-z0-9._-]+)"/.exec(got.disposition);
  const link = el('a'), href = URL.createObjectURL(got.blob);
  link.href = href;
  link.download = named ? named[1] : 'nassimhub-diagnostics.tar.gz';
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(href), 60000);
  notice(T.diag.downloaded);
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------
applyStrings();
$('title').textContent = t('title.signedOut');
$('identity').textContent = t('connecting');

$('login-form').addEventListener('submit', e => {
  e.preventDefault();
  busy($('login-submit'), async () => {
    const password = $('login-password').value, l = T.login;
    if (!auth) throw new Error(t('error.network'));
    if (!auth.configured && !setupCode && !$('setup-code').value.trim()) throw new Error(l.needProof);
    if (!password) throw new Error(l.needPassword);
    if (password.length > 256) throw new Error(l.tooLong);
    if (!auth.configured && password.length < 12) throw new Error(l.tooShort);
    if (!auth.configured && password !== $('setup-confirm').value) throw new Error(l.mismatch);
    await request('/admin/login', { body: { password, setup_code: setupCode || $('setup-code').value.trim() } });
    setupCode = '';
    $('login-form').reset();
    $('session-ended').hidden = true;
    notice('');
    tab = 'overview';
    await session();
    $('main').focus();
  });
});
for (const b of document.querySelectorAll('[data-tab]')) b.addEventListener('click', () => switchTab(b.dataset.tab).catch(err => notice(err.message, true)));
$('refresh').addEventListener('click', () => busy($('refresh'), async () => {
  wifi = node = caps = null;
  await refresh(false);
  if (tab !== 'overview') await switchTab(tab, false);
}));
$('logout').addEventListener('click', () => busy($('logout'), async () => {
  try {
    await request('/admin/logout', { body: {} });
  } finally {
    // Whatever the device answered, this tab forgets everything.
    expire(t('session.loggedOut'));
  }
}));
$('scan').addEventListener('click', () => busy($('scan'), async () => {
  const list = $('networks');
  setState('networks-state', 'loading');
  let d;
  try { d = await api('wifi/scan', { body: {} }); } catch (err) { setState('networks-state', err.code === 'session_expired' ? null : 'error', err.message); return; }
  list.replaceChildren();
  // A list taken before the access point came up is old, and says so.
  const scanned = when(d.scanned_at), note = $('scan-note'), sup = T.wifi.support;
  note.textContent = d.from_cache === true ? t('wifi.cached', { time: scanned ? scanned.toLocaleString() : T.wifi.cachedTimeUnknown }) : '';
  note.hidden = d.from_cache !== true;
  for (const n of d.networks || []) {
    // Every network is listed whatever its support: leaving one out would
    // read as "the device cannot see it". One that cannot be joined is shown
    // and is simply not a button.
    const blocked = n.support === 'unsupported';
    const b = el(blocked ? 'div' : 'button', undefined, 'network' + (n.support === 'verified' || !n.support ? '' : ' ' + n.support));
    const kinds = [];
    if (n.support === 'unverified' && n.channel > 14) kinds.push(sup.band5);
    if (n.support === 'unverified' && n.security === 'wpa3') kinds.push(sup.wpa3);
    if (n.support === 'unverified' && n.security === 'open') kinds.push(sup.open);
    if (blocked && /802\.1X|enterprise/i.test(n.support_reason || '')) kinds.push(sup.enterprise);
    // The device's own sentence stays in brackets, as its reason.
    const mark = (sup[n.support] || sup.unknown) + (kinds.length ? ' · ' + kinds.join('、') : '') + (n.support_reason ? '（' + n.support_reason + '）' : '') + (blocked ? ' · ' + T.wifi.notSelectable : '');
    b.append(el('strong', n.ssid), el('small', String(n.security || '').toUpperCase() + ' · ' + n.signal_dbm + ' dBm' + (n.channel ? ' · ' + t('wifi.channel', { channel: n.channel }) : '')), el('small', mark, 'support'));
    if (!blocked) {
      b.type = 'button';
      b.addEventListener('click', () => {
        $('ssid').value = n.ssid;
        $('wifi-security').value = ['wpa2', 'wpa3', 'open'].includes(n.security) ? n.security : 'wpa2';
        togglePSK();
        ($('wifi-security').value === 'open' ? $('wifi-submit') : $('psk')).focus();
      });
    }
    list.append(b);
  }
  setState('networks-state', list.children.length ? null : 'empty', T.wifi.noNetworks);
}));
$('wifi-security').addEventListener('change', togglePSK);
$('setup-ap-show').addEventListener('click', () => {
  $('setup-ap-note').textContent = '';
  $('setup-ap-show').hidden = true;
  $('setup-ap-form').hidden = false;
  $('setup-ap-password').focus();
});
$('setup-ap-hide').addEventListener('click', () => {
  hideSetupAP(T.wifi.ap.cleared);
  $('setup-ap-show').focus();
});
$('setup-ap-form').addEventListener('submit', e => {
  e.preventDefault();
  busy($('setup-ap-submit'), revealSetupAP);
});
$('wifi-form').addEventListener('submit', e => {
  e.preventDefault();
  busy($('wifi-submit'), async () => {
    if (!check(wifiProblems())) return;
    const ssid = $('ssid').value, security = $('wifi-security').value;
    if (!confirm(t('wifi.confirm', { ssid }))) return;
    const body = { ssid, security, psk: security === 'open' ? '' : $('psk').value };
    // The passphrase leaves the page as soon as it has been read.
    $('psk').value = '';
    wifiWatch++;
    wifi = await api('wifi/connect', { body });
    render();
    outcomeBanner(T.wifi.submitted, false);
    watchWiFi();
  });
});
$('forget').addEventListener('click', () => busy($('forget'), async () => {
  if (!confirm(T.wifi.confirmForget)) return;
  wifiWatch++;
  wifi = await api('wifi/forget', { body: {} });
  render();
  showOutcome(await api('wifi/change'));
}));
$('sms-refresh').addEventListener('click', () => busy($('sms-refresh'), loadSMS));
$('sms-block-recheck').addEventListener('click', () => busy($('sms-block-recheck'), async () => {
  // Only asks. It does not send the draft, whatever the answer.
  const outcome = await refreshSMSBlock();
  if (outcome === 'clear') notice(T.sms.block.cleared);
  else if (outcome === 'unknown') notice(T.sms.block.unknownNow, true);
  else notice('');
}));
$('sms-text').addEventListener('input', () => { $('sms-count').textContent = t('sms.count', { bytes: utf8Length($('sms-text').value) }); });
$('sms-form').addEventListener('submit', e => {
  e.preventDefault();
  busy($('sms-submit'), async () => {
    if (!check(smsProblems())) return;
    const to = smsNumber(), body = $('sms-text').value;
    if (!confirm(t('sms.confirmSend', { to }))) return;
    // The same message keeps its request id, so the device can recognise a
    // repeat and answer with the first receipt. A different message gets a
    // new one.
    if (!pendingSMS || pendingSMS.to !== to || pendingSMS.text !== body) pendingSMS = { request_id: newRequestID(), to, text: body };
    try {
      await api('sms/send', { body: pendingSMS });
    } catch (err) {
      // Not retried. On a timeout the outcome is unknown, and the id is kept
      // for the person's own next attempt.
      if (err.code === 'timeout' || err.code === 'network' || err.status === 503) throw new ApiError(T.sms.uncertain + (err.status === 503 ? '（' + err.message + '）' : ''), err.status, err.code);
      if (typeof err.code === 'string' && err.code.startsWith('trust_')) {
        // Refused by the usage policy, before anything reached the modem. The
        // draft and its request id stay as they are; nothing is retried.
        notice('');
        showSMSBlock(err.code, err.state, true);
        $('sms-block').focus();
        return;
      }
      throw err;
    }
    hideSMSBlock();
    pendingSMS = null;
    $('sms-text').value = '';
    $('sms-count').textContent = '';
    notice(T.sms.submitted);
    await loadSMS();
  });
});
$('rollback').addEventListener('click', () => busy($('rollback'), async () => {
  if (!updateShown) return;
  const shown = updateShown;
  if (!confirm(t('update.rollbackConfirm', { release: shown.release, version: shown.version || T.unknown, previous: shown.previous ? ' ' + shown.previous : '' }))) return;
  renderUpdate(await api('update/rollback', { body: { release_id: shown.release } }));
  notice(T.update.rollbackDone);
}));
$('logs-refresh').addEventListener('click', () => busy($('logs-refresh'), loadLogs));
$('download-diag').addEventListener('click', () => busy($('download-diag'), downloadDiagnostics));
$('password-form').addEventListener('submit', e => {
  e.preventDefault();
  busy($('password-submit'), async () => {
    const old = $('old-password').value, next = $('new-password').value, again = $('confirm-password').value, pe = T.settings.error;
    if (!check([['old-password', old ? '' : pe.oldEmpty], ['new-password', next.length < 12 ? pe.newShort : next.length > 256 ? pe.newLong : ''], ['confirm-password', next === again ? '' : pe.mismatch]])) return;
    const data = await request('/admin/password', { body: { current_password: old, password: next } });
    auth.csrf = data.csrf;
    $('password-form').reset();
    notice(T.settings.changed);
  });
});

function renderSystem(data) {
  $('system-state').textContent = (data.running ? T.system.running : T.system.stopped) + ' · ' + data.ssh.port;
  $('system-enabled').checked = data.ssh.enabled;
  $('system-port').value = data.ssh.port;
  $('system-password-login').checked = data.ssh.password_login;
  $('system-root-login').checked = data.ssh.root_login;
  $('system-fingerprint').textContent = data.host_fingerprint || T.none;
  $('system-users').replaceChildren();
  for (const account of data.accounts || []) {
    const row = document.createElement('p');
    row.textContent = account.name + ' · UID ' + account.uid + ' · ' + (account.locked ? T.system.locked : T.system.ready) + (account.sudo ? ' · sudo' : '') + ' · ' + account.home;
    $('system-users').appendChild(row);
  }
}
async function loadSystem() {
  const generation = systemGeneration, sessionAuth = auth;
  try {
    const data = await api('system');
    if (generation === systemGeneration && auth === sessionAuth && auth && auth.authenticated) renderSystem(data);
  } catch (err) {
    if (generation === systemGeneration && auth === sessionAuth && auth && auth.authenticated) $('system-state').textContent = err.message;
  }
}
async function changeSystem(body, field) {
  const generation = systemGeneration, sessionAuth = auth;
  const current = $(field).value;
  $(field).value = '';
  if (!current) throw new Error(T.system.needCurrent);
  const data = await api('system/change', { body: { ...body, current_password: current } });
  if (generation === systemGeneration && auth === sessionAuth && auth && auth.authenticated) {
    renderSystem(data); notice(T.system.changed);
  }
}
$('system-action').addEventListener('change', () => {
  const action = $('system-action').value;
  $('system-password-fields').hidden = !['create', 'password'].includes(action);
  $('system-key-field').hidden = action !== 'keys';
  $('system-toggle-field').hidden = !['sudo', 'lock'].includes(action);
  $('system-new-password').value = $('system-confirm').value = '';
});
$('system-ssh-form').addEventListener('submit', e => {
  e.preventDefault(); busy($('system-ssh-submit'), () => changeSystem({ action: 'ssh', ssh: {
    enabled: $('system-enabled').checked, port: Number($('system-port').value), password_login: $('system-password-login').checked, root_login: $('system-root-login').checked,
  }}, 'system-ssh-current'));
});
$('system-account-form').addEventListener('submit', e => {
  e.preventDefault(); busy($('system-account-submit'), async () => {
    const action = $('system-action').value, body = { action, user: $('system-user').value };
    if (['create', 'password'].includes(action)) {
      body.password = $('system-new-password').value;
      if (body.password.length < 12 || body.password !== $('system-confirm').value) throw new Error(T.system.mismatch);
    }
    if (action === 'keys') body.keys = $('system-keys').value.split(/\r?\n/).map(v => v.trim()).filter(Boolean);
    if (['sudo', 'lock'].includes(action)) body.enabled = $('system-toggle').checked;
    if (action === 'delete' && !confirm(T.system.removeConfirm)) return;
    $('system-new-password').value = $('system-confirm').value = '';
    await changeSystem(body, 'system-account-current');
  });
});

document.addEventListener('visibilitychange', () => {
  if (document.hidden || !auth || !auth.authenticated) return;
  checkSession();
  if (tab === 'overview') refresh(true);
});
setInterval(checkSession, SESSION_CHECK_MS);
session().catch(err => notice(t('error.unreachable', { message: err.message }), true));
})();
