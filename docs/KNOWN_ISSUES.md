# 已知问题与避免踩坑

1. WPA2/WPA3 混合热点不能按“包含 WPA3”直接强制 SAE。本版已修复混合识别，明确选择纯 WPA3 时仍使用 SAE，不自动改成 WPA2。
2. /proc/device-tree 常为符号链接。检查 APR 节点时必须跟随它；“没找到文件”不能证明基带没有音频服务。
3. 芯片相同不代表 RF 校准、签名、分区、运营商配置相同。不能直接刷手机基带到数据棒子。
4. IMS 注册不是双向音频验收，不能提前宣称可拨号。
5. 下行、上行监听及注入需要匹配的 q6 伪端口；普通物理音频口不等于通话录音/放音口。VoLTE 与 modem voice 会话可能不同，必须实测。
6. 网页电话状态与媒体连接生命周期要跟随真实呼叫；本版媒体监视已加入真实呼叫终止与连续查询失败后的清理，浏览器整体链路仍需回归。
7. 宿主机与棒子资源字段不能混用；设备未上报的温度、频段、带宽等保持未知。
8. USB 固定地址的多设备路由冲突必须在宿主隔离。不能仅因页面支持多个卡片就认为多棒子 USB 已验证。
9. 初始后台无初始化凭据不能设置密码。已配对 NAS 提供正式入口；不要把初始化码做成通用默认密码。
10. 不支持 5/6 GHz；纯 WPA3、其他运营商 VoLTE 和长时间双向网页电话都不能当作已经通过的功能。

11. mmcli -K 的短信正文会将 UTF-8 字节输出为 GLib 八进制转义。本版在命令输出边界解码一次，保留正文里的字面反斜杠。升级 NAS 时必须原位迁移旧正文与消息标识，保留已读/删除状态，避免重复导入。
12. 接听/挂断应直接查询目标 Call 对象，不能逐条遍历历史呼叫。本版使用 D-Bus GetAll 与 Accept/Hangup，真实基带状态仍是通话状态的依据。
13. 远端通话经电脑音响播放后再由电脑麦克风拾取会形成回路，浏览器回声消除会抑制它。验证上行请戴耳机并在本地直接对麦克风讲话，或者使用仅发送给远端的有限测试音。不要用自己的远端回声判断上行是否失效。浏览器行为见 [W3C Media Capture](https://www.w3.org/TR/mediacapture-streams/)。

14. 配网热点（setup access point）**未在真机验证，默认关闭**。出厂配置是 `provisioning = false`、`provisioning_ap = off`，通用镜像不带它的前置条件；只有打包时显式 `NSH_SETUP_AP=on` 才带（包清单写 `enabled (not verified on hardware)`）。没有前置条件就把配置改成 `auto`，预期结果是 `AP_FAILED`（polkit 拒绝）或热点连得上但页面打不开（80 端口绑定失败）。热点口令目前没有任何界面显示，只能经 USB 维护连接读 `/var/lib/nassimhub/setup-ap-passphrase`。USB 管理通道不受这些影响。见 RELEASING.md 第 11 节。
15. 纯 WPA3（仅 SAE）与 5 GHz 网络**未在本板验证**。扫描结果里它们标为 `unverified`：可能可用，也可能不可用；不隐藏、不承诺。已验证的只有 2.4 GHz 的 WPA2 与 WPA2/WPA3 混合模式（按 WPA2 加入）。第 10 条写的是“不支持 5/6 GHz”，而 Agent 的扫描结果对 5 GHz 标的是 `unverified` 而不是 `unsupported`；在有本板 `iw list` 的实测记录之前，两处说法以“未验证”为准。
16. 服务小区的**带宽没有上报**。频段、EARFCN、PCI、TAC、小区号来自设备上定时器已经在发的两条 QMI 查询；带宽需要再加一条查询，这一轮有意没加（多一条查询就多占一次通话和短信也依赖的 QMI 通道）。界面上带宽保持“未知”，不从频段推算。
17. 上述小区字段的来源文件 `/run/nassimhub-ims/radio.metrics` 由 `nassimhub-radio-status.timer` 写入，而这个定时器只由逐设备的 `node/deploy/audio/install-voice.sh` 安装。**通用 Factory 镜像（Lite 和 Dev）里没有它**，所以没装通话部署的设备上这些字段全部是“未知”。这不是单元加固挡住了读取，而是没有人写这个文件。
18. Node 线路 DTMF（按键音）的协议、NAS 路由和设备发送后端已实现并通过离线测试。`voice_dtmf` 默认关闭，尚未真机验证基带和运营商是否接受按键；客服语音菜单不能按已验收功能发布。不确定的发送结果不会自动重发，参见 [DTMF 验收说明](CODEX_R130_DTMF_AND_DEVICE_POLICY.md)。
19. **Node 本地执行信任策略：已实现，只有离线测试，未在真机验证。** NAS 的信任引擎做决定并用自己的身份密钥给策略签名（`dial`/`send_sms`/`dtmf`/`forward_otp` 的拒绝列表、状态、代次）；Agent 用配对时钉住的 NAS 公钥验证后保存在状态目录的 `trust-policy.json`，并在拨号、发短信的请求入口以及本机管理页的发短信入口自行拒绝（`node/agent/trust`、`node/proto/trustpolicy.go`、NAS `internal/nassimhubnode/devicepolicy.go`）。接听、挂断、收短信、状态、Wi-Fi、更新、配对不受它限制。几条容易踩的规则：
    - **限制不过期，许可会过期。** 拒绝列表在策略过期、NAS 断开、设备重启后都继续有效；策略允许的操作在策略“不新鲜”时同样被拒绝，直到 NAS 再发一次。
    - **设备的墙上时钟不参与“是否接受策略”。** UFI003 没有带电池的 RTC，可能在 1970 年或上次保存的时间启动，且只接 USB 时没有 NTP。防重放/防回滚靠签名和严格递增的代次。有效期用单调时钟从“收到策略的那一刻”起算（`expires_at − issued_at`，NAS 目前签 24 小时、每 6 小时续签）。墙上时钟向前或向后的校正都不改变已经确认的许可有效期；防重放仍由认证会话、签名和代次约束，不能用旧文档在未认证状态续期。
    - **重启后需 NAS 重新确认。** 单调时间不跨重启，所以从磁盘读回的策略在 NAS 重发之前算“不新鲜”（`GET /v1/trust` 的 `freshness: stale_restart`，管理页显示“设备重启后需由 NAS 重新确认策略；连接 NAS 后自动恢复”）。NAS 在每个新会话上、任何外发请求之前重发上一次签名的策略；同一份签名文档再次到达即恢复，不消耗新的代次。**后果：设备重启后、NAS 连上之前，本机管理页不能发短信**，即使策略是 TRUSTED。
    - **前向校时锁定已在源码修复，未做真机验收。** 收到的许可只按单调时间失效，重启后仍需 NAS 重新确认。策略限制不会因校时、过期或重启而解除。
    - 与旧版本的兼容：旧 NAS 从不下发策略，新 Agent 没有策略时行为与以前完全一样；旧 Agent 对策略接口回 404，NAS 显示“设备不执行”，只有 NAS 自己的闸门生效。
    - 换模组检测用的硬件标识读自 `/sys/devices/soc0/serial_number`（只上报带域前缀的 SHA-256）。**UFI003 的主线内核是否导出这个文件、Agent 的服务用户在单元加固下能否读到，都没有核实**；读不到时如实显示“不支持”，不拿 IMEI、MAC 或接口名代替。
    - 本仓库 `node/` 快照要在同步 Node 源码之后才包含上面“时钟/重启”这两条规则；同步前的快照仍是旧规则（拒绝“签发时间在设备未来 10 分钟以上”的策略，时钟早于 `issued_at` 即判过期），在没有 RTC 的设备上会把设备锁在不能外发的状态。发布前确认 `node/agent/trust/gate.go` 里有 `freshnessLocked`。
    - 未在真机做过的：策略在重启/掉电后仍在并仍被执行、时钟未校准（1970）开机后首次连接 NAS 即可外发、NAS 不重启而设备重启后的第一次外发、管理页上的拒绝提示。NAS 网页是否显示 `freshness` 不在这一项的修改范围内（接口字段已提供）。
20. `node/deploy/audio/install-voice.sh` 在 r127 及之前会覆盖 `/usr/bin/nassimhub-agent`（OTA 设计里的 Factory Agent）。r128 起默认保留它，替换必须显式并带哈希（RELEASING.md 第 12 节）；新脚本**只有离线测试，未在真机运行过**。已被旧脚本装上 `dev` Agent 的设备更新仍是关闭的，需要用 `--replace-agent` 换成带版本号的构建。
21. 配网热点启用时 Agent 服务持有 `CAP_NET_BIND_SERVICE`。单元用 `SocketBindDeny=` 把 80/tcp 以外的低端口全部拒绝，但这依赖内核的 cgroup BPF；棒子的内核是否支持没有核实，不支持时 systemd 只记一条警告，Agent 可以绑定 1024 以下的任意端口。
22. **`ota_signature_policy = required`（或 PQ_EXTREME）下，双签的 Agent 更新在重启后被回滚——已在 Node 源码修复，只有离线测试。** 原因是 `nassimhub-agent`（以及 mock Node）的 `main` 在注册 ML-DSA 验证器（`proto.EnableStandardPQ()`，原先只在 `nodeserver.New` 里）之前就调用了 `ota.Launch`，Factory Agent 的启动校验无法检查后量子签名，按“不可校验”拒绝已安装的发布（方向是拒绝而不是放行）；`preferred` 下启动校验只复核了经典签名。修复：`ota.Launch` 自己先注册验证器，两个 `main` 也在调用它之前注册（重复注册无害，走注册表的锁）。测试：`node/agent/ota` 的 `TestStartUpVerifiesADualSignedReleaseBeforeAnythingElseEnabledTheProvider`（去掉修复即失败）、`node/proto` 的 `TestEnableStandardPQIsIdempotentAndSafeWhileVerifying`，以及用真实进程的 NAS 端到端测试 `TestE2EDualSignedUpdateSurvivesRestartsWhenPostQuantumSignaturesAreRequired`（`required` 与 PQ_EXTREME 两种：双签 1.1.0 被应用、重启、确认，再重启两次仍在；用去掉修复的二进制跑同一测试得到 `ROLLED_BACK`）。**仍需注意：**(a) 做启动校验的是系统镜像里的 Factory Agent，OTA 从不替换它——**已经刷了旧 Factory Agent 的设备不会因为收到新的 Agent 更新而修好**，在换上含此修复的 Factory Agent（重刷镜像，或按 RELEASING.md 第 12 节 `--replace-agent`）之前不要在这些设备上启用 `required`/PQ_EXTREME；(b) 本仓库 `node/` 快照要在同步了 Node 源码之后才包含这个修复，发布前请确认 `node/agent/ota/launch.go` 里有 `proto.EnableStandardPQ()`；(c) 未在真机验证。见 KEY-MANAGEMENT.md 7.3。
23. `firmware/rootfs.lock.json` **尚未解析**：没有快照时间戳、没有软件包版本、没有内核制品哈希、没有 `nassimhub` 的 uid/gid、没有 rootfs 分区大小。`scripts/build-rootfs.sh` 因此只能以 `--unlocked` 运行并把产物标为“不是发布输入”。真实的 mmdebstrap bootstrap 从未运行过，两次真实构建是否逐字节相同未知。见 ROOTFS-BUILD.md。
24. `release-keys.json`（`scripts/publish-keys.sh`）**没有签名**：`nsh-release` 只能给 Agent 更新清单签名。它的真实性来自发布渠道；设备不读它，它不撤销任何钥匙。
