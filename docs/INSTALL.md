# 安装、备份与回滚

## 先核对硬件

目标 UFI003_MB_V02 / MSM8916 / aarch64。先只读记录 USB VID/PID、启动模式、板型、GPT、boot header、DTB、根分区、内核及基带服务状态。其他 UFI003 外壳不代表同一板型。按自己的分区尺寸审核镜像；本仓库不提供任意设备通用刷写命令。

修改前在本地私有目录备份 boot、系统配置和自己的恢复资料，校验 SHA256，并确认 EDL 救援流程。设备唯一分区的备份只能由本人保存，绝不能上传公开仓库。不要克隆别人的 NV。

## 构建源码

运行 scripts/check.sh 和 scripts/build-agent.sh VERSION（例如 `sh scripts/build-agent.sh 1.15.1`）。静态 arm64 Agent 无 glibc 链接依赖，但其运行后端需要系统里的 ModemManager、NetworkManager、D-Bus/polkit、ALSA 程序等。

构建是可复现的：同一源码、同一 Go 版本两次构建逐字节相同，`build/BUILDINFO.json` 记录版本、Go 版本、目标平台、`node/` 内容哈希以及该工具链是否有 ML-DSA；`sh scripts/test-reproducible-build.sh` 构建两次并比较。不给 VERSION 时构建出的是 `dev`：能运行，但永远不安装也不启动更新，打包脚本拒绝用它做 Factory 包。完整流程（构建、打包、仓库外签名、校验、发布、密钥保管与轮换）见 [RELEASING.md](RELEASING.md)。

离线 rootfs 使用 debootstrap 构建 Debian 13 arm64，安装 systemd、systemd-timesyncd、ca-certificates、network-manager、wpasupplicant、modemmanager、libqmi-utils、qrtr-tools、rmtfs、alsa-utils、polkitd 和板型对应内核。同一份软件包名单以机器可读形式记在 `firmware/debian-packages.json`（只有包名）。r128 起有可重复的构建脚本 `scripts/build-rootfs.sh`：从 snapshot.debian.org 的固定时间戳构建，版本锁在 `firmware/rootfs.lock.json`，依赖说明在 `firmware/rootfs-dependencies.json`，接已验证的内核制品（不在这里构建）；完整步骤见 [ROOTFS-BUILD.md](ROOTFS-BUILD.md)。**默认锁仍为模板；r134 已从签名快照实际构建并校验 207 个包及 703 个模块，已解析锁与内核输入一起保存在该次构建目录。r138 已在一台 UFI003 上实测修正后的本人配置恢复版 rootfs：启动、重启、USB/Wi-Fi、身份保持、NAS 认证配对、短信读取和 10000 下行音频通过。旧 r134/r135 通用候选包未包含全部修正，不能直接按已验收版发布；须用更新源码及版本锁重新构建干净包。**要启用配网热点（`NSH_SETUP_AP=on`，见下）时还需要 `dnsmasq-base`：NetworkManager 的 shared 模式靠它给连上热点的手机发地址。装 `dnsmasq-base` 即可，**不要**装完整的 `dnsmasq`（那会多出一个全系统的 DNS/DHCP 服务）。overlay 里的权限规则需要 polkitd；已在可用真机上核对，因此把它列为显式依赖，避免只靠推荐包导致网络和短信权限失效。软件包来源与固件再分发授权由构建者核对。不要从正在使用的棒子做整盘 dump 后公开发布。

scripts/package-factory.sh 只加工提供的干净 rootfs 目录，不执行 chroot，不写任何设备。输入需要已经创建不可交互登录的 nassimhub 用户，并锁定账户密码；SSH 密钥由各设备首次启动配置生成，不能放共享私钥。生成 raw ext4 rootfs.img，要求 boot 命令行已经匹配 rootfs 标签或板型对应 PARTUUID。包清单的 `rootfs.statement` 写明这个 rootfs 的来源：给了 `NSH_ROOTFS_MANIFEST`（`build-rootfs.sh` 的产物）且目录树与之一致时是 `built from lock <sha256>`，否则是 `operator-supplied (unverified provenance)`。设置 ROOT_SPEC=LABEL=rootfs（或实际匹配的 PARTUUID 值）后打包，脚本会核对 boot 命令行。第三个参数选择变体 Lite（默认）或 Dev，产物在 `dist/factory/<版本>-<变体>/`；两者的实际差别和未实现的项目见 RELEASING.md 的对照表。它不把 sparse 格式和 raw 格式混为一谈，不负责调整 GPT。需要 sparse 的刷写工具须显式转换并另行审核。

持久状态要求单独存在标签 NSHSTATE 的 ext4 分区，挂载 /var/lib/nassimhub，脚本不会替用户创建或格式化它。镜像不带 machine-id、SSH 主机密钥、管理密码、设备身份、配对、Wi-Fi 密码或音频验收标记。第一次启动由 systemd 和 Agent 创建自己的身份。镜像自带什么、首次启动在设备上生成什么，逐项对应源码列在 [FIRST_BOOT.md](FIRST_BOOT.md)。

包的通用性由脚本强制：打包前审核干净 rootfs，生成镜像前审核合成后的目录树，最后用 `scripts/privacy-check.py --package` 检查成品（设备身份、配对、管理密码或摘要、Wi-Fi 密码、SSH 主机密钥与 authorized_keys、设备证书与私钥、modemst1/modemst2/fsg/fsc/persist 等校准数据、IMEI/ICCID/号码、日志、短信）。任何一步不过都不产出包。通过检查不等于免去人工审核，规则的局限写在 `scripts/genericrules.py`。

Agent 更新（OTA）：只有打包时用 `NSH_OTA_KEYS` 提供了发布**公钥**文件，镜像才带 `/etc/nassimhub/ota-keys.json`（root:root 0644）并去掉状态分区的 noexec（发布版本存放在状态分区并从那里执行）。没有提供时包清单写明 `updates disabled: no release keys`，设备不支持更新，状态分区保持 noexec。发布私钥永远不进镜像。这部分 未在真机验证 / not yet verified on hardware，步骤见 [VALIDATION.md](VALIDATION.md)。

配网热点（setup access point）：默认**不启用**，镜像里也不带它的前置条件（出厂配置 `provisioning = false`、`provisioning_ap = off`，包清单写 `setup access point: not enabled`）。打包时设 `NSH_SETUP_AP=on` 才会叠加 `firmware/setup-ap-overlay/`（只给 `nassimhub` 用户多授予一个 polkit 动作 `wifi.share.protected`，只给 Agent 服务多一个 `CAP_NET_BIND_SERVICE` 用于监听 `192.168.4.1:80`），并把包内的配置改为 `provisioning = true`、`provisioning_ap = auto`；包清单写 `setup access point: enabled (not verified on hardware)`。热点从未在真机上启动过，口令目前只能经 USB 维护连接读取 `/var/lib/nassimhub/setup-ap-passphrase`。逐条核对、动作清单、80 端口三种做法的比较见 RELEASING.md 第 11 节，验收步骤见 [VALIDATION.md](VALIDATION.md)。在设备上关闭：`provisioning_ap = off` 后重启服务。

后台入口：https://10.55.0.2:7581/ （USB）或本机 Wi-Fi IP 的 7581 端口。初始化凭据保存在本机受限状态目录 /var/lib/nassimhub/admin-bootstrap.txt；设备管理员可在设备控制台读取并在“高级维护”栏输入自己的初始化码。不要向开发者发送管理密码。已配对 NAS 可使用 SIM 节点的“打开棒子后台”入口。独立后台仍可通过本机维护入口管理，不以 NAS 在线为条件。

## 电话音频是可选的硬件阶段

先审核 kernel/audio 补丁与 KyonLi 6.12.49-1 源码。以自己的审核过的 DTB 生成候选 DTB，再重打包 boot。build-modules.sh 使用匹配源码和头文件。检查 vermagic、依赖、APR 服务、ALSA 控件；不要把编译成功视为 DSP 兼容成功。

支持时优先 fastboot boot 内存试启；并非所有启动器支持该命令。实际持久修改前保留可恢复的 boot 和模块。逐设备验收 IMS、录音和上行音频后，才使用 node/deploy/audio 的可选组件。禁止在通用镜像内放 local-volte.enabled 或 voice-audio.verified；标记是该设备实际验收记录。

`node/deploy/audio/install-voice.sh HOLDER` 自 r128 起**只安装** holder、unit、polkit 规则与 timer，`/usr/bin/nassimhub-agent`（OTA 设计里“永不改写”的 Factory Agent）保持不动；旧的 `AGENT HOLDER` 写法会被拒绝。确需更换 Factory Agent 时用 `--replace-agent FILE --expect-sha256 HEX`：脚本核对哈希，拒绝 `dev`/无法比较的版本、低于现有 Agent 的版本、有待确认更新时的运行，以及（除非 `--supersede-release`）会让已选中发布被取消的替换；任何一步失败都完整还原并重启 Agent，并说明重启后实际提供服务的是 Factory Agent 还是状态分区里的发布。完整说明见 RELEASING.md 第 12 节；只有离线测试（`sh scripts/test-install-voice.sh`），未在真机验证。

## 回滚

用户态更新：停止 Agent（会清理电话），恢复自己的旧二进制、配置和服务覆盖，daemon-reload，再启动。保留 /var/lib/nassimhub；不要重置身份当作修复手段。

Agent OTA 的回滚是自动的：系统镜像里的 Factory Agent 从不被改写，更新装在状态分区；未在 10 分钟内确认、确认前再次重启、版本不符或无法执行的更新会被撤销，回到上一个版本或 Factory Agent。需要人工介入时，在 /etc/nassimhub/agent.conf 写 `updates = false` 并重启服务即可强制运行 Factory Agent。细节与恢复顺序见 RELEASING.md 第 8、9 节（未在真机验证）。

开机长按约 5 秒进入 9008/EDL 是硬件行为，任何恢复、回滚或重置功能都不绑定到它；任何流程都不写 modemst1/modemst2/fsg/fsc/persist。

音频模块与 boot：恢复原模块选择和匹配的 boot；内存试启断电后回到原 boot。新的硬件故障使用本板正确 EDL programmer 和本人备份，绝不覆盖他人或其他板型的校准分区。

配网热点、量产 Factory/OTA、长期运行、来电、浏览器双向通话仍需按 docs/ROADMAP.md 与 docs/VALIDATION.md 验收。本源码仓库不声称已经完成全部这些测试。
