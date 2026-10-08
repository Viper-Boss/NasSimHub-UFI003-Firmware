# NasSimHub UFI003 Firmware

**把 Qualcomm Snapdragon 410 / MSM8916 UFI003 变成可独立管理、也能接入 NasSimHub 的 Linux SIM 节点。**

基线：**Debian GNU/Linux 13（Trixie，2026-10-08 单设备实测 13.7）+ Linux 6.12.49-msm8916-g93a71ee9468d**，来自 KyonLi 6.12.49-1。目标板为 **UFI003_MB_V02**。本仓库公开固件集成源码、Agent、独立 HTTPS 后台和 q6 通话音频补丁，方便复现与排查，减少反复踩坑。

> 当前是开发者源码版，不是已经通过所有运营商、所有板型验证的量产固件。没有发布从个人设备导出的整盘镜像。最新 Agent 为 dev46，源码包含中文短信解码、通话状态及媒体修复、DTMF、SIM 本机号码读取，以及独立后台的 Linux 用户和 SSH 管理；逐项验收范围见下表。

## 用在什么地方

- 自有 SIM 的短信收发、设备状态查看和 NAS 集中管理。
- 通过 USB 管理 SIM 节点，也可使用 2.4 GHz Wi-Fi；无需 NAS 即可打开棒子自己的管理后台。
- 对已经逐设备验证的基带/运营商组合，研究与使用 VoLTE 呼叫控制及 Linux 通话音频。
- 学习 MSM8916 的 Debian 启动链、QRTR/QMI、ModemManager、APR/QDSP6 与 USB gadget。

## 当前功能与实际验证范围

| 项目 | 当前状态 |
|---|---|
| Debian 13 arm64 / systemd / 持久身份 | 真机运行；身份首次启动生成，/var/lib/nassimhub 必须在持久分区 |
| USB NCM / NAS 配对 | 真机验证；Node 固定服务地址 10.55.0.2:7580 |
| 2.4 GHz WPA2、WPA2/WPA3 混合热点 | 真机连接及保存后重新连接通过；混合热点使用 WPA2 |
| 纯 WPA3-SAE | 软件配置入口存在，尚无本板稳定连接验收，不能承诺支持 |
| 短信读写 | ModemManager 后端已实现；中文短信 UTF-8 与 D-Bus 原文真机比对通过，NAS 修复旧记录需同步更新主项目；仍需按 SIM 和运营商回归 |
| CPU、内存、存储、进程、无线状态 | Agent 有采样及接口；未取得的字段保持未知，不借用另一设备数据 |
| 独立 HTTPS 后台 | 源码内置，端口 7581；管理密码与 NAS 登录、配对密钥独立 |
| VoLTE/q6voice | 特定电信 SIM/基带组合已完成呼叫与 16 kHz PCM 录放音；不保证其他卡或联通组合 |
| 浏览器双向电话 | 当前单设备与电信 SIM 上用户已确认拨出、来电和双向声音正常；不能据此承诺其他运营商或长期稳定性 |
| Linux 账户 / SSH 管理 | dev46 独立后台支持普通用户、root 密码/公钥、sudo、锁定、保留家目录删除及独立 SSH 开关；真机普通账户与公钥登录已验证，真实浏览器的新表单尚待验收；详见 [系统管理](docs/SYSTEM-ADMIN.md) |
| SIM 本机号码 | 优先使用基带报告，支持读取当前设备 SIM 的 EF_MSISDN；仅对实际提供号码的卡有效，不保证任意 SIM 都存有号码；见 [自动号码](docs/AUTO-PHONE-NUMBER.md) |
| 配网热点（setup access point） | 源码与离线测试已有；默认关闭，镜像侧前置条件仅在打包时 `NSH_SETUP_AP=on` 才带入。**未在真机验证**；独立后台已有口令显示入口，需确认管理密码 |
| 温度、CPU 频率、eMMC 寿命、网卡计数、服务小区 | Agent 有采样代码；各数据源在本板上是否可读**未在真机验证**。服务小区带宽不上报；小区字段的来源定时器不在通用镜像里 |
| Debian 13 rootfs 构建 | `scripts/build-rootfs.sh`：snapshot.debian.org 固定时间戳 + 逐包版本锁 + 已验证内核制品的哈希与 vermagic 检查；bootstrap 之后的全部步骤与镜像生成有离线测试（合成输入）。已进行真实 Debian rootfs 构建，修正候选在一台 UFI003 上刷入并启动/重启验收；仓库默认锁仍是模板，通用发布包尚未重新构建和批量验收，见 [可用系统](docs/USABLE-SYSTEM.md) |
| DTMF | Node 协议 1.5、NAS 路由和 ModemManager 按键发送已实现并通过离线测试；通用配置的 `voice_dtmf` 默认关闭；当前单设备已由用户完成语音菜单按键测试，不代表任意卡或通用镜像已支持。见 docs/CODEX_R130_DTMF_AND_DEVICE_POLICY.md |
| Factory/OTA | 可复现的 Agent 构建、Factory 包（Lite/Dev）与 Agent OTA 发布打包、仓库外签名与校验、SBOM 与通用性检查均有离线测试；Agent 更新只替换 Agent 可执行文件。通用可刷写发布包及升级/回滚闭环 **未在真机验证**，见 docs/VALIDATION.md |

## 下载、编译与目录

安装 Go 1.24+（建议与验证环境一致使用 1.27.1）、Python 3、Linux 构建环境。内核工具另需 dtc、cpp、匹配的头文件及 aarch64 GCC。

~~~sh
sh scripts/check.sh
sh scripts/build-agent.sh 1.15.1          # 可复现构建；不带版本号是 dev，不支持更新
# 已审核的干净 rootfs 目录 + 已审核的板型 boot 镜像，完全离线打包（变体 Lite 或 Dev）：
sudo ROOT_SPEC=LABEL=rootfs sh scripts/package-factory.sh /path/to/clean-rootfs /path/to/boot.img Lite
# Agent OTA 发布：未提供密钥时只生成未签名清单，并打印给发布负责人的签名命令
sh scripts/package-ota.sh 1.15.1 stable agent-1.15.1
~~~

发布私钥只存在于仓库之外，脚本拒绝任何位于仓库内的密钥路径。完整流程见 [发布流程](docs/RELEASING.md)，镜像自带与首启生成的内容见 [首次启动](docs/FIRST_BOOT.md)。

| 目录 | 内容 |
|---|---|
| node/agent | 设备 Agent、ModemManager/NetworkManager 后端、短信/呼叫/遥测、独立后台 |
| node/proto、node/xport | 身份、配对、安全策略及传输协议 |
| node/deploy | systemd、配置和可选通话组件 |
| kernel/audio | q6 录放音端口补丁、设备树修改与 boot DTB 重打包工具 |
| firmware/overlay | 首启、持久分区检查、USB NCM 及网络配置 |
| firmware/ota-overlay | 仅在镜像带发布公钥时安装：让状态分区可执行（Agent 更新所需） |
| firmware/setup-ap-overlay | 仅在 `NSH_SETUP_AP=on` 时安装：配网热点所需的一个 polkit 动作和一个 capability（默认不带） |
| firmware/debian-packages.json | 镜像需要的 Debian 软件包名单（不含版本） |
| firmware/rootfs.lock.json、firmware/rootfs-dependencies.json | rootfs 构建的输入锁（**尚未解析**：没有版本）与依赖清单 |
| scripts | 源码检查、隐私与通用性检查、可复现构建、Factory/OTA 打包、SBOM 与许可证检查 |

当前系统状态与限制见 [dev46 状态](docs/STATUS-dev46.md)。

查看 [设备安装与恢复](docs/INSTALL.md)、[发布流程](docs/RELEASING.md)、[rootfs 构建](docs/ROOTFS-BUILD.md)、[发布密钥管理](docs/KEY-MANAGEMENT.md)、[安全更新](docs/SECURITY-UPDATES.md)、[验收清单](docs/VALIDATION.md)、[架构与协议](docs/ARCHITECTURE.md)、[路线图](docs/ROADMAP.md)、[已知问题](docs/KNOWN_ISSUES.md)。NAS 集成主项目在 [NasSimHub](https://github.com/Viper-Boss/NasSimHub)。此仓库可独立开发，不包含 NAS 全部源码。

## 重要的设备边界

不要跨板型盲刷，不要复制他人的 modemst1/modemst2/fsg/persist 或校准数据。按键开机长按约 5 秒进入 Qualcomm 9008/EDL，是硬件既有行为，**不用于 NasSimHub 恢复出厂**。本项目脚本不自动刷分区、不重分区、不格式化设备。

AGPL-3.0-only 用于本项目自己的代码和文档；Linux 衍生部分保留 GPL 及上游授权，详见 [NOTICE](NOTICE.md) 和 [许可证边界](LICENSES/README.md)。

English: Developer source for a Debian 13 / Linux 6.12.49 UFI003 SIM node, with standalone HTTPS administration, USB/Wi-Fi management, SMS and experimental carrier-dependent VoLTE/QDSP6 audio. This is not a universal carrier-certified firmware or a production-ready image.
