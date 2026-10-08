# 安全更新：一个修复怎样到达设备

本文说明安全修复的两条下发途径、各自能修什么、用户会看到什么。密钥见 [KEY-MANAGEMENT.md](KEY-MANAGEMENT.md)，发布命令见 [RELEASING.md](RELEASING.md)，rootfs 见 [ROOTFS-BUILD.md](ROOTFS-BUILD.md)。

**状态**：按源码与离线测试描述。更新、确认、回滚的整条链路 **未在真机验证 / not yet verified on hardware**（[VALIDATION.md](VALIDATION.md)）。

## 1. 两条途径，范围不同

| | Agent 更新（OTA，经 NAS） | 系统镜像（Factory 包，刷机） |
|---|---|---|
| 能修的 | `nassimhub-agent` 可执行文件里的问题：Node 协议、配对、独立后台、短信/通话控制逻辑、遥测、更新机制自身在“已安装发布”一侧的代码 | 其余一切：内核、Debian 软件包（NetworkManager、ModemManager、systemd、OpenSSL 库…）、overlay 里的 unit/polkit 规则、默认配置、**发布公钥文件**、**Factory Agent 本身** |
| 不能修的 | 上一栏右边的所有东西。更新机制不写 boot、设备树、基带分区、根文件系统（`node/agent/ota/ota.go`） | 状态分区里的内容（身份、配对保持不变） |
| 到达方式 | 发布方签名 → 管理员把 `manifest.signed.json` 与二进制导入 NAS → NAS 经已配对的连接送到设备 → 设备用自己的公钥校验 | 发布方出镜像 → 设备所有者核对后刷写（本项目脚本不刷机） |
| 前提 | 镜像带发布公钥（否则设备“不支持更新”）；Factory Agent 是带版本号的构建（`dev` 不参与更新）；设备已与 NAS 配对 | 能物理接触设备；按 INSTALL.md 备份 |
| 自动程度 | **默认不自动**：`update_url` 默认为空，设备不主动拉取；由管理员在 NAS 上导入并对设备下发 | 手动 |
| 失败时 | 自动回滚到上一个版本或 Factory Agent（未在 10 分钟内确认、确认前再次重启、版本不符、无法执行） | 重刷上一份镜像 |

一个要点：**Factory Agent 里的缺陷不能靠 OTA 根除。** 它是每次启动的第一个进程，负责校验并启动已安装的发布；OTA 装上的修复版运行时，Factory Agent 的那段启动代码仍然是旧的，并且任何回滚都回到它。Factory Agent 自身（启动校验、回滚逻辑）的安全修复需要新镜像。逐设备的替代办法是 `install-voice.sh --replace-agent FILE --expect-sha256 HEX`（RELEASING.md 第 12 节；需要在设备上以 root 执行，未在真机验证）。

Debian 软件包的修复：重新解析 rootfs 锁到更新的快照（`build-rootfs.sh --lock --timestamp <更新的时间戳>`），锁文件的 diff 就是这次升级了哪些包；重新构建、打包、出镜像。**当前锁未解析**，在第一次解析完成之前，仓库无法回答“镜像里的某个 Debian 包是什么版本”——只有具体镜像的 `DEBIAN-PACKAGES.txt` 能回答。

## 2. Agent 安全更新的步骤（发布方）

1. 修复，递增数字版本（设备拒绝数字版本不高于当前版本的发布；`-后缀` 不算升级）。
2. `sh scripts/build-agent.sh <版本>`，`sh scripts/check.sh`。
3. `sh scripts/package-ota.sh <版本> stable agent-<版本>`；在持钥机器上签名（RELEASING.md 第 4 节），双签需要 Go ≥ 1.27 构建的 `nsh-release`。
4. `nsh-release verify … -keys <设备上实际安装的 ota-keys.json>`；`privacy-check.py --ota-release`。
5. 公布：`manifest.signed.json`、`nassimhub-agent`、`SHA256SUMS`、`sbom.spdx.json`，以及说明（影响的版本、修复的版本、是否需要同时更新镜像）。`manifest.signed.json` 必须逐字节原样传递。
6. 若修复同时涉及 Factory Agent 或系统：另出镜像，并在说明里写清“仅 OTA 不够”。

## 3. 用户看到什么

- NAS 的 Node 更新面板：导入的发布及其 `gateway`（`verified`：网关用自己的发布公钥校验过；`unverified`：网关没有配置 `MODEMDECK_NASSIMHUB_OTA_KEYS`，什么也没校验，由设备决定）与 `signatures`（`classical_only` / `dual_signed`）。
- 设备更新状态：状态机 `AVAILABLE → DOWNLOADING → STAGED → VALIDATING → READY → APPLYING → PENDING_CONFIRM → IDLE`，或 `FAILED` / `ROLLED_BACK` 及原因；签名一栏 `{policy, outcome, pq_available, requires_toolchain}`——只有经典签名时显示“仅经典”，构建不支持 ML-DSA 时显示缺什么工具链，不会显示成“正常”。
- 设备不支持更新时显示**原因**之一，而不是静默：没有发布公钥；`updates = false`；Factory Agent 是开发构建（`dev`）或版本不可比较；钥匙文件不可用；Agent 协议早于 1.3。
- 设备拒绝一个发布时的原因（签名无效、钥匙不在钥匙文件里、策略要求后量子签名而没有、平台或架构不符、版本不高于当前、与 NAS 版本不兼容、哈希不符）。
- 更新后设备会重启 Agent 一次；10 分钟内未确认则自动回滚，状态变为 `ROLLED_BACK`。更新期间进行中的通话会中断（停止 Agent 会清理通话）。
- 系统镜像更新没有任何界面：设备所有者自己刷写，刷后 `/etc/nassimhub/ota-keys.json`、Factory Agent 版本随镜像变化；用 `publish-keys.sh --check` 核对钥匙文件。

已知限制（会影响安全更新的可用性）：

- `ota_signature_policy = required` / PQ_EXTREME 下，双签更新在重启后被回滚（KEY-MANAGEMENT.md 7.3，Agent 启动顺序缺陷，**未修复**）。修复它本身需要新的 Factory Agent，即新镜像或 `--replace-agent`。
- Go < 1.27 构建的 Agent 在 `required` 下拒绝一切更新。
- 没有远程撤销发布钥的手段（KEY-MANAGEMENT.md 第 5 节）。
- Factory 包没有签名。

## 4. 报告与披露

漏洞报告渠道见仓库根目录 `SECURITY.md`（GitHub 私密漏洞报告）。不要在公开 issue 里贴利用细节、分区镜像、IMEI/ICCID、号码、短信、密钥。

## 5. 支持窗口与响应时间

**TODO（项目负责人决定，这里没有替你定）**：

- 哪些 Agent 版本线、哪些系统镜像在多长时间内获得安全修复；
- 从确认漏洞到发布修复的目标时间；
- Debian 基础系统多久刷新一次快照（每次都是一份新镜像）；
- 密钥轮换的周期与重叠期的发布数 N；
- 不再支持的版本如何告知用户。

在这些写下来之前，本项目**不承诺**任何支持期限；README 的表述（开发者源码版，不是量产固件）仍然是准确的。

## 6. SBOM

`build/sbom/sbom.spdx.json`（随 Factory 包与 OTA 发布一起提供）列出链接进 Agent 的 Go 模块及版本、内核与参考构建仓库的固定版本。Debian 软件包：rootfs 锁已解析时逐包列出（名称、版本、架构、源码包、.deb 的 SHA-256，`pkg:deb/debian/…` purl）；锁未解析时 Debian 条目写明 `not included: rootfs lock unresolved`，不列任何猜测的包。SBOM 里的 Debian 列表是**锁**固定的集合；某个具体包的实际内容以它自己的 `DEBIAN-PACKAGES.txt` 与 `PACKAGE-MANIFEST.json` 的 `rootfs.statement` 为准。用它回答“这个 CVE 影响我们吗”时，先确认手里的镜像是 `built from lock <同一个哈希>`。
