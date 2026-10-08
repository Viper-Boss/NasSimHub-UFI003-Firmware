# 发布流程：构建 → 打包 → 签名（仓库外）→ 校验 → 发布

本文覆盖两类产物：

- **Factory 包**（`dist/factory/<版本>-<变体>/`）：系统镜像输入，含 Factory Agent、systemd 单元、默认配置，以及（只在提供时）发布公钥文件。
- **OTA 发布**（`dist/ota/<release-id>/`）：只更新 Agent 可执行文件。更新机制不写 boot、设备树、基带分区或根文件系统（`node/agent/ota/ota.go` 包注释）。

状态：脚本与 Agent 的 OTA 逻辑都有离线测试（`sh scripts/check.sh`）。**整条链路在 UFI003 上 未在真机验证 / not yet verified on hardware**，验收清单见 [VALIDATION.md](VALIDATION.md)。所有脚本离线运行，不联网、不刷机、不写设备。

## 0. 红线

- 发布**私钥**永远不进仓库、不进 `build/`、`dist/`、不进任何镜像。脚本只从环境变量拿私钥目录路径，路径在任何仓库内就拒绝（`scripts/package-ota.sh`；`nsh-release keygen` 同样拒绝，见 `node/agent/cmd/nsh-release/main.go` 的 `insideRepository`）。
- 开机按键长按约 5 秒是 Qualcomm 9008/EDL，是硬件既有行为。**绝不把任何功能（恢复出厂、回滚、配网、重置）绑定到这个动作上。**
- **绝不写** modemst1 / modemst2 / fsg / fsc / persist，也不写设备 NV。本仓库没有任何脚本会打开块设备；更新机制只能替换 Agent。
- 没在真机做过的事不写成“已验证”。

## 1. 生成与保管发布密钥（一次性，发布负责人，仓库外）

`nsh-release` 是发布者工具，从 `node/agent/cmd/nsh-release` 构建（`scripts/package-ota.sh` 会自动构建到 `build/tools/`，也可自行构建）。双签需要 Go ≥ 1.27（ML-DSA 来自标准库 `crypto/mldsa`，见 `node/proto/pqmldsa_go127.go`）。

~~~sh
# KEYDIR 必须在所有仓库之外，例如离线介质上的目录
nsh-release keygen  -dir "$KEYDIR" -key-id release-2026 -pq ml-dsa-87   # 或 -pq ml-dsa-65 / -pq none
nsh-release keyring -dir "$KEYDIR" -out ota-keys.json                   # 只含公钥
python3 scripts/privacy-check.py --public-keyring ota-keys.json         # 确认它确实只含公钥
~~~

- `keygen` 在 `KEYDIR` 写 `<id>.ed25519.key`（及 `<id>.mldsa.key`），权限 0600，已有同名钥匙时拒绝覆盖，不打印私钥。
- `keyring` 输出的 `ota-keys.json` 是**公钥**文件，是唯一应该离开 `KEYDIR` 的东西。
- 保管：`KEYDIR` 离线保存并有备份；能读到它的人就能给所有信任该公钥的设备签发更新。钥匙丢失不可恢复，只能轮换（见 §6）。

## 2. 构建（可复现）

~~~sh
sh scripts/build-agent.sh 1.15.1        # 或 VERSION=1.15.1 sh scripts/build-agent.sh
~~~

产出 `build/nassimhub-agent`（静态 linux/arm64）、`build/BUILDINFO.json`（版本、Go 版本、GOOS/GOARCH、`node/` 内容哈希、该工具链是否有 ML-DSA、是否使用了提交的 go.mod）、`build/SHA256SUMS`、`build/sbom/`。

- 版本经 `-ldflags "-X main.version=..."` 写入；必须是设备能比较的版本号（`node/proto/compat.go` 的 `ParseVersion`：最多三段数字，可带 `v` 前缀和 `-后缀`）。**不带版本构建出的是 `dev`，这样的 Agent 永远不安装也不启动更新**（`node/agent/cmd/nassimhub-agent/main.go`：`Disabled: !settings.Updates || version == "dev"`）。
- 可复现：`-trimpath -buildvcs=false`、`CGO_ENABLED=0 GOOS=linux GOARCH=arm64`、`GOWORK=off`，不写入构建时间。同一源码、同一 Go 版本，两次构建逐字节相同；`sh scripts/test-reproducible-build.sh` 在不同路径、空构建缓存下构建两次并比较。
- 正式发布使用仓库里提交的 `go.mod`，`BUILDINFO.json` 里 `go_mod` 为 `committed`。`NSH_GO_FLAGS`（例如 `-modfile=...`）只给离线测试环境用，这样构建出来的 `go_mod` 是 `override`，不要发布。
- 第三方许可证：构建同时生成 SPDX 2.3 SBOM 并执行许可证策略，见 §10。

## 3. 打包

### 3.1 OTA

~~~sh
sh scripts/package-ota.sh 1.15.1 stable agent-1.15.1     # VERSION CHANNEL(stable|beta) RELEASE_ID
~~~

没有提供密钥时，脚本写出 `nassimhub-agent`、`BUILDINFO.json`、未签名的 `manifest.json`、`SHA256SUMS`，然后**停下**并打印给发布负责人的确切命令。版本必须与 `BUILDINFO.json` 记录的一致，否则拒绝：设备会用 `-version` 运行暂存的二进制，与清单不一致就拒绝更新（`node/agent/ota/installer.go` 的 `Validate`）。

版本号规则（`node/proto/ota.go` 的 `CheckManifest`）：设备拒绝数字版本不高于当前运行版本的发布；比较时忽略 `-后缀`，所以 `1.15.1-a` → `1.15.1-b` **不算**升级。

### 3.2 Factory

~~~sh
sudo ROOT_SPEC=LABEL=rootfs NSH_OTA_KEYS=/path/ota-keys.json SOURCE_URL=https://... \
  sh scripts/package-factory.sh /path/to/clean-rootfs /path/to/boot.img Lite    # 或 Dev
~~~

- `NSH_OTA_KEYS` 可省略：镜像里就没有 `/etc/nassimhub/ota-keys.json`，包清单写 `updates disabled: no release keys`，设备报告更新不可用。**没有公钥的设备 = 不支持更新**，不是“以后再补”，补的唯一途径是刷带公钥的新系统镜像。
- `NSH_ROOTFS_MANIFEST=/path/ROOTFS-MANIFEST.json` 可省略：给出 `scripts/build-rootfs.sh` 为这个 rootfs 目录写的清单时，脚本重新计算目录树哈希、核对 boot 镜像，包清单与终端写 `rootfs: built from lock <sha256>`（`--unlocked` 的产物写“不可复现、不是发布输入”），并用固定 UUID/hash seed/时间戳生成可逐字节重复的 `rootfs.img`。不给时写 `rootfs: operator-supplied (unverified provenance)`，镜像生成方式与以前相同。见 [ROOTFS-BUILD.md](ROOTFS-BUILD.md)。**仓库里的 rootfs 锁尚未解析**，所以目前没有任何包能写出 `built from lock`。
- `NSH_SETUP_AP=on|off`（默认 `off`）：是否把配网热点的镜像侧前置条件打进镜像并启用热点，见 §11。默认关闭时包清单写 `setup access point: not enabled`；打开时写 `setup access point: enabled (not verified on hardware)`。写成 `on`/`off` 以外的值会被拒绝。
- `SOURCE_URL` 可省略：`SOURCE.md` 会如实写“未提供源码位置”，由分发者负责随包提供对应源码（AGPL-3.0 第 6 条）。
- 包内容：`images/`（rootfs.img、boot.img）、`rootfs-overlay/`（叠加到干净 rootfs 上的全部文件，便于审核）、`PACKAGE-MANIFEST.json`（每个文件的大小、SHA-256、权限）、`SHA256SUMS`、`LICENSE`、`LICENSES/`、`NOTICE.md`、`THIRD-PARTY-NOTICES.md`、`SOURCE.md`、`sbom.spdx.json`、`BUILDINFO.json`、`DEBIAN-PACKAGES.txt`。
- 打包过程三次把关：干净 rootfs 审核 → 合成目录树审核 → 成品包通用性检查；任何一步失败都不产出包（最后一步失败时目录改名为 `*.REJECTED`）。镜像里带什么、首启生成什么见 [FIRST_BOOT.md](FIRST_BOOT.md)。
- Factory 包本身**没有签名**（`SHA256SUMS` 只保证完整性，不保证来源）。

### 3.3 Lite / Dev 对照

只列出仓库里**有实现**的差别；没有实现的写“未实现”，不暗示存在。

| 项目 | Lite | Dev |
|---|---|---|
| Factory Agent、Agent 单元及覆盖、默认配置 | 有 | 有 |
| 持久分区挂载与检查、首启目录权限、USB NCM（开发用 USB ID）、NetworkManager/polkit 规则 | 有 | 有 |
| 发布公钥文件、状态分区去掉 noexec | 仅在提供 `NSH_OTA_KEYS` 时 | 仅在提供 `NSH_OTA_KEYS` 时 |
| 可选通话部署源文件（`node/deploy/audio/*`）放在 `/usr/share/nassimhub/voice-deploy`，**不安装、不启用** | 无 | 有 |
| 镜像内启用通话/VoLTE 音频 | 未实现（只能逐设备验收后安装） | 未实现（同左） |
| `hold-cs-voice` 可执行文件 | 未实现 | 未实现（只有源码，需要 aarch64 C 编译器） |
| 按变体选择音频 DTB / q6 内核模块 | 未实现（boot 镜像由打包者提供） | 未实现 |
| 按变体选择 SSH、串口控制台、调试工具 | 未实现（打包脚本不安装任何 Debian 软件包） | 未实现 |
| 精简体积的 rootfs | 未实现（两种变体用同一个输入 rootfs） | — |
| 配网热点（setup access point）及其镜像侧前置条件 | 仅在 `NSH_SETUP_AP=on` 时；默认不带、不启用。**未在真机验证**（§11） | 同左 |
| 正式 USB VID/PID、Factory 包签名、系统镜像级 OTA | 未实现 | 未实现 |

## 4. 签名（发布负责人，持钥机器，仓库外）

~~~sh
NSH_RELEASE_KEY_DIR=/path/outside/any/repository/release-keys \
NSH_RELEASE_KEY_ID=release-2026 NSH_RELEASE_PQ_KEY_ID=release-2026 \
NSH_OTA_KEYS=/path/ota-keys.json \
  sh scripts/package-ota.sh 1.15.1 stable agent-1.15.1
~~~

- 对已存在的 `manifest.json` 签名（不重新生成），写出 `manifest.signed.json`：Ed25519，给了 `NSH_RELEASE_PQ_KEY_ID` 时再加 ML-DSA（双签）。两个签名覆盖同一段清单字节（`node/proto/ota.go`）。
- `NSH_OTA_KEYS` 指向**设备上实际安装的那份公钥文件**时，校验才有意义：用设备不信任的钥匙签出来的发布，对着自己的钥匙目录能过，却装不到任何设备上。不提供时脚本从钥匙目录导出公钥来校验。
- 钥匙目录只读取；脚本不复制、不打印私钥，也不在其中写任何文件。

## 5. 校验与发布

签名后脚本立即像设备那样校验（`nsh-release verify`：公钥文件 + 制品哈希；双签时加 `-require-pq`），校验不过就不留下 `manifest.signed.json`。也可以单独复核：

~~~sh
nsh-release verify -signed dist/ota/agent-1.15.1/manifest.signed.json -keys ota-keys.json \
  -binary dist/ota/agent-1.15.1/nassimhub-agent -require-pq
(cd dist/ota/agent-1.15.1 && sha256sum -c SHA256SUMS)
python3 scripts/privacy-check.py --ota-release dist/ota/agent-1.15.1
~~~

发布：把 `manifest.signed.json` 和 `nassimhub-agent` **原样**交给 NAS 网关导入（NAS 仓库的 Node 更新接口；网关只是搬运，接受与否由设备用自己的公钥决定）。`manifest.signed.json` 不能被格式化、重新缩进或重排字段，否则两个签名都失效（`nsh-release` 包注释）。

设备侧签名策略：`ota_signature_policy = preferred` 接受只有经典签名的发布并如实标注；`required`（或安全级别 PQ_EXTREME）拒绝没有有效 ML-DSA 签名的发布（`node/agent/cmd/nassimhub-agent/main.go` 的 `updateSignaturePolicy`）。

## 6. 密钥轮换

设备只从 `/etc/nassimhub/ota-keys.json` 读公钥，Agent 的服务用户无权改它（`node/agent/ota/keyring.go`）。更新机制只能换 Agent，**不能**换这个文件。所以：

1. 在仓库外 `keygen` 新钥匙（新的 key id）。
2. `keyring` 导出同时包含新旧公钥的 `ota-keys.json`（钥匙目录里新旧私钥都在时自动如此）。
3. 用它打新的 Factory 包并刷系统镜像；轮换**只能**随系统镜像下发。
4. 之后的发布用新钥匙签。确认没有设备还只信任旧钥匙后，再出一版只含新公钥的镜像。

没刷新镜像的设备仍然只信任旧钥匙。旧钥匙一旦泄露，没有远程吊销手段：只能重刷镜像。

完整的生成仪式、公钥公布（`scripts/publish-keys.sh` → `release-keys.json`，**未签名**，真实性来自发布渠道）、重叠轮换的限制（清单只有一个 `key_id`）、撤销的现状与建议扩展、泄露处置、以及网关/Agent/清单/策略的能力矩阵，见 [KEY-MANAGEMENT.md](KEY-MANAGEMENT.md)。安全修复怎样到达设备见 [SECURITY-UPDATES.md](SECURITY-UPDATES.md)。Go 1.27 的 Docker 镜像 tag 与 digest 由发布工程师从镜像仓库读取核对后再提交（`docker buildx imagetools inspect golang:1.27.x-bookworm`），文档与脚本里都没有预先写入的 digest。

## 7. systemd 与文件权限要求

| 要求 | 原因 | 现状 |
|---|---|---|
| `Restart=always` | 应用更新、回滚都是 Agent **干净退出**，靠 systemd 重新拉起，再由 Factory Agent 决定运行哪个版本（`main.go`、`node/agent/ota/updater.go`）。`on-failure` 会让更新后的设备停着不动 | `node/deploy/nassimhub-agent.service` 已是 `Restart=always`、`RestartSec=5` |
| 状态分区允许执行 | 发布版本存放在 `/var/lib/nassimhub/agent-releases/<id>/nassimhub-agent`，暂存后先执行 `-version` 验证，启动时由 Factory Agent `exec`（`installer.go`、`boot.go`） | 基础挂载单元是 `noexec`；带公钥打包时安装 `firmware/ota-overlay` 的覆盖去掉 `noexec`（保留 `nosuid,nodev`）。不带公钥时保持 `noexec`。**未在真机验证** |
| `/etc/nassimhub/ota-keys.json` root:root 0644 | Agent 用自己改不了的钥匙校验更新 | 打包脚本按此安装，`audit-rootfs.py` 拒绝组或其他人可写 |
| `/etc/nassimhub` 服务用户不可写 | 同上；配置也不该被服务改写 | 目录 root:root 0755；单元里 `ProtectSystem=strict`，`ConfigurationDirectory=` 不会把目录属主改成服务用户 |
| Factory Agent 不可被服务用户改写 | 它是永远能启动的兜底 | `/usr/bin/nassimhub-agent` root 所有 0755 |
| 版本不是 `dev` | `dev` 关闭整个更新机制 | 打包脚本拒绝 `dev` |

`node/deploy/audio/install-voice.sh` 自 r128 起默认**保留** `/usr/bin/nassimhub-agent`，只有显式的 `--replace-agent FILE --expect-sha256 HEX` 才替换它，并拒绝 `dev`/不可比较/更旧的版本。行为、检查与离线测试见 §12。

## 8. 回滚（按实现）

以下全部来自 `node/agent/ota/`（`ota.go`、`boot.go`、`installer.go`、`updater.go`）与 `node/proto/ota.go`，有离线测试，**未在真机验证**。

- **切换是原子的**：`agent-releases/current` 符号链接用 rename 切换；切换前先记下回滚目标。断电只会留下旧链接或新链接。
- **确认窗口 10 分钟**（`OTAConfirmWindow`）：应用后新版本处于待确认状态，NAS 在设备带着清单承诺的版本重新上线后确认，也可手动确认。
- **自动回滚**的情形：
  - 窗口内没人确认：运行中的 Agent 每 30 秒检查一次，超时即回滚并重启（`Supervise`）；
  - 新版本启动后在确认前又重启了一次（第二次重启视为新版本起来又死了）；
  - 起来的不是清单承诺的版本；
  - 切换过程被打断；
  - 新版本无法执行：取消选中，Factory Agent 自己继续运行。
- **每次启动都重新校验**：Factory Agent 用公钥重新验证选中版本的签名与二进制哈希，验不过就取消选中、自己运行；状态目录里的文件不因为“已经在那儿”就被信任。
- **手动回滚**只对“已应用、未确认”的更新有效。确认之后回滚目标被清除，旧版本目录被清理。
- **Factory 下限（不降级）**：发布版本不得低于系统镜像里 Factory Agent 的版本，否则启动时拒绝运行。刷了更新的系统镜像之后，状态分区里残留的旧发布不会把它悄悄降回去。
- **同一发布最多尝试 3 次**（`MaxAttempts`）。
- 回滚到的是“上一个运行的版本”：上一个发布，或 Factory Agent。

## 9. 恢复说明

按从轻到重排列。**都未在真机验证**；步骤 1–3 只动 Agent 自己的文件，不碰分区。

1. 等：未确认的更新 10 分钟内会自己回滚。
2. 强制运行 Factory Agent：在 `/etc/nassimhub/agent.conf` 写 `updates = false` 后 `systemctl restart nassimhub-agent`。此时无论状态分区里有什么，都运行系统镜像里的 Agent（`node/agent/ota/launch.go`：`Disabled means the factory agent runs, whatever is on disk`）。排查完改回 `true`。
3. 取消选中的发布：`rm /var/lib/nassimhub/agent-releases/current` 后重启服务，Factory Agent 运行。**不要删除** `device.json`、`pairing.json` 等身份文件，重置身份不是修复手段。
4. 用户态整体恢复：见 [INSTALL.md](INSTALL.md) 的回滚一节。
5. 系统镜像恢复：重刷本板型审核过的 rootfs/boot；持久分区（NSHSTATE）保留则身份与配对保留。

永远不做的事：

- **不绑定** 开机长按约 5 秒（9008/EDL）到任何 NasSimHub 功能，也不在文档里把它当作日常恢复入口；EDL 只是硬件救援手段，需要本板正确的 programmer 和本人备份。
- **不写** modemst1 / modemst2 / fsg / fsc / persist，不克隆他人 NV 或校准数据；Factory 包里出现这些名字会被 `privacy-check.py --package` 拒绝。

## 10. SBOM 与许可证

- `python3 scripts/sbom.py generate --agent build/nassimhub-agent`：SPDX 2.3 JSON。Go 模块取自二进制本身（`go version -m`，即实际链接进去的），许可证从模块源码目录里的许可证文件按文本识别；识别不了或没有许可证文件就记 `NOASSERTION`，**不猜**。另列出 `firmware/upstream.lock.json` 里的非 Go 组件（Debian 基线、内核、参考构建仓库），它们的许可证不在此断言。Debian 软件包：`firmware/rootfs.lock.json` 已解析时逐包列出（名称、版本、架构、源码包、.deb 的 SHA-256）；未解析时 Debian 条目写明 `not included: rootfs lock unresolved`，不列任何包。
- 许可证策略 `scripts/licence-policy.json`：模块许可证缺失、未知或不在允许列表里即失败，除非在 `allowlist` 里按“模块 + 版本”登记并写明理由。`build-agent.sh` 构建时执行，`package-factory.sh` 打包时复查。
- SPDX 覆盖：`python3 scripts/sbom.py spdx-coverage`。`scripts/`、`node/` 没有文件头，`kernel/` 只有部分文件有；没有去改几百个文件头，而是用 `LICENSES/spdx-map.json` 把 `LICENSES/README.md` 已经写明的归属做成可检查的路径映射（文件自带的 SPDX 头优先）。它不改变任何文件的许可证。

## 11. 配网热点（setup access point）的镜像侧前置条件

Agent 的配网热点逻辑在 `node/agent/netbackend/networkmanager/setupap.go`（设计见 Node 仓库 `docs/WIFI_PROVISIONING.md`）。Node 侧报告说“今天的镜像上热点起不来”，给了三条理由。下面逐条对着本仓库的文件核对；**能核对的是文件里写了什么，NetworkManager / polkit / 内核在棒子上的实际行为一条都没有在真机验证**。

| Node 侧的说法 | 对着文件核对的结果 |
|---|---|
| (a) polkit 规则没有授予 `org.freedesktop.NetworkManager.wifi.share.protected` | **属实。** `firmware/overlay/etc/polkit-1/rules.d/49-nassimhub-networkmanager.rules` 只列了 `network-control`、`settings.modify.system`、`wifi.scan` 三项。热点配置是 `ipv4.method shared` 加 WPA2-PSK（`setupap.go` 的 `startAP`）；按 NetworkManager 的授权逻辑，激活“共享”的 Wi-Fi 配置除 `network-control` 外还要 `wifi.share.protected`（有无线加密时）或 `wifi.share.open`（无加密时）。后一句来自 NetworkManager 的公开行为，本容器里没有它的策略文件可以对照，也没有实测 |
| (b) 配网页面监听 `192.168.4.1:80`，而 Agent 是非特权用户且 `CapabilityBoundingSet` 为空 | **属实。** `node/agent/internal/provisioning/provisioning.go`：`DefaultListenAddress = "192.168.4.1:80"`，`main.go` 没有传别的地址，也没有配置项可改；`node/deploy/nassimhub-agent.service`：`User=nassimhub`、`CapabilityBoundingSet=`、`AmbientCapabilities=`（都为空）。本仓库的 overlay 里没有任何 sysctl 文件，所以内核默认的 `net.ipv4.ip_unprivileged_port_start=1024` 生效，绑定 80 端口会得到 EACCES。Agent 这时会记一条 `the access point is up but the setup page cannot listen`（同文件） |
| (c) 镜像里可能没有 `dnsmasq` | **无法从仓库判定，按“可能没有”处理。** 本仓库不安装任何 Debian 软件包；`docs/INSTALL.md` 原来的软件包清单里没有 `dnsmasq-base`，而 Debian 的 `network-manager` 对它只是“推荐”（Recommends）关系——这一点凭对 Debian 打包的了解写出，没有在本容器内对照 Debian 13 的 control 文件——`debootstrap` 默认不装推荐包。现在该要求记在 `firmware/debian-packages.json` 与 INSTALL.md，打包脚本在 `NSH_SETUP_AP=on` 时检查输入 rootfs 里有没有 `/usr/sbin/dnsmasq` |

另外两处核对时发现、但不属于这三条的事实：

- 出厂配置 `node/deploy/agent.conf` 里是 `provisioning = false` **和** `provisioning_ap = off`。`main.go` 里 `provisioning = false` 会把热点一并关掉，所以只改 `provisioning_ap` 不够。
- 热点口令由设备首次需要时生成，存在 `/var/lib/nassimhub/setup-ap-passphrase`（0600）。当前快照里没有任何界面或 API 显示它（`SetupAPCredential` 没有被 `localadmin` 调用），只能经 USB 维护连接读文件。**即使镜像侧条件全部满足，普通用户目前也用不了这个热点。**

### 11.1 作为可选片段提供：`firmware/setup-ap-overlay/`

与 `firmware/ota-overlay/` 的做法相同：默认不进镜像，只有 `NSH_SETUP_AP=on` 时由 `scripts/package-factory.sh` 叠加。片段只有两个文件：

| 文件 | 内容 |
|---|---|
| `etc/polkit-1/rules.d/48-nassimhub-setup-ap.rules` | 只对用户 `nassimhub`、只授予 `org.freedesktop.NetworkManager.wifi.share.protected` |
| `etc/systemd/system/nassimhub-agent.service.d/setup-ap.conf` | `CapabilityBoundingSet=CAP_NET_BIND_SERVICE`、`AmbientCapabilities=CAP_NET_BIND_SERVICE`，外加三条 `SocketBindDeny=` |

`NSH_SETUP_AP=on` 时打包脚本还做三件事：把**包内那一份** `agent.conf` 改成 `provisioning = true`、`provisioning_ap = auto`（`node/deploy/agent.conf` 本身不动；只改这两个键，`scripts/imagepolicy.py` 的 `enable_setup_ap`，改完用 Agent 自己的 `-check-config` 在测试里验证）；要求输入 rootfs 有 `/usr/sbin/dnsmasq`；在包清单 `setup_access_point` 里写明启用状态、加了哪个 polkit 动作、哪个 capability、需要哪个软件包，以及 `verified_on_hardware: false`。

### 11.2 polkit：热点路径用到的全部动作

`nmcli` 以 `nassimhub` 身份、无登录会话运行，polkit 默认策略对这类主体不放行，所以每个动作都要显式授予。热点从启动到停止用到的动作，以及各自由谁授予：

| 动作 | 热点为什么需要 | 由谁授予 |
|---|---|---|
| `…NetworkManager.settings.modify.system` | `connection delete` / `connection add`：每次启动都重建 `nassimhub-setup-ap` 配置 | 基础规则（已有，加入网络同样需要） |
| `…NetworkManager.network-control` | `connection up` / `connection down`：启停热点 | 基础规则（已有，加入网络同样需要） |
| `…NetworkManager.wifi.scan` | 启动热点前的最后一次扫描 | 基础规则（已有） |
| `…NetworkManager.wifi.share.protected` | 激活带加密的共享 Wi-Fi 配置 | **片段新增，仅此一项** |

没有授予、也不应授予的：`wifi.share.open`（Agent 从不创建开放热点；不授予则 NetworkManager 自己也会拒绝）、`enable-disable-network` / `enable-disable-wifi` / `enable-disable-wwan`、`settings.modify.global-dns`、`settings.modify.hostname`、`reload`、`checkpoint-rollback`。

关于“不要整体授予 `network-control`”：片段**没有**授予它。它在基础规则里早已存在，是客户端加入网络（已在真机运行）所必需的；NetworkManager 没有比它更窄的“激活某个连接”的动作，所以无法再收窄，这里只是如实说明它的范围：它允许该用户启停任意连接和设备，不限于 Wi-Fi。

强制手段：`scripts/imagepolicy.py` 里按文件登记了“允许授予的动作 + 理由”。`scripts/audit-rootfs.py` 在打包时检查 rootfs 里每个提到 `nassimhub` 的 polkit 规则文件：不在登记表里的文件、授予了登记表以外动作的规则、授予给别的用户的规则、以及形状不是“用户 + 动作名单”的规则（前缀匹配、无用户判断、正则等）一律失败；片段的两个文件在没有 `--setup-ap` 时出现也失败。`scripts/test-setup-ap-overlay.sh` 另外在 JavaScript 引擎里实际执行每个规则文件，对照登记表检查它的判定。

### 11.3 80 端口：三种做法的比较

| 做法 | 影响范围 | 结论 |
|---|---|---|
| 单元覆盖里 `AmbientCapabilities=CAP_NET_BIND_SERVICE` + 相同的 `CapabilityBoundingSet` | 只有 Agent 这一个服务拿到一个 capability。它允许绑定 1024 以下的任意端口，所以再用 `SocketBindDeny=` 把 80/tcp 以外的低端口全部拒绝 | **采用** |
| sysctl `net.ipv4.ip_unprivileged_port_start=80` | 全系统、所有用户、所有网络命名空间都能绑定 80–1023（包括 443 等）；与热点是否开启无关，永久生效 | 不采用；`audit-rootfs.py` 发现任何 sysctl 文件设置它就失败 |
| systemd socket 单元监听 80，把套接字交给 Agent | 权限最小（Agent 完全不需要 capability） | 现在做不到：Agent 不接受继承的监听套接字（源码里没有 `LISTEN_FDS`），而且它只在热点起来时才监听、连上网络后就关闭，`192.168.4.1` 在热点起来之前也不存在。需要 Node 侧改代码，已列入给 Node 负责人的事项 |

选第一种的其他理由：ambient capability 不依赖文件 capability，也能跨过 Factory Agent `exec` 已安装发布的那一步（`node/agent/ota/boot.go` 的 `Chain`），所以更新后的 Agent 仍能监听；`NoNewPrivileges=yes` 不影响 ambient capability。基础单元里的其余加固行一行未动：`scripts/test_tools.py` 的 `test_fragment_changes_the_capability_and_nothing_else` 比较带片段和不带片段时单元的全部生效设置，只允许 `CapabilityBoundingSet`、`AmbientCapabilities`、`SocketBindDeny` 三项不同。

`SocketBindDeny=` 依赖内核的 cgroup BPF（`CONFIG_CGROUP_BPF`）。棒子的内核是否带它没有核实；不带时 systemd 记一条警告并忽略这三行，此时 Agent 能绑定 1024 以下的任意端口。验收清单里有一步专门判断是哪种情况。

### 11.4 没有做的

- 没有在真机上启动过热点。片段解决的是“文件里缺什么”，不是“热点能用”。射频与驱动是否支持 AP 模式（`iw list`）、NetworkManager 的 shared 模式在这颗内核上能否配好地址转换，都要按 [VALIDATION.md](VALIDATION.md) 验收。
- NetworkManager 的 shared 模式还会自己配置防火墙/NAT 规则（需要 nftables 或 iptables）。手机只访问 `192.168.4.1` 本机，不需要转发；但缺少这些工具时 NetworkManager 是报警告还是激活失败，没有核实。
- 口令的界面展示、mDNS/证书地址的动态刷新属于 Node 侧。

## 12. `install-voice.sh` 与 Factory Agent

`/usr/bin/nassimhub-agent` 是 OTA 设计里的“系统镜像里的 Agent”：更新从不改写它、每次启动都从它开始、已安装发布的版本不得低于它（`node/agent/ota/boot.go` 的 `VerifyRelease` / `Boot`、`launch.go` 的 `Launch` 与 `NotAReleaseVersion`、`node/proto/compat.go` 的 `ParseVersion`）。r127 之前 `node/deploy/audio/install-voice.sh AGENT HOLDER` 会无条件用第一个参数覆盖它。**r128 起脚本已改**（原 `docs/proposed/install-voice-keep-factory-agent.patch` 已删除，由真正的修改取代）；以下全部来自源码与离线测试（`sh scripts/test-install-voice.sh`；Node 仓库 `test/voiceinstall`），**未在真机验证**。

### 12.1 现在的行为

| 调用 | 结果 |
|---|---|
| `install-voice.sh HOLDER` | 只安装 holder、查询脚本、unit/timer、polkit 规则、`voice.conf`；**不碰** `/usr/bin/nassimhub-agent`。`-voice-media -check-config` 由已安装的 Agent 执行 |
| `install-voice.sh AGENT HOLDER`（旧写法） | 拒绝，提示新写法；不做任何改动 |
| `install-voice.sh --replace-agent FILE --expect-sha256 HEX HOLDER` | 通过下列全部检查后才替换 Factory Agent，并备份原来的 |

替换前的检查（任一不过即退出，此时没有停止 Agent、没有写任何文件）：

| 检查 | 拒绝的理由 |
|---|---|
| `sha256sum FILE` 等于 `--expect-sha256`（装入的临时文件在改名前再核对一次） | 可校验：装进去的就是发布负责人点名的那个二进制 |
| `FILE -version` 的版本能被 `proto.ParseVersion` 解析 | `dev`、`voice-test`、四段版本等不是发布版本：这样的 Factory Agent 不运行任何已安装发布、不接受任何更新，也不能作为下限（`NotAReleaseVersion`） |
| 版本不低于现有 Factory Agent | 下限不下移；没有绕过开关。现有 Agent 本身不是发布版本时无从比较，脚本说明后放行 |
| 版本不高于状态分区里选中的发布，除非 `--supersede-release` | 新的 Factory Agent 启动时会把比它旧的发布取消选中（`VerifyRelease` 的下限规则） |
| 更新状态不是 `APPLYING` / `PENDING_CONFIRM` / `ROLLING_BACK`（保留模式同样检查） | 脚本要停止并重启 Agent；确认前的再次重启会被判为更新失败并回滚 |

脚本里的版本解析是 POSIX shell 写的。它与 `proto.ParseVersion` 是否一致不靠审阅：`node/scripts/install-voice-versions.tsv`（本仓库 `scripts/` 下有相同副本）里的每个字符串，加上 4000 个生成的字符串（含各种 Unicode 空白、非 ASCII 数字、64 位上限两侧的数、非 UTF-8 字节、shell 元字符），同时喂给两边，要求接受/拒绝与三段数值完全相同；另取约两万对版本比较大小，要求与 `Version.Compare` 相同。Go 测试在 Node 仓库 `test/voiceinstall`（只依赖 `proto`）。

### 12.2 谁在重启后提供服务

脚本在改动前和结束时各打印一次预期，并在结束时读取服务主进程的可执行文件作为实际观察。判断顺序与 `Boot` 相同，但**不校验签名**（发布版本取自状态分区里清单的 `version` 字段）：

| 情形 | 脚本的说法 |
|---|---|
| 没有选中的发布 | Factory Agent |
| `updates = false` | Factory Agent；发布留在原处不启动 |
| Factory Agent 不是发布版本（`dev` 等） | Factory Agent；发布留在原处不启动（脚本同时给出警告） |
| 没有发布公钥文件 | Factory Agent；发布无法校验，会被 Agent 取消选中 |
| 选中的发布版本低于（新的）Factory Agent | Factory Agent；发布在启动时被取消选中（只有 `--supersede-release` 才会走到这里） |
| 其余 | **选中的发布**，不是 `/usr/bin/nassimhub-agent`；带 `-voice-media` 的启动参数原样传给发布（`Chain`） |

最后一行的含义没有变：发布若不含通话所需的代码，通话行为就是发布的行为。脚本现在在重启 3 秒后再查一次 `is-active`，发布因不认识参数而立即退出时会被发现，并触发完整还原。

### 12.3 失败与还原

每个文件先写到目标旁边的临时文件、再 `rename` 到位，且全部在停止 Agent **之前**备好。任何一步失败或收到 HUP/INT/TERM：恢复每个文件（包括“原来不存在”）、恢复 `local-volte.enabled` 的属主与权限、恢复两个 timer 原来的启用/运行状态、`daemon-reload`、重新启动被停掉的 Agent，以非零状态退出。离线测试对成功路径上的每一个步骤（保留模式 34 步、替换模式 45 步）各注入一次失败，并在改名过程中发送 TERM/HUP，逐次比较整棵目录树的类型、权限与 SHA-256。

脚本不写、不删状态分区：`agent-releases/`、`ota-state.json`、`device.json`、`pairing.json` 在所有测试用例前后逐字节比较。

### 12.4 仍然成立的事实

- 替换成功后，包清单与 `BUILDINFO.json` 记录的 Factory Agent 哈希不再对应设备上的文件；[VALIDATION.md](VALIDATION.md) 里“`/usr/bin/nassimhub-agent` 的哈希仍等于出厂哈希”的检查会失败，这是如实的结果。记录新的 `sha256sum /usr/bin/nassimhub-agent` 与版本。
- 回到镜像原来的 Agent：恢复 `/var/backups/nassimhub-voice-<时间>/` 里的 `agent`、`agent.conf`、`service.d` 后 `daemon-reload` 并重启，或重刷系统镜像。不要动 `/var/lib/nassimhub` 里的身份与配对文件。
- 重刷系统镜像会把 `/usr/bin/nassimhub-agent` 和 `voice.conf` 一起换回镜像里的内容；状态分区不动。
- 已经被旧脚本装上 `dev` Agent 的设备：新脚本在保留模式下会给出警告但不阻止安装；用 `--replace-agent` 换成 `scripts/build-agent.sh <版本>` 的构建即可恢复更新能力（状态分区里通过校验的发布会重新被运行）。
