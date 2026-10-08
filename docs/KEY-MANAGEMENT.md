# 发布密钥管理：生成、保管、公布、轮换、撤销与能力矩阵

本文只讲 **Node Agent 更新（OTA）的发布密钥**，以及与之并列、容易混淆的 NAS 网关自身的发布密钥。操作命令见 [RELEASING.md](RELEASING.md) 第 1、4、5、6 节；安全修复怎样到达设备见 [SECURITY-UPDATES.md](SECURITY-UPDATES.md)。

**状态**：本文全部由读源码和离线测试得出（`sh scripts/check.sh`，一次性测试密钥）。没有任何一步在真机上做过；没有真实的发布密钥存在于本仓库、交付 ZIP 或任何构建产物里，也**不应该**存在。私钥由发布方在仓库之外另行生成和保管。

## 1. 三把钥匙，三个位置

| 钥匙 | 用途 | 私钥 | 公钥放在哪里 | 谁读它 |
|---|---|---|---|---|
| Agent 发布钥（Ed25519，可选再加 ML-DSA-87/65） | 给 Agent 更新清单签名 | 发布方的 `KEYDIR`（`nsh-release keygen`，仓库外） | 设备镜像 `/etc/nassimhub/ota-keys.json`（root:root 0644，`NSH_OTA_KEYS` 打包时放入）；NAS 的 `MODEMDECK_NASSIMHUB_OTA_KEYS=/path`（同一个文件） | 设备：`node/agent/ota/keyring.go` `LoadKeyring`；NAS：`cmd/modemdeck/nassimhub_nodes.go` `openNodeReleaseStore`。两边都用 `proto.ParseOTAKeyFile`（`node/proto/ota_keyfile.go`） |
| NAS 网关自身的发布钥（Ed25519，与授权签发钥是同一把） | 给**网关自己**的发布清单签名 | 签发方机器（NAS 仓库 `cmd/licensegen`） | NAS 源码常量 `release.SigningPublicKey = license.IssuerPublicKey`（`internal/release/verify.go`） | NAS 自更新 |
| NAS 网关自身的后量子发布钥（ML-DSA-87） | 网关发布清单的第二签名 | `licensegen release-pq-keygen -out <file>`（仓库外） | NAS **构建时**常量 `release.PQSigningPublicKey`（`internal/release/pq.go`）；本树里是空字符串 | NAS 自更新；非空的构建**只**接受双签清单 |

后两把属于 NAS 仓库（独立许可证），固件仓库不生成、不保存、不使用它们；列在这里只为说明“设备镜像里的 `ota-keys.json`”与“NAS 构建时的 `PQSigningPublicKey`”不是同一件事：前者决定设备和 NAS 接受哪些 **Agent** 发布，后者决定 NAS 接受哪些 **NAS** 发布。

## 2. 生成仪式（仓库外）

1. 一台不联网、不是构建机的机器；`nsh-release` 用 Go ≥ 1.27 构建（否则无法生成 ML-DSA 钥匙：`node/proto/pqmldsa_pre127.go` 的 `NewMLDSASeed` 返回错误，`keygen` 明确失败而不是退化）。
2. `KEYDIR` 在任何版本库之外（`nsh-release keygen` 的 `insideRepository` 检查会拒绝；`scripts/package-ota.sh` 同样拒绝仓库内的钥匙目录）。
3. `nsh-release keygen -dir "$KEYDIR" -key-id release-<年份> -pq ml-dsa-87`：写 `<id>.ed25519.key`、`<id>.mldsa.key`（0600，`O_EXCL`，已存在就拒绝覆盖，不打印私钥）。**key id 一经公布永不复用**：`scripts/publish-keys.sh` 拒绝“旧 id、新公钥”。
4. `nsh-release keyring -dir "$KEYDIR" -out ota-keys.json`，再 `python3 scripts/privacy-check.py --public-keyring ota-keys.json`。离开 `KEYDIR` 的只有这个公钥文件。
5. 备份：`KEYDIR` 至少两份离线副本，分开存放；记录每个 key id 的公钥指纹（`release-keys.json` 里的 `sha256`）。钥匙丢失不可恢复，只能轮换。
6. 公布（第 3 节）。

保管原则：能读 `KEYDIR` 的人就能给所有信任这些公钥的设备签发 Agent。日常构建机、CI、NAS、设备上都不放私钥。签名在持钥机器上做（`package-ota.sh` 只读取钥匙目录）。

## 3. 公钥公布：`release-keys.json`

目的：让用户和 Codex 能把**镜像里的** `ota-keys.json` 与项目公布的钥匙核对。

~~~sh
sh scripts/publish-keys.sh ota-keys.json publish/ --note 'release-2026=2026 年起的发布钥'
#   → publish/release-keys.json   publish/release-keys.json.sha256
sh scripts/publish-keys.sh --check publish/release-keys.json /path/from/image/ota-keys.json --sha256 <公告里的哈希>
~~~

内容：每把公钥的 `key_id`、`algorithm`、`public_key`（base64）、公钥的 `sha256` 指纹、`status`、`validity_note`、`supersedes`；整份 `ota-keys.json` 的 SHA-256（可直接与 `sha256sum /etc/nassimhub/ota-keys.json` 比较）；已退役钥匙的列表与原因。

**这份声明没有签名。** 读过 `node/agent/cmd/nsh-release/main.go`：`sign` 子命令把输入按 `proto.OTAManifest` 解码并拒绝未知字段，只能给 Agent 更新清单签名；`proto.SignManifest`/`VerifyManifest` 没有域分隔，把别的文档塞进这个格式会制造“一个签名、两种含义”的风险。所以这里**没有发明签名格式**：声明的真实性来自它的发布渠道（签名的 git tag、发布页）以及在发布公告里重复的 SHA-256。从别处拿到的声明什么也证明不了，`--check` 不带 `--sha256` 时会明说这一点。

要让 `nsh-release` 能给声明签名，需要（建议，未实现）：

- `node/proto`：一个带域分隔的通用签名（例如消息前缀 `nsh-domain=release-key-statement-v1\n`，做法同 NAS 的 `internal/release/canonical.go` 的 `Domain`），以及声明的规范编码；
- `node/agent/cmd/nsh-release/main.go`：`sign-statement` / `verify-statement` 子命令；
- `scripts/publish-keys.sh`、`scripts/release_keys.py`：调用它并写入 `signatures` 字段；
- 测试：两种域的签名不能互相冒充（同 NAS 的 `TestTheTwoSignatureDomainsCannotBeConfused`）。

设备**不读**这份声明。它不增加、不过期、不撤销任何钥匙。

## 4. 轮换

事实（源码）：设备只从 `/etc/nassimhub/ota-keys.json` 读公钥，Agent 的服务用户不能写它；Agent 更新**只替换 Agent 可执行文件**（`node/agent/ota/ota.go` 包注释），**不能**替换这个文件。因此：

- 公钥文件只能随**系统镜像**（Factory 包，`NSH_OTA_KEYS`）到达设备。“用旧钥签一个带新公钥文件的 Agent 发布”这条路在当前实现里**不存在**。
- Factory 包本身没有签名（`SHA256SUMS` 只是完整性）。也就是说，新公钥文件的可信度来自刷机者对镜像来源的核对——这正是 `release-keys.json` 的用途。

重叠轮换的步骤：

1. 仓库外 `keygen` 新 key id（旧私钥仍在 `KEYDIR`）。
2. `keyring` 导出同时含新旧公钥的 `ota-keys.json`；`publish-keys.sh … --previous <上一份声明> --supersedes <新id>=<旧id>` 公布重叠期声明。
3. 用这份文件出系统镜像；**NAS 的 `MODEMDECK_NASSIMHUB_OTA_KEYS` 同步换成同一份文件**并重启网关（文件在启动时读取，读不全即拒绝启动：`TestNodeReleaseStoreKeyFileIsAllOrNothing`）。
4. 重叠期内发布用哪把钥签：清单格式只有**一个** `key_id` 和**一个** `pq_key_id`（`proto.OTASignedManifest`），不能同时带两把经典钥的签名。所以重叠期必须继续用**旧钥**签，直到确认所有需要更新的设备都已刷到含新公钥的镜像；之后改用新钥。想“同时发新旧两种签名”只能发布两个不同的 `manifest.signed.json`（同一个二进制、同一个 release id 的两份清单会被 NAS 的发布仓库拒绝：`ImportManifest` 的“a different manifest is already stored”），当前没有受支持的做法。
5. 重叠 N 个发布之后（N 由项目负责人定；仓库里没有这个策略，见 SECURITY-UPDATES.md 的 TODO），出一版只含新公钥的镜像，`publish-keys.sh … --retired <旧id>=<原因>`。从 `KEYDIR` 的在用副本里移走旧私钥（归档或销毁，由负责人决定）。

没有刷新镜像的设备始终只信任旧钥：轮换不会自动到达它们。

## 5. 撤销

**今天存在的**：从公钥文件里去掉一把钥匙 = 撤销，并且只在设备刷到**不含该钥的系统镜像**时生效；NAS 侧在换了 `MODEMDECK_NASSIMHUB_OTA_KEYS` 文件并重启后生效（此后网关拒绝导入用该钥签的发布；已存进 `node-releases/` 的发布每次读取都按**当前**钥匙重新校验——`internal/nassimhubnode/updates.go` 的 `describeLocked` 调用 `decode`——所以用被移除的钥签的旧发布此后校验失败、不再被当作可用发布，但文件仍留在目录里，由管理员移除）。

**今天不存在的**（直说）：

- 没有在线撤销列表，设备不向任何地方查询钥匙状态；
- 钥匙文件格式里没有逐钥的过期时间或“已撤销”标记：`OTAKeyFile` 只有 `version`、`ed25519`、`ml_dsa`，并且**拒绝未知字段**（`DisallowUnknownFields`）；
- Agent 更新无法下发新的钥匙文件；
- `release-keys.json` 的 `retired` 只是给人看的信息。

已安装的发布在每次启动时用**当时的**钥匙文件重新校验（`node/agent/ota/boot.go` `VerifyRelease`）：设备刷到不含旧钥的镜像后，用旧钥签的已安装发布会被取消选中，回到 Factory Agent。

**建议的扩展（未实现，只列出会改哪些文件）**：给钥匙加 `not_after`（过期）与 `revoked`（撤销，含时间与原因）。

| 文件 | 改动 |
|---|---|
| `node/proto/ota_keyfile.go` | `OTAKeyFile` 升 `version: 2`，每把钥匙从字符串变为对象 `{public_key, not_after?, revoked?}`；`ParseOTAKeyFile` 同时接受 v1；`EncodeOTAKeyFile` 输出 v2 |
| `node/proto/ota.go`、`ota_pq.go` | `OTAKeyring`/`OTAPQKeyring` 带上有效期；`VerifyManifest`/`VerifyManifestHybrid` 以清单的 `released_at` **和**设备当前时间判断（棒子没有电池时钟，必须写明时钟不可信时的行为） |
| `node/agent/ota/keyring.go`、`boot.go`、`ota.go` | 启动校验与状态里报告“钥匙已过期/已撤销” |
| `node/agent/cmd/nsh-release/main.go` | `keyring -not-after`、`keyring -revoke` |
| NAS：`node/proto` 的随带副本、`cmd/modemdeck/nassimhub_nodes.go`、`internal/nassimhubnode/updates.go` | 同步；界面显示 |
| `scripts/genericrules.py`（`public_keyring_problem`）、`scripts/release_keys.py`、`scripts/test_tools.py`、`scripts/test-publish-keys.sh` | 接受 v2 并测试 |
| 兼容性 | **旧 Agent 会拒绝 v2 文件**（未知版本 → 钥匙文件不可用 → 更新不可用但设备照常启动，`launch.go`）。因此 v2 文件只能放进其 Factory Agent 已能读 v2 的镜像；这一条必须先有测试 |

即使实现了，撤销仍然只随系统镜像到达设备，除非另做一条受签名保护的钥匙文件更新通道——那是另一项设计，这里不提议。

## 6. 泄露处置（playbook）

1. **立即**：停止用该钥签名；通知用户不要导入新的发布，直到公布新的声明。说明影响面：持有该私钥的人可以签出任何信任它的设备都会接受的 Agent（只要版本号更高、平台匹配）；Agent 以非特权用户运行，但能发短信、拨号、读写其状态目录。
2. NAS：把 `MODEMDECK_NASSIMHUB_OTA_KEYS` 换成不含该钥的文件并重启（此后用该钥签的已导入发布不再通过校验）；清理 `node-releases/` 里的残留。**没有设置这个变量的网关不校验任何东西**（`GatewayUnverified`），只能靠设备自己校验。
3. 设备：唯一的撤销手段是刷不含该钥的系统镜像。在刷之前可在设备上 `updates = false` 并重启服务，强制只运行 Factory Agent 且不接受任何更新（`launch.go` 的 `Disabled`）。
4. 生成新钥（新 key id），出新镜像，`publish-keys.sh … --retired <旧id>=compromised <日期>`，在签名的渠道上公布新声明及其 SHA-256。
5. 如果泄露的只是 Ed25519 而设备策略是 `required` 且 ML-DSA 钥未泄露：伪造的发布仍需要有效的 ML-DSA 签名，设备会拒绝——这是双签的意义；仍然要轮换。策略是 `preferred` 的设备没有这层保护。
6. 复盘：私钥是否进过仓库、镜像、构建产物（`privacy-check.py` 的包检查会拦截已知格式，但不是证明）。

如果泄露的是 NAS 的签发/发布钥：那把钥同时能签授权和网关发布（`internal/release/verify.go` 的注释写明了这个取舍），处置在 NAS 仓库的流程里，不在本文范围。

## 7. 能力矩阵

### 7.1 单侧规则（一切单元格由它推出）

`proto.VerifyManifestHybrid`（`node/proto/ota_pq.go`）对“经典签名有效、钥匙都在钥匙文件里”的清单：

| 这一侧的构建 | 清单 | 策略 | 结果 | 依据（测试） |
|---|---|---|---|---|
| 任意 | 仅经典 | preferred | 接受，`classical_only` | `TestAClassicalOnlyManifestIsAcceptedUnderPreferredAndNamed` |
| 任意 | 仅经典 | required | **拒绝**（`ErrOTAPQUnsigned`） | `TestRequiredRefusesAClassicalOnlyManifest` |
| Go < 1.27（无 `crypto/mldsa`） | 双签 | preferred | 接受，但结果是 `classical_only`：ML-DSA 签名**没有被检查**（`pq_key_id` 仍须在钥匙文件里且算法一致） | `TestABuildWithoutMLDSARefusesRequiredAndDoesNotClaimDual` |
| Go < 1.27 | 双签 | required | **拒绝**（`ErrOTAPQUnavailable`） | 同上 |
| Go ≥ 1.27 | 双签 | preferred / required | 接受，`dual_signed`；ML-DSA 签名损坏或 key id 未知时在**任何**策略下拒绝 | `TestADualSignedManifestVerifies`、`TestABrokenPostQuantumManifestSignatureFailsUnderEveryPolicy`、`TestAnUnknownPostQuantumKeyIDIsRefused` |

（以上测试在 `node/proto/ota_pq_test.go`。“Go < 1.27”由构建标签 `//go:build !go1.27`（`pqmldsa_pre127.go`）决定，对 1.24、1.25、1.26 相同；这里实际运行验证用的是 Go 1.24.7 与 1.27.1，**容器里没有 Go 1.26**。）

策略从哪里来：

- 设备：`ota_signature_policy`（默认 `preferred`）与安全级别取较严者，PQ_EXTREME 强制 `required`（`node/agent/cmd/nassimhub-agent/main.go` `updateSignaturePolicy`，`node/proto/seclevel.go` `OTARequirementFor`）。
- 网关：没有独立开关；`MODEMDECK_NASSIMHUB_SECURITY_LEVEL=PQ_EXTREME` 时 `required`，否则 `preferred`（`openNodeReleaseStore`）。**没有设置 `MODEMDECK_NASSIMHUB_OTA_KEYS` 时网关不校验**，发布标为 `gateway: "unverified"`，任何清单都会被搬运，由设备决定（`internal/nassimhubnode/updates.go` `decode`）。
- 网关用 Go < 1.27 构建且级别为 PQ_EXTREME：**拒绝启动**（`security level PQ_EXTREME needs ML-DSA…`，`startNasSimHubNodes`）。PQ_EXTREME 而钥匙文件里没有 ML-DSA 钥：拒绝启动（`openNodeReleaseStore`）。

### 7.2 网关 × Agent × 清单 × 策略

假设网关配置了钥匙文件，两侧策略相同（列“策略”）。“网关”列是导入发布时的结果，“设备”列是设备收到后的结果；网关拒绝时发布到不了设备。显示的字段：网关 `NodeRelease.gateway`（`verified`/`unverified`）与 `signatures`（`classical_only`/`dual_signed`）；设备 `OTADeviceStatus.signatures = {policy, outcome, pq_available, requires_toolchain}`（`proto.DescribeOTASignatures`）。

| 网关构建 | Agent 构建 | 清单 | 策略 | 网关 | 设备 | 最终 |
|---|---|---|---|---|---|---|
| 1.26 | 1.24–1.26 | 经典 | preferred | 接受，`classical_only` | 接受，`classical_only`，`pq_available: false`，`requires_toolchain: go1.27` | 安装；两侧都如实标注仅经典 |
| 1.26 | 1.24–1.26 | 经典 | required | —（网关在 PQ_EXTREME 下不启动） | 拒绝 `ErrOTAPQUnsigned` | 不安装 |
| 1.26 | 1.24–1.26 | 双签 | preferred | 接受，标 `classical_only`（未检查 ML-DSA） | 接受，标 `classical_only`（未检查） | 安装；**没有任何一方检查过后量子签名**，两侧都不会显示 `dual_signed` |
| 1.26 | 1.24–1.26 | 双签 | required | — 不启动 | 拒绝 `ErrOTAPQUnavailable` | 不安装 |
| 1.26 | 1.27 | 经典 | preferred | 接受，`classical_only` | 接受，`classical_only`，`pq_available: true` | 安装 |
| 1.26 | 1.27 | 经典 | required | — 不启动 | 拒绝 `ErrOTAPQUnsigned` | 不安装 |
| 1.26 | 1.27 | 双签 | preferred | 接受，标 `classical_only` | 接受，`dual_signed` | 安装；设备检查了两个签名，网关只检查了经典签名 |
| 1.26 | 1.27 | 双签 | required | — 不启动（若只在设备上设 `required`：网关按 preferred 接受并标 `classical_only`） | 接受，`dual_signed`（Factory Agent 须含 7.3 的修复） | 安装；见 7.3 |
| 1.27 | 1.24–1.26 | 经典 | preferred | 接受，`classical_only` | 接受，`classical_only`，`pq_available: false` | 安装 |
| 1.27 | 1.24–1.26 | 经典 | required | 拒绝 | （到不了）若直接给设备：拒绝 | 不安装 |
| 1.27 | 1.24–1.26 | 双签 | preferred | 接受，`dual_signed` | 接受，标 `classical_only`（设备无法检查） | 安装；网关检查了两个签名，设备只检查了经典签名并如实显示 |
| 1.27 | 1.24–1.26 | 双签 | required | 接受，`dual_signed` | 拒绝 `ErrOTAPQUnavailable` | 不安装：这样的 Agent 在 `required` 下永远无法更新，只能刷用 Go ≥ 1.27 构建的 Factory Agent |
| 1.27 | 1.27 | 经典 | preferred | 接受，`classical_only` | 接受，`classical_only` | 安装 |
| 1.27 | 1.27 | 经典 | required | 拒绝（`TestReleaseStoreRequiresDualSignaturesWhenToldTo`） | 拒绝（`TestDualSignedReleasesAndTheRequiredPolicy`） | 不安装 |
| 1.27 | 1.27 | 双签 | preferred | 接受，`dual_signed` | 接受，`dual_signed` | 安装 |
| 1.27 | 1.27 | 双签 | required | 接受，`dual_signed` | 接受，`dual_signed`，重启后保留（`TestE2EDualSignedUpdateSurvivesRestartsWhenPostQuantumSignaturesAreRequired`；Factory Agent 须含 7.3 的修复） | 安装；见 7.3 |

每个“设备”单元格 = 7.1 的规则套上 Agent 的构建与策略；每个“网关”单元格 = 同一规则套上网关的构建与策略（`decode` 调用的就是 `proto.VerifyManifestHybrid`）。直接有端到端测试的只有标出测试名的几格；其余是由 7.1 的被测规则推出的，**没有**逐格的组合测试，也没有任何一格在真机上验证过。

协议早于 1.3 的 Agent 没有更新接口：网关显示“该设备不支持更新”（`node/proto/compat.go` 协议 1.3 的注释），与签名无关。

### 7.3 `required` 策略下双签更新在重启后被回滚：已在 Node 源码修复（离线测试，未在真机验证）

**缺陷。** `nassimhub-agent` 的 `main` 先调用 `ota.Launch`，之后才在 `nodeserver.New` 里调用 `proto.EnableStandardPQ()`（mock Node 的 `main` 顺序相同）。Factory Agent 启动时做发布校验（`Boot` → `VerifyRelease` → `VerifyManifestHybrid`）的那一刻，后量子验证器还没有注册，于是即使是 Go 1.27 构建：

- `required`（或 PQ_EXTREME）：已安装的双签发布校验失败（`this build cannot verify post-quantum update signatures`），不被运行，更新被判为未生效并回滚；每次更新都如此。方向是“失败即拒绝”，不会装上未校验的东西，但功能上等于不能更新。
- `preferred`：启动校验只检查了经典签名（按 `classical_only` 通过），发布照常运行。

**修复。** `ota.Launch` 在做任何校验之前自己调用 `proto.EnableStandardPQ()`，所以调用方不可能把顺序弄错；两个 `main` 也在调用 `ota.Launch` 之前显式调用一次。`EnableStandardPQ` 可重复调用，注册与读取都经过验证器注册表的读写锁。没有 `crypto/mldsa` 的构建（Go < 1.27）行为不变：什么都不注册，7.2 表里对应的格子照旧。

**测试（全部离线，modem 为模拟）。**

- `node/agent/ota`：`TestStartUpVerifiesADualSignedReleaseBeforeAnythingElseEnabledTheProvider`——按服务进程的状态安装并确认一个双签发布，清空注册表（新进程的初始状态），再按 `main` 的方式调用 `Launch`，连续两次“重启”；`required` 与 `preferred` 都要求启动校验得到 `dual_signed` 并运行该发布。去掉 `Launch` 里的那一行，此测试失败并打印上面的拒绝日志。
- `node/proto`：`TestEnableStandardPQIsIdempotentAndSafeWhileVerifying`（`-race`）。
- NAS 端到端，真实进程：`TestE2EDualSignedUpdateSurvivesRestartsWhenPostQuantumSignaturesAreRequired`，两种设备配置（`-ota-signature-policy required`；`-security-level PQ_EXTREME`）：仅经典签名的发布被设备拒绝；双签 1.1.0 被推送、应用、重启后确认，再经两次进程重启仍是当前发布。用去掉修复的二进制跑同一测试，两种配置都得到 `ROLLED_BACK`。

**启用 `required`/PQ_EXTREME 之前仍要确认的事。**

1. 做启动校验的是**系统镜像里的 Factory Agent**，OTA 不替换它。已经刷了不含此修复的 Factory Agent 的设备，收到含修复的 Agent 更新也不会修好：更新仍会在重启时被旧的 Factory Agent 拒绝并回滚。这些设备要先换 Factory Agent（重刷镜像，或 RELEASING.md 第 12 节的 `--replace-agent`）。
2. 本仓库的 `node/` 快照在同步 Node 源码之后才包含修复；构建镜像前确认 `node/agent/ota/launch.go` 里有 `proto.EnableStandardPQ()`。
3. 以上没有任何一项在真机上验证过。

### 7.4 网关自身的发布（NAS 仓库，供对照）

| 网关构建 | `PQSigningPublicKey` | 接受 | 依据 |
|---|---|---|---|
| 任意 | 空（本树现状） | 仅经典清单（`release.signed.json`）；报告自己“不是后量子” | `internal/release/pq.go` `policyFor`；`TestAGenuineManifestVerifies` |
| Go ≥ 1.27 | 已填入 | **只**接受双签清单，两个签名都必须有效；没有“优先双签、退回经典” | `TestADualSignedManifestNeedsBothSignatures`、`TestABuildWithAPostQuantumKeyNeverAcceptsAClassicalManifest` |
| Go < 1.27 | 已填入 | 什么都不接受：无法校验 ML-DSA 即拒绝（`ErrPQUnavailable`），不是放行 | `internal/release/pq.go` `VerifyDual` |

旧网关用“拒绝未知字段”的方式解码经典清单，所以双签清单是**另一种文档、另一个发布路径**，经典清单保持原样继续发布，旧网关不受影响（`pq.go` 包注释）。

## 8. 工具链声明

- Agent 与 `proto` 的 `go.mod` 是 `go 1.24`；NAS 是 `go 1.26.5`。ML-DSA（双签、后量子身份）需要 Go ≥ 1.27（`proto.GoVersionForMLDSA`）。
- 本轮离线验证使用的本地工具链：Go 1.27.1（全部测试）与 Go 1.24.7（兼容性）。
- **Go 1.27 的 Docker 镜像 tag 与 digest 我们没有提供，也没有猜。** 编写环境不能访问镜像仓库。发布工程师在联网机器上读取并核对后再写进构建配置：

  ~~~sh
  docker buildx imagetools inspect golang:1.27.x-bookworm     # 把 x 换成实际要用的补丁版本
  ~~~

  记录输出里的 manifest list digest（`sha256:…`）与目标平台的 digest，与 Docker Hub 官方页面核对一致后，以 `golang:1.27.x-bookworm@sha256:<读到的值>` 的形式提交。未经读取核对的 digest 不提交。
