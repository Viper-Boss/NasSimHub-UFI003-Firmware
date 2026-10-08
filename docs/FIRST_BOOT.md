# 镜像里带什么，首次启动在设备上生成什么

通用镜像（Factory 包）可以刷到同一板型的任何一台设备上，所以它**不能**带任何属于某一台设备或某一个人的东西。下面两张表逐项对应到源码；表里的每一行都能在所列文件里核对。

本文描述的是源码行为。首次启动流程 **未在真机验证 / not yet verified on hardware**（指本轮新增的 PQ 身份与 OTA 部分；设备身份、配对、后台在此前版本已在真机运行，见 README），验收步骤见 [VALIDATION.md](VALIDATION.md)。

## 镜像自带（每台设备相同）

| 内容 | 位置 | 来源 |
|---|---|---|
| Factory Agent（系统镜像里的 Agent，更新永不改写它） | `/usr/bin/nassimhub-agent`，root 所有，0755 | `scripts/build-agent.sh` 构建，`scripts/package-factory.sh` 安装；不可改写的理由见 `node/agent/ota/installer.go` 开头注释 |
| 默认配置（不含任何密码、密钥、令牌） | `/etc/nassimhub/agent.conf`，0644 | `node/deploy/agent.conf`；配置文件不读取任何机密，见 `node/agent/internal/config/config.go` 包注释 |
| 发布**公钥**文件（只在打包时提供了才有） | `/etc/nassimhub/ota-keys.json`，root:root 0644 | `nsh-release keyring` 生成；格式与校验见 `node/proto/ota_keyfile.go`，读取见 `node/agent/ota/keyring.go` |
| systemd 单元与覆盖 | `/etc/systemd/system/nassimhub-agent.service` 及 `.service.d/` | `node/deploy/`、`firmware/overlay/` |
| 持久分区挂载、状态检查、USB NCM、NetworkManager 与 polkit 规则 | `firmware/overlay/` 下各文件 | 同左 |
| 配网热点的前置条件（只在 `NSH_SETUP_AP=on` 打包时才有） | `/etc/polkit-1/rules.d/48-nassimhub-setup-ap.rules`、`/etc/systemd/system/nassimhub-agent.service.d/setup-ap.conf`，以及配置里的 `provisioning = true`、`provisioning_ap = auto` | `firmware/setup-ap-overlay/`、`scripts/imagepolicy.py`；每台设备相同，不含任何口令 |
| 空的 `/etc/machine-id` | 打包时清空 | `scripts/package-factory.sh` |

没有发布公钥文件的镜像：设备不信任任何发布者，无法校验任何更新，Agent 报告“更新不可用”及原因（`node/agent/ota/boot.go` 中 `no release keys are installed on this device...`），包清单写明 `updates disabled: no release keys`。**发布私钥永远不在镜像、仓库或任何构建产物里。**

## 首次启动在设备上生成（每台设备不同，留在持久分区 `/var/lib/nassimhub`）

| 文件 | 内容 | 何时生成 | 源码 |
|---|---|---|---|
| `device.json` | Ed25519 设备身份（种子）、由公钥派生的 `device_id`；0600 | Agent 首次启动；之后只读取、绝不重新生成 | `node/agent/internal/identity/identity.go`（`LoadOrCreate`） |
| `device-cert.pem` | 用设备身份密钥自签的 Node TLS 证书；只存证书，不含私钥；临近过期时用同一把密钥重签 | 首次以 TLS 启动（`plaintext = false`） | `node/agent/nodetls/nodetls.go`（`EnsureCertificate`） |
| `pq-identity.json` | 附加的 ML-DSA 身份（种子）+ 设备 Ed25519 密钥对它的绑定签名；0600 | 首次启动，且仅当 Agent 由 Go ≥ 1.27 构建、`pq_identity = true`；否则不生成，设备保持经典身份 | `node/agent/internal/pqidentity/pqidentity.go`（`LoadOrCreate`）；算法 `node/proto/pqidentity.go`（`PQAlgorithmFor`：默认 ML-DSA-65，PQ_EXTREME 为 ML-DSA-87） |
| `admin-bootstrap.txt` | 独立后台的一次性初始化码（setup proof）；0600；设置管理密码后删除 | 首次启动且尚未设置管理密码 | `node/agent/internal/localadmin/admin.go`（`Open`、`OwnerSetup`） |
| `admin.json` | 管理密码的盐与 PBKDF2-SHA256 摘要（不存明文） | 设备所有者设置密码时 | `node/agent/internal/localadmin/admin.go`（`save`） |
| `admin-tls-key.pem`、`admin-tls-cert.pem` | 独立后台自己的 ECDSA P-256 密钥与自签证书（与 Node 协议身份无关） | 首次启动后台时 | `node/agent/internal/localadmin/certificate.go` |
| `transport-key.json` | KCP 传输密钥；0600；只经已配对的 TLS 通道交给 NAS | 首次启动 | `node/agent/internal/transportkey/transportkey.go`（`Open`） |
| `pairing.json` | 与 NAS 的配对信任记录 | 没有该文件即未配对；配对或解除配对时写入 | `node/agent/internal/pairing/pairing.go`（`Open`、`persistLocked`） |
| `setup-ap-passphrase` | 配网热点的 WPA2 口令（16 个字符、80 bit）；0600。没有内置默认口令 | 首次需要启动热点时；`provisioning_ap = off`（默认）时不会生成 | `node/agent/netbackend/networkmanager/setupap.go`（`setupAPPassphrase`）。包里出现这个文件名会被 `privacy-check.py --package` 拒绝 |
| `sms-requests.json` | 短信发送请求的幂等记录（请求指纹、消息编号、状态） | 首次经 Agent 发短信时 | `node/agent/modembackend/msm8916/sms_write.go` |
| `ota-state.json`、`ota.lock`、`ota-staging/`、`agent-releases/` | 更新状态机、传输暂存、已安装的发布版本 | 首次收到更新时 | `node/agent/ota/ota.go`、`updater.go`、`installer.go` |
| `/etc/machine-id` | systemd 机器标识 | 首次启动由 systemd 写入 | 镜像内为空文件 |
| USB 序列号与两端 MAC | 由 `machine-id` 派生 | 每次启动 | `firmware/overlay/usr/local/libexec/nassimhub-usb` |

`pq-identity.json` 损坏或与设备身份不符时 Agent **不会**悄悄重新生成，而是报告没有 PQ 身份（同文件的包注释）。设备身份同理：`device.json` 存在但读不出来时 Agent 拒绝启动，不会换一把新钥匙。

不由本仓库负责的首启内容：SSH 主机密钥、Wi-Fi 配置（包括热点启用后 NetworkManager 自己保存的 `nassimhub-setup-ap` 连接配置）由输入的 rootfs 和 NetworkManager 在设备上产生；本仓库的 overlay 不生成也不携带它们（未实现）。

## 通用性由脚本强制，不靠约定

- `scripts/audit-rootfs.py`：打包前检查干净 rootfs，生成镜像前再检查一遍合成后的目录树。
- `scripts/privacy-check.py --package <包目录>`：检查最终的包（文件名规则、布局、分区名规则、PEM/OpenSSH 私钥格式、带标签的 IMEI/ICCID/号码、高熵疑似密钥、镜像内的私钥字节）。
- 规则与其局限写在 `scripts/genericrules.py` 开头：例如 64 位十六进制密钥与校验和无法区分、没有标签的 IMEI 查不出来，压缩过的内核镜像内部扫描不到。**通过检查不等于可以免去人工审核。**
- 单元测试 `scripts/test_tools.py` 对每一类违规各放一个假样本并断言被拦下，同时断言干净的包通过。
