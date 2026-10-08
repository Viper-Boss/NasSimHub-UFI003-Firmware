# 架构与协议

启动链：板载 bootloader → Android boot image v0 → Image.gz + 尾部 DTB → Debian 13 arm64 / systemd。boot 重打包工具只支持明确识别的 v0 结构，其他格式拒绝处理。

设备侧：QRTR/QMI + rmtfs + ModemManager 管理基带；NetworkManager 管理 Wi-Fi（客户端；配网热点的代码已有，默认关闭，镜像侧前置条件是可选片段 `firmware/setup-ap-overlay/`，**未在真机验证**）；APR/QDSP6/ALSA 驱动提供已经验证的通话 PCM。Agent 在非特权 nassimhub 用户下运行，能力采用 yes/no/unknown，不能仅凭 IMS 注册就开放拨号。

USB NCM 设备端为 10.55.0.2/29，NAS 端由 NAS 集成配置地址和发现。多个棒子都使用同一地址时，宿主必须隔离接口/路由/命名空间；当前没有验收通用多棒子同时接入方案，不能直接桥接同网段。

7580：Node 协议，TLS 1.3、Ed25519 设备身份、配对和证书绑定、会话认证。7581：独立设备后台，自有 HTTPS 证书与本机管理密码。首次管理密码设置需要设备的初始化凭据，或从已配对 NAS 的“打开棒子后台”入口取得短暂访问材料。凭据不会打进通用镜像，不放 URL 查询参数或公共日志。首次 HTTPS 证书需要设备所有者核对。

管理后台只绑定当前棒子的状态，NAS 全局信息由 NAS 提供。敏感身份、短信和通信记录留在用户设备。没有默认共享 SSH 私钥、默认管理密码或固定 device_id。

协议实现：TCP/TLS 主路径；可选 KCP 与 FEC 代码；TLS 混合密钥协商策略支持按构建工具链启用 X25519MLKEM768。强制策略无法满足时拒绝启动，不能静默降级。

Agent 更新（OTA）与后量子签名，按“已实现 / 未验证”分开说：

- **已实现并有离线测试**：发布清单的 Ed25519 签名与可选的 ML-DSA 第二签名（双签；ML-DSA 需要签名主机和 Agent 都由 Go ≥ 1.27 构建），发布者工具 `nsh-release`（`keygen`/`keyring`/`manifest`/`sign`/`verify`）；设备侧用 `/etc/nassimhub/ota-keys.json` 里的公钥校验，`ota_signature_policy = required` 或安全级别 PQ_EXTREME 时拒绝没有有效 ML-DSA 签名的发布；更新只替换 Agent 可执行文件，装在状态分区，由系统镜像里的 Factory Agent 每次启动重新校验后 `exec`；确认窗口、自动回滚、Factory 版本下限（`node/agent/ota/`、`node/proto/ota.go`）。设备的附加 ML-DSA 身份（`pq-identity.json`，由设备 Ed25519 密钥签名绑定）同样已实现。打包、仓库外签名、校验流程见 [RELEASING.md](RELEASING.md)。
- **未在真机验证**：以上全部。没有任何一次真实设备上的更新、重启、确认、回滚或断电恢复；状态分区去掉 noexec 的挂载覆盖也没有在棒子上启动过。验收清单在 [VALIDATION.md](VALIDATION.md)。
- **没有实现**：系统镜像级 OTA（内核、rootfs、基带）；发布密钥的远程吊销（只能随新系统镜像更换公钥文件）；Factory 包本身的签名。
- **Node 本地的信任策略没有强制执行**：`node/agent/trust` 里有一个观察期/信任状态机，但 Agent 的任何请求路径都没有调用它；谁可以让这台设备发短信、拨号、更新，由已配对的 NAS 决定并执行。不要把这个包的存在读成设备侧已有这层保护。

通话控制通过 ModemManager；设备音频为 PCM S16LE、16 kHz，传输链路仍需完整浏览器验收。16 kHz PCM 不证明运营商实际协商 AMR-WB，也不保证手机端高清。本网不提供自行接入运营商 IMS 核心网的客户端。
