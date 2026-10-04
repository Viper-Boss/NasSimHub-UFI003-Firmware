# 架构与协议

启动链：板载 bootloader → Android boot image v0 → Image.gz + 尾部 DTB → Debian 13 arm64 / systemd。boot 重打包工具只支持明确识别的 v0 结构，其他格式拒绝处理。

设备侧：QRTR/QMI + rmtfs + ModemManager 管理基带；NetworkManager 管理 Wi-Fi；APR/QDSP6/ALSA 驱动提供已经验证的通话 PCM。Agent 在非特权 nassimhub 用户下运行，能力采用 yes/no/unknown，不能仅凭 IMS 注册就开放拨号。

USB NCM 设备端为 10.55.0.2/29，NAS 端由 NAS 集成配置地址和发现。多个棒子都使用同一地址时，宿主必须隔离接口/路由/命名空间；当前没有验收通用多棒子同时接入方案，不能直接桥接同网段。

7580：Node 协议，TLS 1.3、Ed25519 设备身份、配对和证书绑定、会话认证。7581：独立设备后台，自有 HTTPS 证书与本机管理密码。首次管理密码设置需要设备的初始化凭据，或从已配对 NAS 的“打开棒子后台”入口取得短暂访问材料。凭据不会打进通用镜像，不放 URL 查询参数或公共日志。首次 HTTPS 证书需要设备所有者核对。

管理后台只绑定当前棒子的状态，NAS 全局信息由 NAS 提供。敏感身份、短信和通信记录留在用户设备。没有默认共享 SSH 私钥、默认管理密码或固定 device_id。

协议实现：TCP/TLS 主路径；可选 KCP 与 FEC 代码；TLS 混合密钥协商策略支持按构建工具链启用 X25519MLKEM768。强制策略无法满足时拒绝启动，不能静默降级。ML-DSA、双签 OTA、PQ_EXTREME 的配置和拒绝逻辑不代表完整可发布实现，见路线图。

通话控制通过 ModemManager；设备音频为 PCM S16LE、16 kHz，传输链路仍需完整浏览器验收。16 kHz PCM 不证明运营商实际协商 AMR-WB，也不保证手机端高清。本网不提供自行接入运营商 IMS 核心网的客户端。
