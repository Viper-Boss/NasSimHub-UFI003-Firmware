# 可用系统基线与发布边界

目标是先保留已验收的 USB 管理、Wi-Fi 客户端、独立后台、短信和当前设备的通话功能，再扩展其他功能。不要为启用未验收特性而改变正在使用的设备身份、配对或通话路径。

## r134 的实际构建输入

- Debian 13 trixie / arm64，使用 20261001T000000Z 主仓库和安全仓库快照。207 个实际安装包已经与签名 InRelease 和 Packages 索引校验，不能用合成测试树代替。
- 已运行的内核为 `6.12.49-msm8916-g93a71ee9468d`。候选 boot 使用同一内核、音频 DTB 和 initramfs，仅把根分区选择改为 `root=LABEL=rootfs`。r138 在一台 UFI003 上实际刷写、启动和重启了该 boot 与修正后的 Debian 13 rootfs，设备身份保持不变。
- 模块来自该已验证内核的模块目录，构建时逐项核对 vermagic。initramfs 审核确认支持 LABEL 解析，未发现设备身份、共享 SSH 密钥或 Wi-Fi 连接文件。
- polkitd 是显式运行依赖，不依赖推荐包。Factory Agent 为静态 ARM64 二进制。

默认锁文件仍是输入模板；实际已解析锁必须与其 boot 和模块输入一起保存，调用 `build-rootfs.sh --lock-file FILE` 重建。只有完整构建、成品检查和启动验收都通过，才能标为可发布固件。

## r138 真机修正

- 干净镜像缺少固件目标目录时，完整校验本人固件后创建；固件恢复后按顺序启动已知的离线 remoteproc。
- 仅对 `usb0` gadget 覆盖 Debian 的默认不托管规则，使 NetworkManager 接管 USB 地址。
- 显式安装并启用 `systemd-timesyncd`，避免无硬件时钟的设备重启后无法通过签名请求的时间窗口验证。
- 维护 SSH 继续使用设备本人的公钥及主机密钥。通用包不携带任何维护凭据；不能将本机已登录验收当成通用镜像自带登录密钥。
- 修复 ModemManager 空短信列表的标量 `sms : 0` 输出兼容，缺失或损坏的列表仍报错。
- 本机已实测 USB/Wi-Fi、NAS 认证配对、短信 Unicode 读取、10000 接通和非静音下行 PCM。新的浏览器双向通话、来电、热点及长期稳定性仍待验证。

r134/r135 的旧候选包未包含上述全部修正。r138 私有验收镜像包含设备自己的配置与固件，禁止公开；发布前必须从更新源码及完整版本锁重新生成干净通用包。

## 通用包与已有设备

通用包不带 Qualcomm 专有固件、任何设备的 NV、校准文件、身份、Wi-Fi 密码或后台密码。因此不能把“干净 Debian 镜像能生成”写成“任意 UFI003 刷完立即可 VoLTE”。使用者须保留自己设备的恢复资料，按板型提供获准使用的固件，并完成自己的 SIM/运营商验收。

已有设备的持久身份在 NSHSTATE，刷 rootfs 时必须保留该分区，不能格式化它。独立后台默认通过 USB `https://10.55.0.2:7581/` 管理；Node 协议地址为 `10.55.0.2:7580`。

## 本机已验证 VoLTE 配置的保护

旧部署可能把本机的只读 modem shadow profile 放在根文件系统 `/var/lib/nassimhub-modem/local-volte`。替换 rootfs 前需在本机私有备份后，把该设备自己的文件保护到 NSHSTATE 下的 `/var/lib/nassimhub/.private-modem/local-volte`；目录 root:root 0700、文件 0600，逐文件比较并验证 SHA256SUMS。

可选启动脚本 `node/deploy/audio/rmtfs-local-profile` 优先选择已验证的持久副本，其次选择原位置；校验失败则使用原始分区的只读模式。对应 rmtfs 单元须加 `RequiresMountsFor=/var/lib/nassimhub`，避免挂载前读取配置。它只在本机存在明确启用标记时选择 profile；Factory 包不生成标记、不安装 profile，也不自动启用此路径。

迁移文件不等于已完成重启验收。替换系统前还需保留该设备自己的启用配置、声卡验收和恢复步骤；不得把这些文件复制到别人的镜像。

## 本阶段保留的限制

- 配网热点默认关闭；先使用已验收的 USB 配网流程。
- 没有发布公钥时更新不可用，不填假公钥，不启用 required 签名策略。
- 当前设备支持 VoLTE 通话和 DTMF；网络实际协商的语音编码、高清音质及其他运营商不能仅由 16 kHz Linux PCM 推断。
- Factory 候选生成后仍须逐项完成 boot/rootfs 启动、持久身份、短信、双向通话、重启恢复和回滚验收。
