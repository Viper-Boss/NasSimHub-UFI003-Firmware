# 安装、备份与回滚

## 先核对硬件

目标 UFI003_MB_V02 / MSM8916 / aarch64。先只读记录 USB VID/PID、启动模式、板型、GPT、boot header、DTB、根分区、内核及基带服务状态。其他 UFI003 外壳不代表同一板型。按自己的分区尺寸审核镜像；本仓库不提供任意设备通用刷写命令。

修改前在本地私有目录备份 boot、系统配置和自己的恢复资料，校验 SHA256，并确认 EDL 救援流程。设备唯一分区的备份只能由本人保存，绝不能上传公开仓库。不要克隆别人的 NV。

## 构建源码

运行 scripts/check.sh 和 scripts/build-agent.sh。静态 arm64 Agent 无 glibc 链接依赖，但其运行后端需要系统里的 ModemManager、NetworkManager、D-Bus/polkit、ALSA 程序等。

离线 rootfs 使用 debootstrap 构建 Debian 13 arm64，安装 systemd、ca-certificates、network-manager、wpasupplicant、modemmanager、libqmi-utils、qrtr-tools、rmtfs、alsa-utils 和板型对应内核。软件包来源与固件再分发授权由构建者核对。不要从正在使用的棒子做整盘 dump 后公开发布。

scripts/package-factory.sh 只加工提供的干净 rootfs 目录，不执行 chroot，不写任何设备。输入需要已经创建不可交互登录的 nassimhub 用户，并锁定账户密码；SSH 密钥由各设备首次启动配置生成，不能放共享私钥。生成 raw ext4 rootfs.img，要求 boot 命令行已经匹配 rootfs 标签或板型对应 PARTUUID。设置 ROOT_SPEC=LABEL=rootfs（或实际匹配的 PARTUUID 值）后打包，脚本会核对 boot 命令行。它不把 sparse 格式和 raw 格式混为一谈，不负责调整 GPT。需要 sparse 的刷写工具须显式转换并另行审核。

持久状态要求单独存在标签 NSHSTATE 的 ext4 分区，挂载 /var/lib/nassimhub，脚本不会替用户创建或格式化它。镜像不带 machine-id、SSH 主机密钥、管理密码、设备身份、配对、Wi-Fi 密码或音频验收标记。第一次启动由 systemd 和 Agent 创建自己的身份。

后台入口：https://10.55.0.2:7581/ （USB）或本机 Wi-Fi IP 的 7581 端口。初始化凭据保存在本机受限状态目录 /var/lib/nassimhub/admin-bootstrap.txt；设备管理员可在设备控制台读取并在“高级维护”栏输入自己的初始化码。不要向开发者发送管理密码。已配对 NAS 可使用 SIM 节点的“打开棒子后台”入口。独立后台仍可通过本机维护入口管理，不以 NAS 在线为条件。

## 电话音频是可选的硬件阶段

先审核 kernel/audio 补丁与 KyonLi 6.12.49-1 源码。以自己的审核过的 DTB 生成候选 DTB，再重打包 boot。build-modules.sh 使用匹配源码和头文件。检查 vermagic、依赖、APR 服务、ALSA 控件；不要把编译成功视为 DSP 兼容成功。

支持时优先 fastboot boot 内存试启；并非所有启动器支持该命令。实际持久修改前保留可恢复的 boot 和模块。逐设备验收 IMS、录音和上行音频后，才使用 node/deploy/audio 的可选组件。禁止在通用镜像内放 local-volte.enabled 或 voice-audio.verified；标记是该设备实际验收记录。

## 回滚

用户态更新：停止 Agent（会清理电话），恢复自己的旧二进制、配置和服务覆盖，daemon-reload，再启动。保留 /var/lib/nassimhub；不要重置身份当作修复手段。

音频模块与 boot：恢复原模块选择和匹配的 boot；内存试启断电后回到原 boot。新的硬件故障使用本板正确 EDL programmer 和本人备份，绝不覆盖他人或其他板型的校准分区。

首次 AP 配网、量产 Factory/OTA、长期运行、来电、浏览器双向通话仍需按 docs/ROADMAP.md 验收。本源码仓库不声称已经完成全部这些测试。
