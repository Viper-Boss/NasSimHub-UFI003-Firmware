# NasSimHub UFI003 Firmware

**把 Qualcomm Snapdragon 410 / MSM8916 UFI003 变成可独立管理、也能接入 NasSimHub 的 Linux SIM 节点。**

基线：**Debian GNU/Linux 13（Trixie，当前真机 13.1）+ Linux 6.12.49-msm8916-g93a71ee9468d**，来自 KyonLi 6.12.49-1。目标板为 **UFI003_MB_V02**。本仓库公开固件集成源码、Agent、独立 HTTPS 后台和 q6 通话音频补丁，方便复现与排查，减少反复踩坑。

> 当前是开发者源码版，不是已经通过所有运营商、所有板型验证的量产固件。没有发布从个人设备导出的整盘镜像。最新源码已包含 WPA2/WPA3 混合热点识别、中文短信转义解码与接听/挂断查询优化。

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
| 浏览器完整双向电话 | 媒体及控制接口已实现，持续双向、来电及断线回归仍待完整验收 |
| DTMF | 暂不支持 |
| Factory/OTA | 提供离线打包骨架和源码构建；通用可刷写发布包及升级闭环尚未验收 |

## 下载、编译与目录

安装 Go 1.24+（建议与验证环境一致使用 1.27.1）、Python 3、Linux 构建环境。内核工具另需 dtc、cpp、匹配的头文件及 aarch64 GCC。

~~~sh
sh scripts/check.sh
sh scripts/build-agent.sh
# 已审核的干净 rootfs 目录 + 已审核的板型 boot 镜像，完全离线打包：
sudo ROOT_SPEC=LABEL=rootfs sh scripts/package-factory.sh /path/to/clean-rootfs /path/to/boot.img
~~~

| 目录 | 内容 |
|---|---|
| node/agent | 设备 Agent、ModemManager/NetworkManager 后端、短信/呼叫/遥测、独立后台 |
| node/proto、node/xport | 身份、配对、安全策略及传输协议 |
| node/deploy | systemd、配置和可选通话组件 |
| kernel/audio | q6 录放音端口补丁、设备树修改与 boot DTB 重打包工具 |
| firmware/overlay | 首启、持久分区检查、USB NCM 及网络配置 |
| scripts | 源码检查、隐私检查、离线构建与打包 |

查看 [设备安装与恢复](docs/INSTALL.md)、[架构与协议](docs/ARCHITECTURE.md)、[路线图](docs/ROADMAP.md)、[已知问题](docs/KNOWN_ISSUES.md)。NAS 集成主项目在 [NasSimHub](https://github.com/Viper-Boss/NasSimHub)。此仓库可独立开发，不包含 NAS 全部源码。

## 重要的设备边界

不要跨板型盲刷，不要复制他人的 modemst1/modemst2/fsg/persist 或校准数据。按键开机长按约 5 秒进入 Qualcomm 9008/EDL，是硬件既有行为，**不用于 NasSimHub 恢复出厂**。本项目脚本不自动刷分区、不重分区、不格式化设备。

AGPL-3.0-only 用于本项目自己的代码和文档；Linux 衍生部分保留 GPL 及上游授权，详见 [NOTICE](NOTICE.md) 和 [许可证边界](LICENSES/README.md)。

English: Developer source for a Debian 13 / Linux 6.12.49 UFI003 SIM node, with standalone HTTPS administration, USB/Wi-Fi management, SMS and experimental carrier-dependent VoLTE/QDSP6 audio. This is not a universal carrier-certified firmware or a production-ready image.
