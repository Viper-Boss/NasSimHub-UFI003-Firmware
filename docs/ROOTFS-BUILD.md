# Debian 13 rootfs：可重复构建、输入锁定与依赖清单

本文说明 `scripts/build-rootfs.sh` 怎样从锁定的 Debian 归档快照构建 UFI003 的 Debian 13（trixie）arm64 根文件系统，怎样接上**已验证的内核**（不在这里构建），以及哪些事只能在联网构建机和真机上做。

**状态（务必先读）**

| 项目 | 状态 |
|---|---|
| 锁文件解析、软件包集合哈希、bootstrap 之后的全部处理（账户、清理、固定文件、内核模块 vermagic 检查、固件规则、确定性 tar）、`package-factory.sh` 的来源标注与可重复 ext4 镜像 | **offline-tested**：`python3 scripts/test_rootfs.py`（38 项，手写夹具）与 `sh scripts/test-build-rootfs.sh`（合成的 bootstrap/内核/模块） |
| `mmdebstrap` 从 snapshot.debian.org 真正 bootstrap（`--lock` 与正式构建的第一步）、`rootfs_fetch_index.py` 的联网取索引与 gpgv 验签 | **build-tested（r134）**：已在 WSL 的 ARM64 模拟环境实际运行，固定快照 20261001T000000Z；InRelease 验签与索引哈希通过，207 个包锁定并重建验证。已修复实际运行暴露的截断下载、仓库路径差异、锁定模式 UID/GID 读取和上游数据误报。默认锁是模板，实际已解析锁随本次产物保存。未在真机启动新镜像 |
| `firmware/rootfs.lock.json` | **未解析（unresolved）**：只有包名与结构，`versions: null`。快照时间戳、软件包版本、内核制品哈希、`nassimhub` 的 uid/gid、rootfs 分区大小都不在本仓库里，一律为 `null`，没有猜 |
| 用本流程构建出的 rootfs 启动、刷写 | **从未做过**。本仓库里没有任何一个 rootfs 或镜像是“可刷包”；`check.sh` 里的 rootfs/Factory 测试用的是**合成输入**，产物不能启动、不能刷 |

未解析的锁**不能**产出发布用的 rootfs：`build-rootfs.sh` 直接拒绝；只有显式 `--unlocked` 才构建，并且在 `ROOTFS-MANIFEST.json`、`PACKAGE-MANIFEST.json` 和终端输出里都标明“不可复现、不是发布输入”。

## 1. 文件与分工

| 文件 | 作用 |
|---|---|
| `firmware/rootfs.lock.json` | 输入锁：suite、架构、variant、snapshot.debian.org 时间戳、**逐包版本**（解析后）及其清单 SHA-256、`SOURCE_DATE_EPOCH`、服务账户 uid/gid、内核 boot.img 与模块的 SHA-256、镜像 UUID/hash seed/分区大小 |
| `firmware/debian-packages.json` | 向 bootstrap 请求的包名（与 `docs/INSTALL.md` 列出的已验证镜像名单一致，`scripts/test_tools.py` 与 `scripts/test_rootfs.py` 保持三处同步） |
| `firmware/rootfs-dependencies.json` | 依赖清单：每个包为什么在、是否在已验证名单里；**不在名单里的一律标 `unverified - not in the verified image list` 且不安装**；内核与固件的来源规则 |
| `scripts/build-rootfs.sh` | 驱动脚本：`--lock` 解析锁；默认模式构建；`--unlocked` 构建非发布产物 |
| `scripts/rootfs_tools.py` | 不联网、不 chroot 的全部步骤（可单测） |
| `scripts/rootfs_fetch_index.py` | **唯一**联网的 Python 代码：取 `InRelease`（gpgv 验签）与 `Packages`（对 `InRelease` 的 SHA-256 校验）；只被 `--lock` 调用 |
| `scripts/package-factory.sh` | 在 rootfs 上叠加 Agent、overlay、unit（符号链接启用，不在 chroot 里跑 systemctl）、权限归一化，生成 ext4 镜像；现在记录 rootfs 来源 |

`build-rootfs.sh` **不**叠加 Agent/overlay、**不**生成 ext4：这些只有一份实现，在 `package-factory.sh` 里（含 r127 的权限归一化）。`build-rootfs.sh` 的产物是“干净的基础树 + 来源清单”，交给 `package-factory.sh`。

## 2. 依赖清单（摘要，完整内容在 `firmware/rootfs-dependencies.json`）

安装的包 = `docs/INSTALL.md` 为已验证镜像列出的名单，**不多不少**：`systemd`、`ca-certificates`、`network-manager`、`wpasupplicant`、`modemmanager`、`libqmi-utils`、`qrtr-tools`、`rmtfs`、`alsa-utils`、`polkitd`；`--setup-ap` 时加 `dnsmasq-base`（配网热点本身未在真机验证）。其余由依赖关系带入，解析后的锁逐一列出。

**没有**按印象添加的包。下列各项在仓库里找不到“已验证镜像装了它”的记录，因此只列在 `not_installed` 里并标记 `unverified - not in the verified image list`：`libmbim-utils`、`protection-domain-mapper`、`tqftpserv`、`openssh-server`。若 Codex 在已验证设备上确认其中某个包确实存在且必需，做法是：把包名加入 `firmware/debian-packages.json` 的 `base` **和** `docs/INSTALL.md`，在 `rootfs-dependencies.json` 里移到 `installed`，再重新 `--lock`。

variant：锁里是 `important`（mmdebstrap 对“debootstrap 默认集合”的叫法）。`docs/INSTALL.md` 只说已验证镜像“使用 debootstrap”，**没有记录**用的是不是默认 variant；见第 4 步的核对。

不启用 `non-free-firmware`，不从 Debian 取任何固件。

### 固件：型号相关 ≠ 设备唯一

- 基带/Wi-Fi 固件属于设备厂商，本项目**无权再分发**（`NOTICE.md`、`LICENSES/README.md`）。它不在仓库里，脚本不下载、不内嵌；只有操作者用 `--firmware-dir DIR` 提供时才复制进 `usr/lib/firmware/`，并在 `ROOTFS-MANIFEST.json` 里逐文件列出路径与 SHA-256、写明“不可再分发”。带这种固件的 rootfs/镜像不得由本项目公开发布。
- **允许**的是“同一板型每台设备都相同”的文件（型号相关，device-model-specific）。这与现有隐私规则不冲突：`scripts/genericrules.py` 禁止的是属于**某一台设备**的内容。某个文件是否真的每台相同，仓库里没有名单，由操作者比较两台设备上的 SHA-256 确认。
- **拒绝**的是设备唯一数据：`modemst1`、`modemst2`、`fsg`、`fsc`、`persist`（及其导出文件）、`*.qcn`、`*.xqcn`、`*.efs`、`*.nvm`。`rootfs_tools.py firmware` 用与 `audit-rootfs.py` 相同的规则（`genericrules.name_findings` 的 `modem-calibration`，以及私钥内容扫描）逐文件拒绝；构建结束时整棵树再过一遍 `audit-rootfs.py`，打包时还有 `privacy-check.py --package`。校准/NV 数据在任何情况下都不进镜像。改文件名绕过检查是违规操作，规则的局限见 `genericrules.py` 开头。
- 已验证镜像的固件是放在 rootfs 里还是启动时从设备自己的分区加载，**仓库里没有记录（未知）**。由 Codex 在设备上确认后再决定是否需要 `--firmware-dir`。

### 内核：只消费，不构建、不修改

来源见 `firmware/upstream.lock.json`（KyonLi/ufi003-kernel 6.12.49-1，`6.12.49-msm8916-g93a71ee9468d`）。`build-rootfs.sh` 需要两个由发布负责人提供的制品：

- `--boot-img`：板子实际启动的 Android v0 boot 镜像（Image.gz + 尾部 DTB）。脚本从内核自身的 `Linux version …` 字样读出 release 字符串，必须等于锁里的 `kernel.release`。
- `--modules`：与之配套的 `lib/modules/<release>`（目录或 tar）。**每个**模块的 vermagic 第一个词必须等于上面读出的 release，必须有 `modules.dep`（脚本不对目标树运行宿主机的 depmod）；`build`/`source` 这两个指向构建机的符号链接被去掉。任何一个模块不符即失败，rootfs 不产出。

两者的 SHA-256 在 `--lock` 时写入锁，之后每次构建核对；`package-factory.sh` 还会核对交给它的 boot 镜像就是 rootfs 构建时用的那一个。

## 3. 构建机

Debian 12/13 或 Ubuntu 24.04（amd64 或 arm64），能访问 `https://snapshot.debian.org`，root 权限。

~~~sh
sudo apt install mmdebstrap qemu-user-static binfmt-support arch-test debian-archive-keyring gpgv e2fsprogs python3
~~~

- 密钥环 `/usr/share/keyrings/debian-archive-keyring.gpg` 必须含 trixie 的归档签名密钥（较旧发行版自带的 `debian-archive-keyring` 可能不含；不含时 mmdebstrap 与 gpgv 都会报签名错误——这是正确行为，升级该包，不要关闭验签）。
- 记录 `mmdebstrap --version`、`mke2fs -V`、`tar --version`：可复现性只对**相同版本的这些工具**成立。`ROOTFS-MANIFEST.json` 记录了 mmdebstrap 版本。

## 4. 步骤

### 第 0 步（Codex，已验证设备上，只读）：取得锁里缺的事实

~~~sh
id -u nassimhub; id -g nassimhub                    # → --service-uid / --service-gid
getent passwd nassimhub                             # 家目录与 shell：脚本写的是 /var/lib/nassimhub 与 /usr/sbin/nologin，不同则先报告
uname -r                                            # 必须是 6.12.49-msm8916-g93a71ee9468d
dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\n' | sort > verified-packages.tsv
blockdev --getsize64 /dev/disk/by-label/rootfs      # 字节数 ÷ 1048576，向下取整 → --image-size-mib
find /lib/firmware -type f | sort > verified-firmware-list.txt     # 只要文件名清单，判断固件在不在 rootfs 里
tar -C / -cf modules-6.12.49.tar lib/modules/$(uname -r)           # 模块；boot.img 用自己已校验的备份
~~~

`verified-packages.tsv` 和固件文件名清单可以交给构建者；**不要**上传分区镜像、`/var/lib/nassimhub`、NetworkManager 连接配置或任何校准数据。

uid/gid 必须与已有设备一致：状态分区（NSHSTATE）上的文件归这个数字 id 所有，首启脚本只改目录本身的属主。rootfs 分区大小在本仓库文档里**没有记载**，所以是必填参数。

### 第 1 步：解析锁（联网，一次；刷新基础系统时重做）

~~~sh
sudo sh scripts/build-rootfs.sh --lock --timestamp 20260101T000000Z \
     --boot-img /path/boot.img --modules /path/modules-6.12.49.tar \
     --service-uid <N> --service-gid <N> --image-size-mib <N>      # 需要配网热点时加 --setup-ap
~~~

时间戳是 snapshot.debian.org 上存在的一个快照（`YYYYMMDDTHHMMSSZ`），由发布负责人选定；`SOURCE_DATE_EPOCH` 取同一时刻。脚本：用 mmdebstrap 从 `https://snapshot.debian.org/archive/debian/<ts>/`（`trixie main`）和 `…/debian-security/<ts>/`（`trixie-security main`）bootstrap 一次；读出 `var/lib/dpkg/status`；取两个归档的 `InRelease`（gpgv 验签）与 `Packages`（按 `InRelease` 校验），要求**每个已安装的包版本都出现在锁定的索引里**并记下 .deb 的 SHA-256；写回 `firmware/rootfs.lock.json`（`status: "resolved"`）。

预期输出的最后两行：

~~~
rootfs lock …/firmware/rootfs.lock.json: resolved, snapshot <ts>, <N> packages, manifest sha256 <hex>
The lock is resolved: review the diff of …/rootfs.lock.json (package list and versions), commit it, then build.
~~~

### 第 2 步：审核锁的 diff 再提交

- 把锁里的 `packages.versions`（名称）与第 0 步的 `verified-packages.tsv` 比较。多出来或缺少的包说明 variant 或请求名单与已验证镜像不同：调整 `variant`（例如 `minbase`、`required`）或名单后重新 `--lock`，**不要**手改 `versions`（`manifest_sha256` 会对不上，构建拒绝）。版本不同是预期的（快照时刻不同），以锁为准。
- 确认 `polkitd` 在列表里（overlay 的规则需要它）。
- 提交锁文件。从此 `sbom.py` 生成的 SBOM 会逐包列出这组 Debian 软件包。

### 第 3 步：构建

~~~sh
sudo sh scripts/build-rootfs.sh --out /build/rootfs-a --boot-img /path/boot.img --modules /path/modules-6.12.49.tar
#   可选：--firmware-dir /path/model-firmware     --setup-ap（必须与解析锁时一致）
~~~

脚本依次：核对锁已解析、内核 release 与两个 SHA-256 → mmdebstrap（同一快照）→ 解包（不含设备节点）→ **核对已安装的包集合与锁逐包相同**（不同则列出差异并失败）→ 创建 `nassimhub`（固定 uid/gid、锁定口令、nologin）→ 清除 apt 列表与缓存、日志、machine-id、SSH 主机密钥、随机种子、构建机的 `resolv.conf` 等 → 写固定的 hostname/hosts/时区（Etc/UTC）/locale（C.UTF-8）→ 安装模块（vermagic 检查）→ 可选固件 → mtime 截到 `SOURCE_DATE_EPOCH` → `audit-rootfs.py` → 确定性 tar（按名排序、数字属主、无 atime/ctime）→ `ROOTFS-MANIFEST.json`。失败时输出目录改名为 `<out>.FAILED`。

预期输出：

~~~
rootfs tree:    /build/rootfs-a/rootfs (<N> entries, tree sha256 <hex>)
rootfs archive: /build/rootfs-a/rootfs.tar (sha256 <hex>)
packages:       <N> (manifest sha256 <与锁里 manifest_sha256 相同>)
provenance:     built from lock <锁文件的 sha256> (snapshot <ts>)
~~~

### 第 4 步：打包（Agent、overlay、unit、ext4）

~~~sh
sh scripts/build-agent.sh <版本>
sudo ROOT_SPEC=LABEL=rootfs NSH_ROOTFS_MANIFEST=/build/rootfs-a/ROOTFS-MANIFEST.json \
     NSH_OTA_KEYS=/path/ota-keys.json sh scripts/package-factory.sh /build/rootfs-a/rootfs /path/boot.img Lite
~~~

给了 `NSH_ROOTFS_MANIFEST` 时，`package-factory.sh` 重新计算目录树哈希并与清单比较（构建后改过的树被拒绝），核对 boot 镜像，然后用固定参数生成镜像：`mke2fs -U <锁里的 uuid> -E hash_seed=<锁里的 seed>`、`E2FSPROGS_FAKE_TIME=$SOURCE_DATE_EPOCH`、`mke2fs -d` 之后用 debugfs 把每个 inode 的 ctime/atime 设为同一时刻，镜像大小 = 锁里的分区大小（放不下即失败）。uuid 与 hash seed 是任意常量，boot 命令行按 LABEL/PARTUUID 选根分区，不用这个 UUID。

`PACKAGE-MANIFEST.json` 的 `rootfs.statement` 只有三种取值，终端最后也会打印同一句：

| 取值 | 含义 |
|---|---|
| `built from lock <sha256>` | rootfs 由 `build-rootfs.sh` 按已解析的锁构建，目录树与清单一致 |
| `built by build-rootfs.sh WITHOUT a resolved lock (non-reproducible, not a release input)` | `--unlocked` 的产物 |
| `operator-supplied (unverified provenance)` | 没有给清单：来源只是操作者的说法；镜像按内容大小生成，不保证逐字节可重复（与 r127 行为相同） |

分区预算：镜像大小就是分区大小，文件系统自身开销由 mke2fs 决定。打包后用 `dumpe2fs -h dist/factory/<v>-Lite/images/rootfs.img | grep -E 'Block count|Free blocks'` 记录余量；余量多少算够（日志、apt、以后的系统更新）**没有在真机上定过**，由项目负责人给出数值后写回本节。

### 第 5 步：验证可复现

~~~sh
sudo sh scripts/build-rootfs.sh --out /build/rootfs-b --boot-img /path/boot.img --modules /path/modules-6.12.49.tar
sha256sum /build/rootfs-a/rootfs.tar /build/rootfs-b/rootfs.tar           # 必须相同
cmp /build/rootfs-a/ROOTFS-MANIFEST.json /build/rootfs-b/ROOTFS-MANIFEST.json
# 再分别打包（两个不同的 NSH_DIST_DIR），比较 images/rootfs.img 的 sha256
~~~

不相同时定位差异：

~~~sh
python3 scripts/rootfs_tools.py tree-list /build/rootfs-a/rootfs > a.txt
python3 scripts/rootfs_tools.py tree-list /build/rootfs-b/rootfs > b.txt
diff a.txt b.txt
~~~

**预期会遇到、但这里无法预先确认的差异来源**（真实的 Debian 维护脚本从未在本流程里运行过）：维护脚本生成的缓存或带时间的文件、`/etc/shadow` 的“上次修改日”字段、`/var/lib/systemd/catalog/database`、Python 字节码等。处理办法是把确认无用的生成物加入 `scripts/rootfs_tools.py` 的 `CLEAR_DIRECTORIES`/`REMOVE_GLOBS`（并在 `test_rootfs.py` 的夹具里加一项），或对确需保留的文件做归一化；每加一条都写明原因。**在两次构建逐字节相同之前，不要把“可复现”写成事实。**

## 5. `--unlocked`（调试用，永远不是发布输入）

~~~sh
sudo SOURCE_DATE_EPOCH=<N> sh scripts/build-rootfs.sh --unlocked --out DIR --boot-img … --modules … \
     --service-uid <N> --service-gid <N> [--timestamp <ts>] [--from-tar bootstrap.tar]
~~~

用于在锁解析之前试跑流程。`--from-tar` 用现成的 bootstrap 归档代替 mmdebstrap（离线测试就是这样跑的）。产物的 `ROOTFS-MANIFEST.json` 写 `release_input: false`、`reproducible: false` 和原因列表；`package-factory.sh` 把它如实带进 `PACKAGE-MANIFEST.json`。

## 6. 在编写容器里实际运行过什么

容器：无网络（snapshot.debian.org 不可达）、有 root、无 `mmdebstrap`/`debootstrap`、有 `qemu-aarch64-static`、`mke2fs`/`debugfs` 1.47.0、`gpgv`。

| 运行过（offline-tested） | 没有运行过 |
|---|---|
| dpkg status / `Packages` / `InRelease` 解析，损坏数据被拒绝（手写夹具） | 从 snapshot.debian.org 取任何东西；gpgv 对真实 `InRelease` 验签 |
| 经 `file://` 的索引抓取与哈希核对（`--test-unsigned`；未签名的夹具在正常模式下被拒绝） | `mmdebstrap` 的任何一次执行，含 qemu 下的维护脚本 |
| 锁的解析、部分解析、被改动的锁、测试夹具锁都不算发布锁 | `--lock` 的端到端运行 |
| 已安装集合与锁逐包比较 | 用真实 Debian 树跑 finalize（夹具只有几十个文件） |
| 服务账户（固定 id、冲突与范围检查）、清理、固定文件、越界符号链接不被跟随 | 真实内核 boot.img 的 release 读取（夹具是带版本字样的 gzip 流） |
| vermagic：ELF64 `.modinfo` 解析，`.ko`/`.ko.xz`/`.ko.gz`，目录与 tar 输入，不匹配即失败 | 真实模块（数百个、可能是 `.ko.zst`） |
| 固件：型号文件被列出，设备唯一名称全部拒绝 | 真实固件目录 |
| `build-rootfs.sh --unlocked --from-tar` 全流程两次，`rootfs.tar` 逐字节相同 | 两次**真实** bootstrap 是否逐字节相同 |
| `package-factory.sh` 的三种来源标注、boot 镜像/目录树不符被拒绝、两次打包 `rootfs.img` 逐字节相同、固定 UUID 与 inode 时间、按分区大小生成与放不下时失败 | 任何镜像的启动、刷写；分区大小与余量 |

## 7. 上板（Codex）

本仓库的脚本不刷机。镜像做出来以后的事全部在真机上、由 Codex 执行并记录：

1. 核对 `PACKAGE-MANIFEST.json`：`rootfs.statement` 是 `built from lock …`，`rootfs.kernel.boot_img_sha256` 等于将要使用的 boot 镜像，`rootfs.image.size_mib` 等于目标分区大小；`sha256sum -c SHA256SUMS`。
2. 按 `docs/INSTALL.md` 备份 boot 与系统配置，确认 EDL 救援流程；**不要**触碰 modemst1/modemst2/fsg/fsc/persist。
3. 能内存试启（`fastboot boot`）就先试启 boot；持久写入 rootfs 前保留可恢复的原镜像。boot/kernel/DTB 的选择与刷写完全是 Codex 的工作，本流程不改内核、不改 DTB。
4. 首次启动后逐项检查：`systemctl is-system-running`；`uname -r` 与 `ls /lib/modules`；`lsmod` 有模块加载、`dmesg | grep -i 'version magic'` 为空；`systemctl status nassimhub-agent nassimhub-usb ModemManager NetworkManager rmtfs`（单元名以实际为准）；`id nassimhub` 与第 0 步相同；`mmcli -L` 看到基带；`/var/lib/nassimhub` 已挂载且身份未变（升级的设备）；`cat /etc/machine-id` 非空且每台不同；`ls /etc/ssh/ssh_host_*`（若装了 SSH 服务）为首启生成。
5. 按 `docs/VALIDATION.md` 的清单继续。把结果（通过/失败/未做）写回 `docs/VALIDATION.md`，在此之前文档里的状态保持“未在真机验证”。
