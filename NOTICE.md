# Attribution and license boundaries

NasSimHub application code includes the existing Node protocol, transport, agent and local console developed for the NasSimHub project, with subsequent UFI003 hardware integration. Module identifiers are retained for compatibility.

The Debian baseline is Debian 13 Trixie. Debian packages keep their own copyright and licensing; see each package's /usr/share/doc/*/copyright. Debian is not relicensed under AGPL.

Kernel baseline: [KyonLi/ufi003-kernel](https://github.com/KyonLi/ufi003-kernel), release 6.12.49-1, version 6.12.49-msm8916-g93a71ee9468d. Audio patches derive from Linux Qualcomm ASoC/QDSP6 drivers and retain GPL-2.0-only licensing. Files with dual SPDX licenses keep those terms.

Reference build: [KyonLi/ufi003-debian](https://github.com/KyonLi/ufi003-debian). Additional research references: [OpenStick](https://github.com/OpenStick/OpenStick), [msm8916-mainline](https://github.com/msm8916-mainline), [lk2nd](https://github.com/msm8916-mainline/lk2nd), [postmarketOS Zhihe devices](https://wiki.postmarketos.org/wiki/Zhihe_series_(generic-zhihe)). These are references, not bundled or relicensed projects.

The repository contains no modem firmware, carrier MBN, NV dumps or prebuilt kernel image. A publicly downloadable binary does not by itself grant redistribution rights. Obtain board-compatible firmware from an authorized source and retain its licensing.
