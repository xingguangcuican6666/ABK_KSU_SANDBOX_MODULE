# ABK KSU Sandbox

[English](#english) | [中文](#中文)

## 中文

ABK KSU Sandbox 是一个 [AnyBase Kernel (ABK)](https://github.com/xingguangcuican6666/AnyBaseKernel)
外部模块模板。它计划把来自普通 Android 应用的 KernelSU、SukiSU Ultra 或
ReSukiSU 提权会话放入按应用隔离的 SELinux 域和 mount namespace，而不是让会话
直接进入不受限的 `su` 域。

> **状态与安全警告：** 本仓库是实验性内核模块模板，并非已经完成安全审计的
> sandbox。当前代码、上游兼容性和真机行为必须在目标内核及设备上验证。不要把
> CI 通过等同于安全隔离有效，也不要将未经审计的构建用于生产设备。

### 目标行为

- 只处理 KSU 已授权、appId 为 10000-19999、原 SELinux 域为
  `untrusted_app*` 的提权请求。
- 使用 `u:r:anybase_kernel_sandbox_<appid>:<原 MLS range>`，保留调用者的
  MLS categories；同一 appId 的不同 Android 用户共享 type，但使用不同 namespace。
- 提权后只把 euid/egid 设为 `0:0`，real/saved/fs UID/GID 保留原应用身份；清空附加组和 capabilities，并禁止后续凭据切换。
- 进入 sandbox 后拒绝全部 KernelSU supercall ioctl，不能借继承或新建的 KSU fd 修改全局策略或功能。
- 保留 seccomp、cgroup、rlimit、调度、VPN、配额和完整 UID 网络归属。
- 允许经过参数验证的 bind/rbind、tmpfs、umount 和同完整 UID/SID sandbox 进程调试；不授予
  通用 `CAP_SYS_ADMIN` 或 `CAP_SYS_PTRACE`。
- 对未知 KSU 源码结构、LKM 模式、非 enforcing SELinux、注入冲突或部分安装直接失败，
  不回退到普通 `su` 域。

详细约束见 [设计文档](docs/design.md)，开发与验证方法见
[开发文档](docs/development.md)。这些文档描述目标契约；尚未完成的行为不能视为已实现。

### ABK 使用方法

在 ABK 中添加仓库，并同时启用两个阶段：

```text
module:https://github.com/xingguangcuican6666/ABK_KSU_SANDBOX_MODULE;after_patch|module:https://github.com/xingguangcuican6666/ABK_KSU_SANDBOX_MODULE;before_build
```

- `after_patch`：探测内核线和 built-in KSU 变体，复制公共 sandbox 源码并安装薄适配
  Hook。安装器不探测 Android 版本。
- `before_build`：启用 `CONFIG_KSU_ABK_SANDBOX=y`，把 `abk_ksu_sandbox` 追加到
  `CONFIG_LSM`，并静态验证源码、Hook、构建接线和 defconfig；这一步不编译内核。

计划支持的 Android/内核配对为：Android 12/13 使用 5.10 或 5.15，Android 14 使用
6.1，Android 15 使用 6.6，Android 16 使用 6.12。三种 KSU 变体覆盖这些 7 个配对，
共 21 个维护者矩阵 job。LKM 模式不在支持范围内。模块必须在两个阶段执行，缺少任一
阶段都应使构建失败。

### 本地检查

```bash
go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.7
bash -n setup.sh scripts/*.sh
python3 -m compileall -q scripts tests
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

完整内核矩阵需要项目维护者配置的自托管 arm64 runner 和内核源码缓存；公开 runner
上的测试只覆盖安装器行为和固定源码锚点。其中真实 Linux 源码锚点任务只下载被修改的
Torvalds 上游文件并执行两次安装与验证；它不是 Android common/GKI 或厂商内核验证，
也不编译、链接或启动内核。仓库当前没有公开 CI 结果可以证明 arm64 Android 编译成功
或 sandbox 运行时边界成立。

测试 APK 不要求本地构建；`Android smoke apps` 工作流使用固定 action 和 Gradle 版本
编译 direct/libsu APK，执行签名与 ZIP 校验，并上传带 SHA-256 清单的短期 artifact。

## English

ABK KSU Sandbox is an experimental [AnyBase Kernel (ABK)](https://github.com/xingguangcuican6666/AnyBaseKernel)
external-module template. It is intended to place KernelSU, SukiSU Ultra, or
ReSukiSU sessions requested by ordinary Android applications in per-application
SELinux domains and mount namespaces instead of an unrestricted `su` domain.

> **Status and security warning:** this repository is an experimental kernel
> module template, not an audited sandbox. Its code, upstream compatibility,
> and device behavior must be validated against each target kernel and device.
> A passing CI run does not establish a security boundary, and unreviewed builds
> should not be installed on production devices.

### Intended behavior

- Intercept only KSU-authorized requests with appId 10000-19999 whose original
  SELinux domain is `untrusted_app*`.
- Use `u:r:anybase_kernel_sandbox_<appid>:<original MLS range>` and preserve MLS
  categories. Android users with the same appId share a type, but not a namespace.
- Set only euid/egid to `0:0`, retain the app's real/saved/fs UID/GID, clear supplementary groups and all capability sets,
  and prevent subsequent credential switching.
- Deny every KernelSU supercall ioctl after sandbox entry, including calls through inherited or newly installed KSU file descriptors.
- Preserve seccomp, cgroup, rlimit, scheduler, VPN, quota, and full-UID network
  attribution.
- Permit narrowly validated bind/rbind, tmpfs, umount, and debugging of sandbox
  peers with the same full UID/SID, without general `CAP_SYS_ADMIN` or
  `CAP_SYS_PTRACE`.
- Fail closed for unknown KSU source layouts, LKM mode, non-enforcing SELinux,
  injection conflicts, or partial installation. Never fall back to the normal
  `su` domain.

See the bilingual [design](docs/design.md) and [development](docs/development.md)
documents. They define the intended contract; unfinished behavior must not be
treated as implemented.

### ABK usage

Add the repository to ABK and select both stages:

```text
module:https://github.com/xingguangcuican6666/ABK_KSU_SANDBOX_MODULE;after_patch|module:https://github.com/xingguangcuican6666/ABK_KSU_SANDBOX_MODULE;before_build
```

- `after_patch`: detect the kernel line and built-in KSU variant, copy the common
  sandbox sources, and install thin adapters at validated anchors. The installer
  does not detect the Android release.
- `before_build`: enable `CONFIG_KSU_ABK_SANDBOX=y`, append
  `abk_ksu_sandbox` to `CONFIG_LSM`, and statically verify source, hook,
  build-wiring, and defconfig state. It does not compile the kernel.

The planned Android/kernel pairings are Android 12/13 on 5.10 or 5.15, Android
14 on 6.1, Android 15 on 6.6, and Android 16 on 6.12. The three KSU variants
produce 21 maintainer-matrix jobs across those seven pairings. LKM mode is out
of scope. Both stages are required; omitting either stage must fail the build.

### Local checks

```bash
go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.7
bash -n setup.sh scripts/*.sh
python3 -m compileall -q scripts tests
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

The supported kernel matrix requires maintainer-provided self-hosted arm64 runners
and kernel source caches. Public-runner checks cover installer behavior and pinned
source anchors only. The real-Linux anchor job downloads just the modified source
files from Torvalds upstream and runs install/verify twice. It is not an Android
common/GKI or vendor-kernel check, and it does not compile, link, or boot a
kernel. No public CI result in this template currently establishes a successful
arm64 Android build or a working runtime security boundary.

The test APKs do not require a local build. The `Android smoke apps` workflow
uses pinned actions and Gradle, builds the direct/libsu APKs, verifies their
signatures and ZIP structure, and uploads a short-lived artifact with SHA-256
checksums.

## License

GPL-3.0-only. See [LICENSE](LICENSE).
