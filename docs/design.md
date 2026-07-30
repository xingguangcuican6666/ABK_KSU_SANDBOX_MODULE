# Design / 设计

本文是目标安全契约，不是实现完成度或测试通过声明。当前验证范围和缺口见
[开发与验证](development.md)；任何未经过编译和真机测试的行为都应视为未验证。

This document is the target security contract, not a claim of implementation or
test completion. See [development and validation](development.md) for the current
scope and gaps; behavior without kernel-build and device evidence remains
unverified.

## 中文

### 信任边界

本模块只改变普通应用发起的 KSU 提权会话。KSU 管理器、系统 UID、非
`untrusted_app*` 域和未授权调用者保持 KSU 原有行为。匹配的调用者必须在提权前保存
完整 UID、appId、SELinux SID/MLS、namespace、网络和资源控制状态；所有判定都基于
这份不可变快照，不能信任提权后的可变凭据。

模块是纵深防御层，不宣称能抵抗任意内核代码执行、KSU 核心被篡改、SELinux policy
加载器被绕过或硬件/固件攻击。

### 会话流程

1. KSU 授权路径调用适配器；适配器按源码特征识别 KernelSU、SukiSU Ultra 或
   ReSukiSU，不依赖单一固定路径。
2. 仅当原域为 `untrusted_app*` 且 appId 在 10000-19999 时进入 sandbox 流程。
3. 在并发安全事务中创建或复用 SELinux 策略和按完整 UID 的私有 mount namespace。
4. 提交过滤后的凭据与新 SID。策略、namespace 或凭据任一步失败都回滚并拒绝提权。
5. 撤销 KSU 授权时终止该完整 UID 的 sandbox 进程并释放 namespace；正常实例保留到
   重启。最多同时存在 256 个完整 UID 实例，并且每次启动最多创建 256 个不同 appId
   的动态 type；达到上限后新 appId 提权失败，已有 type 仍可复用。

### SELinux 与资源访问

目标 type 名为 `anybase_kernel_sandbox_<appid>`，context 保留原 MLS range。允许集合
应是显式白名单：自身 app data、只读系统视图、必要设备节点、基础日志/DNS 和普通
TCP/UDP。必须拒绝其他应用数据、管理类 Binder、裸块设备、raw socket、网络管理、
eBPF、内核控制以及 domain transition。SELinux 不是 enforcing 时拒绝匹配应用提权。

动态 policy 写入必须幂等并带模块标记；未知已有规则、名称冲突或只能完成部分规则时
立即失败。日志必须限速，且不提供 sysfs 开关或运行时绕过接口。
LSM 按标准 `CONFIG_LSM` 顺序加载并位于列表最后；若启动参数移除或重排模块，late init
不会标记其就绪，匹配的提权请求必须拒绝，不能以缺少或错误排序的 LSM 约束继续执行。

### 凭据、namespace 与受限操作

- 仅 euid/egid 设为 `0:0`；real/saved/fs UID/GID 均保留原应用身份；附加组为空；permitted、
  effective、inheritable、ambient 和 bounding capability 集为空，并锁定 securebits。
- sandbox 身份在 KernelSU supercall 总入口直接返回 `-EPERM`，阻断策略、功能、标记及其他全局控制操作。
- 不替换调用者的 seccomp、cgroup、rlimit、调度和网络身份。
- 每个完整 UID 共享一个从首次调用者当前视图复制的 private mount namespace；禁止
  进入 master namespace。KSU profile 的 master namespace 选项不能覆盖此规则。
- bind 源限自身数据或当前视图中的只读系统文件；rbind 只允许自身数据，避免从只读
  系统挂载递归带入可写子挂载。目标限自身 app data。
  tmpfs 强制原 UID/GID、`0700,nosuid,nodev`，每完整 UID 合计不超过 1 GiB 和 128 个
  mount。拒绝 lazy detach、块文件系统、提权 remount、新 mount API、`setns` 和卸载
  继承 mount，避免仍被文件引用持有的 detached mount 绕过记账。
- 进程访问 Hook 只允许操作同完整 UID 且同 sandbox SID 的 sandbox peer；不获得通用
  ptrace capability，也不绕过到原始应用或其他 SID。

## English

### Trust boundary

The module changes only KSU elevation sessions originating from ordinary apps.
The KSU manager, system UIDs, non-`untrusted_app*` domains, and unauthorized
callers keep their existing KSU behavior. Before elevation, the adapter records
the full UID, appId, SELinux SID/MLS, namespace, networking, and resource-control
state. Decisions use that immutable snapshot, never mutable post-elevation
credentials.

This is a defense-in-depth layer. It does not claim to withstand arbitrary
kernel code execution, a compromised KSU core, a bypassed policy loader, or
hardware/firmware attacks.

### Session flow

1. A KSU authorization path calls a thin adapter detected by source features for
   KernelSU, SukiSU Ultra, or ReSukiSU rather than one fixed path.
2. Only an original `untrusted_app*` domain with appId 10000-19999 enters the
   sandbox path.
3. A concurrency-safe transaction creates or reuses SELinux policy and a private
   mount namespace keyed by full UID.
4. Filtered credentials and the new SID are committed together. A policy,
   namespace, or credential failure rolls back and denies elevation.
5. Revoking KSU authorization terminates sandbox processes for that full UID and
   releases its namespace. Otherwise an instance lives until reboot. The global
   limit is 256 active full-UID instances and 256 distinct appId policy types per
   boot. New appIds fail closed at the limit; existing types remain reusable.

### SELinux and resource access

The target type is `anybase_kernel_sandbox_<appid>` and the context preserves the
original MLS range. Policy is an explicit allowlist for own app data, read-only
system views, required device nodes, basic logging/DNS, and ordinary TCP/UDP.
Other-app data, administrative Binder services, raw block devices, raw sockets,
network administration, eBPF, kernel control, and domain transitions remain
denied. Matching app elevation is denied unless SELinux is enforcing.

Dynamic policy writes must be idempotent and carry module-owned markers. Unknown
existing rules, naming conflicts, or partial rule installation fail closed.
Kernel logs are rate-limited; there is no sysfs switch or runtime bypass.
The LSM loads last through the standard `CONFIG_LSM` order. If a boot-parameter
override omits or reorders it, late initialization does not mark it ready and
matching elevation requests are denied instead of continuing with missing or
misordered mediation.

### Credentials, namespaces, and mediated operations

- Only euid/egid become `0:0`; real, saved, and fs UID/GID remain the original app identity;
  supplementary groups are empty; all capability sets are empty; securebits
  prevent later credential switching.
- The KernelSU supercall dispatcher returns `-EPERM` for sandbox identities,
  blocking policy, feature, mark, and other global control operations.
- The caller's seccomp, cgroup, rlimit, scheduling, and network identity remain.
- Each full UID shares one private mount namespace cloned from the first caller's
  current view. Entering the master namespace is forbidden, including through a
  KSU profile override.
- Bind sources are restricted to own data or read-only system files in the
  current view; recursive binds are restricted to own data so writable nested
  mounts cannot be imported through a read-only system mount. Targets are
  restricted to own app data. tmpfs is forced to the original
  UID/GID and `0700,nosuid,nodev`, with per-full-UID limits of 1 GiB and 128
  mounts. Lazy detach, block filesystems, privilege-increasing remounts, the new
  mount API, `setns`, and unmounting inherited mounts are denied so detached
  mounts retained by file references cannot escape accounting.
- Process mediation permits access only to sandbox peers with the same full UID
  and sandbox SID. It does not bypass to the original app domain or grant general
  ptrace capability.
