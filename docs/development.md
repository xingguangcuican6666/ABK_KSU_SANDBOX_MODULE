# Development and validation / 开发与验证

## 中文

### 仓库契约

`module.conf` 同时声明 `after_patch,before_build`。ABK 在仓库根目录以
`bash setup.sh` 执行入口，并提供 `KERNEL_ROOT`、`DEFCONFIG` 和
`CUSTOM_EXTERNAL_MODULE_STAGE`。

`after_patch` 验证内核线和 built-in KSU 变体，再复制公共实现、更新 Kconfig/Makefile
并在唯一、可验证的源码锚点安装薄适配器。它不读取或验证 Android release；Android
12-16 是计划中的构建/真机矩阵，不是安装器检测结果。每处修改包含模块标记；再次执行
会同步模块拥有的源码、规范化已知旧 Hook，并拒绝无法识别的冲突或部分状态。

`before_build` 设置 `CONFIG_KSU_ABK_SANDBOX=y`，并在保留现有顺序的前提下把
`abk_ksu_sandbox` 追加到 `CONFIG_LSM`；若 defconfig 未显式设置该字符串，则从目标内核
`security/Kconfig` 读取适用于其 `DEFAULT_SECURITY_*` 选择的默认列表。随后静态验证模板源码副本、Kbuild/Kconfig 接线、
适配器 Hook 标记和 defconfig。缺少任何部分都应以非零状态退出。这个
阶段不调用编译器，也不证明链接或启动成功。LKM、未知变体和非支持内核线必须给出明确
错误。

`after_patch` 的 Python 安装器把自身的文件写入放在回滚事务中；较后的锚点失败时会恢复
已有文件，并移除本次创建的文件/空目录。回滚失败会作为独立错误报告。`before_build`
对 defconfig 的开关发生在这个事务之外，因此静态验证失败后该配置行可能仍然存在，但
构建会以非零状态停止。

### 检查层级

```bash
# 语法和单元测试
go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.7
bash -n setup.sh scripts/*.sh
python3 -m compileall -q scripts tests
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

当前 `tests/test_installer.py` 是安装器级测试。它覆盖三种 synthetic KSU 形态的探测、
安装/验证二次执行、未知或多个 KSU 树、LKM、缺失/较晚锚点的完整回滚、已有部分注入、
外来或意外 sandbox 条目、未变源码重装时保留构建产物、源码变化时事务性失效旧产物、
模板更新的 mtime、旧 Hook 规范化、损坏 Hook 的 verify 拒绝、两个 ABK 阶段、必需基础
配置、6.12 `lsm_count.h`、ReSukiSU 动态 LSM 的源码/config/Kbuild 门控、运行时 LSM
尾序与任意重复 token 判定，以及不支持的内核线。LSM 尾序测试会用主机 C 编译器编译
并执行只依赖标准类型的 `lsm_order.h` 判定器。

除这个纯判定器外，它不编译内核 C 源码，也不执行或模拟 SELinux policy、凭据转换、
namespace 并发、撤权、mount/tmpfs 记账、ptrace/signal 或网络归属。上述项目只能由
内核编译、内核级测试和真机验收覆盖，不能从 Python 单元测试通过中推断。

`.github/workflows/upstream-integration.yml` 有两个不同范围的任务：

- `inject` 从固定 commit 获取三种真实 KSU 源码，搭配 synthetic Linux 6.6/6.12 文件，
  执行安装、二次安装和静态验证。它检查 KSU 布局和安装器回归，但 synthetic Linux
  文件不能证明真实内核兼容。
- `linux-anchors` 从 `torvalds/linux` 固定 commit 下载 5.10、5.15、6.1、6.6、6.12 中
  安装器实际修改的源码文件，搭配固定 KernelSU Official 执行相同的安装/验证。它检查
  上游源码锚点，不是 Android common/GKI 或厂商 backport 验证；仍然不进行预处理、
  编译、链接或启动，也不覆盖 SukiSU/ReSukiSU 与每条真实 Linux 线的笛卡尔积。

所有固定值只能通过普通提交和评审更新；工作流不跟随分支头。

`.github/workflows/kernel-matrix.yml` 是 7 个有效 Android/内核配对的 arm64 维护者入口：
Android 12/13 对应 5.10/5.15，Android 14 对应 6.1，Android 15 对应 6.6，Android 16
对应 6.12。三种 KSU 变体合计 21 个 job。它需要项目级 variable
`ABK_KERNEL_MATRIX_ENABLED=true`、secret `ABK_KERNEL_SOURCE_TOKEN`、自托管 runner 标签，
以及 runner 上的 `/opt/abk/bin/run-kernel-matrix`。该驱动在当前 job 中构建指定 Android、
内核线和 KSU 变体。配置缺失时工作流会明确失败，不会伪造成功结果。
仓库不包含该私有驱动或内核源码缓存，因此工作流文件本身不是矩阵已执行的证据。

`.github/workflows/android-smoke-apps.yml` 在公开 runner 上编译 direct/libsu 两个验收
APK。它固定 checkout、JDK、Gradle 和 artifact action，安装 Android SDK 35，运行两个
`assembleDebug` 任务，然后用 `apksigner` 和 `unzip` 校验并上传 APK 与 SHA-256 清单。
该 job 证明应用可构建，不证明内核 sandbox 行为；后者仍需真机验收。

### 真机验收（尚未由本仓库证明完成）

发布前必须在每个声称支持的组合上，用测试 APK 分别覆盖 libsu 和直接 `su`。至少验证：
context 与 MLS、同完整 UID namespace 复用、跨 Android 用户隔离、撤权终止、自身数据
访问、其他应用数据/进程拒绝、system 只读、裸块拒绝、VPN/断网/配额继承、合法
bind/tmpfs、非法 mount 与 master namespace 切换失败。收集 `dmesg`/audit 日志并确认没有
未限速泄漏。

`test-apps/` 是验收夹具源码，不是测试已通过的记录。任何尚未执行的矩阵或真机项目都
必须在发布记录中标为未验证。

## English

### Repository contract

`module.conf` declares both `after_patch,before_build`. ABK runs
`bash setup.sh` from the repository root with `KERNEL_ROOT`, `DEFCONFIG`, and
`CUSTOM_EXTERNAL_MODULE_STAGE` available.

`after_patch` validates the kernel line and built-in KSU variant. It then copies
the common implementation, updates Kconfig/Makefile wiring, and installs thin
adapters at unique validated source anchors. It does not read or validate the
Android release; Android 12-16 is a planned build/device matrix, not an installer
detection result. Every change carries a module marker; a rerun synchronizes
module-owned source, normalizes recognized old hooks, and rejects unknown
conflicts or partial state.

`before_build` sets `CONFIG_KSU_ABK_SANDBOX=y` and appends
`abk_ksu_sandbox` to `CONFIG_LSM` without reordering existing entries. If the
defconfig does not set that string explicitly, it reads the target kernel's
applicable `DEFAULT_SECURITY_*` default from `security/Kconfig`. It then
statically verifies copied template
sources, Kbuild/Kconfig wiring, adapter hook markers, and defconfig state. Any
missing component is a non-zero exit. This stage does not invoke a
compiler and does not establish successful linking or boot. LKM mode, unknown
variants, and unsupported kernel lines produce explicit errors.

The `after_patch` Python installer wraps its own file writes in a rollback
transaction. A later anchor failure restores existing files and removes files or
empty directories created by that run; rollback failure is reported separately.
The `before_build` defconfig toggle occurs outside that transaction, so its
configuration line may remain after static verification fails, although the
build still stops with a non-zero status.

### Validation layers

```bash
# Syntax and unit tests
go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.7
bash -n setup.sh scripts/*.sh
python3 -m compileall -q scripts tests
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

`tests/test_installer.py` currently contains installer-level tests. It covers
detection of three synthetic KSU shapes, repeat install/verify, unknown or
multiple KSU trees, LKM mode, complete rollback after early and late missing
anchors, an existing partial injection, foreign or unexpected sandbox entries,
preservation of build artifacts for unchanged sources, transactional stale-
artifact invalidation after source changes, source-update mtimes, normalization
of old hooks, verify rejection of damaged hooks, both ABK stages, required base
configuration, the 6.12 `lsm_count.h` edit, the ReSukiSU dynamic-LSM
source/config/Kbuild gate, runtime tail and arbitrary duplicate-token
validation, and an unsupported kernel line. The LSM-tail test compiles and
executes the standard-type-only `lsm_order.h` predicate with the host C compiler.

Apart from that pure predicate, it does not compile kernel C sources or
execute/simulate SELinux policy, credential transitions, namespace concurrency,
revocation, mount/tmpfs accounting, ptrace/signal mediation, or network
attribution. Those require kernel builds, kernel-level tests, and device
acceptance; Python unit success is not evidence for them.

`.github/workflows/upstream-integration.yml` has two scopes:

- `inject` fetches the three real KSU projects at pinned commits and combines
  them with synthetic Linux 6.6/6.12 files. It runs install, repeat install, and
  static verification. This catches KSU-layout and installer regressions, but
  synthetic Linux files do not establish real-kernel compatibility.
- `linux-anchors` downloads the exact files modified by the installer from
  pinned `torvalds/linux` 5.10, 5.15, 6.1, 6.6, and 6.12 commits, combines them
  with pinned KernelSU Official, and performs the same install/verify sequence.
  It validates upstream source anchors, not Android common/GKI trees or vendor
  backports. There is no preprocessing, compilation, linking, or boot, and it is
  not a Cartesian product of every real Linux line and KSU fork.

Pins change only through a reviewed repository commit; neither job follows a
moving branch head.

`.github/workflows/kernel-matrix.yml` is a maintainer entry point for seven valid
Android/kernel pairings: Android 12/13 with 5.10/5.15, Android 14 with 6.1,
Android 15 with 6.6, and Android 16 with 6.12. Across three KSU variants this is
21 jobs. It requires the repository variable
`ABK_KERNEL_MATRIX_ENABLED=true`, the secret
`ABK_KERNEL_SOURCE_TOKEN`, matching self-hosted runner labels, and
`/opt/abk/bin/run-kernel-matrix` on the runner. That driver builds the selected
Android version, kernel line, and KSU variant in the current job. Missing
configuration fails clearly instead of reporting a false success.
The private driver and kernel caches are not part of this repository, so the
workflow definition alone is not evidence that the matrix has run.

`.github/workflows/android-smoke-apps.yml` builds the direct and libsu acceptance
APKs on a public runner. It pins checkout, JDK, Gradle, and artifact actions,
installs Android SDK 35, runs both `assembleDebug` tasks, verifies the outputs
with `apksigner` and `unzip`, and uploads the APKs plus SHA-256 checksums. This
establishes application buildability, not runtime kernel-sandbox behavior.

### Device acceptance (not established by this repository)

Before release, every claimed combination must be exercised with test APKs for
both libsu and direct `su`. At minimum validate context and MLS preservation,
same-full-UID namespace reuse, cross-Android-user isolation, revocation
termination, own-data access,
other-app data/process denial, read-only system views, raw-block denial,
VPN/firewall/quota inheritance, valid bind/tmpfs operations, invalid mount
denial, and master-namespace denial. Capture dmesg/audit output and check that
logging cannot flood or disclose unintended data.

`test-apps/` contains acceptance-fixture source; it is not a record of a passing
test. Every matrix or device case not actually executed is marked unverified in
release notes.
