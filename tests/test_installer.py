#!/usr/bin/env python3
"""Black-box tests for the source installer.

The fixtures intentionally model only the source anchors owned by install.py.
They are not kernel compilation fixtures.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPOSITORY = Path(__file__).resolve().parents[1]
INSTALLER = REPOSITORY / "scripts/install.py"
SETUP = REPOSITORY / "setup.sh"


class SyntheticTree:
    def __init__(
        self,
        base: Path,
        variant: str = "official",
        version: str = "6.6",
        sandbox_enabled: bool = True,
    ) -> None:
        self.base = base
        self.kernel_root = base / "kernel-root"
        self.common = self.kernel_root / "common"
        self.module_root = base / "module-root"
        self.ksu = self.common / "drivers/kernelsu"
        self._write_module()
        self._write_common(version)
        self._write_ksu(self.ksu, variant, version)
        sandbox_line = "CONFIG_KSU_ABK_SANDBOX=y\n" if sandbox_enabled else ""
        lsm_list = "selinux,abk_ksu_sandbox" if sandbox_enabled else "selinux"
        self.write(
            self.kernel_root / "gki_defconfig",
            "CONFIG_KSU=y\n"
            "CONFIG_SECURITY_SELINUX=y\n"
            "CONFIG_NAMESPACES=y\n"
            f'CONFIG_LSM="{lsm_list}"\n'
            + sandbox_line,
        )

    @staticmethod
    def write(path: Path, content: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)

    def _write_module(self) -> None:
        source = self.module_root / "files/abk_ksu_sandbox"
        for filename in (
            "Makefile",
            "abk_sandbox.h",
            "lsm_build_config.h",
            "lsm_order.h",
            "core.c",
            "policy.c",
            "namespace.c",
            "lsm.c",
        ):
            self.write(
                source / filename,
                f"/* ABK_KSU_SANDBOX_V1 */\n/* synthetic {filename} */\n",
            )
        self.write(
            source / "abk_ksu_sandbox_api.h",
            "/* ABK_KSU_SANDBOX_V1: synthetic public API */\n",
        )

    def _write_common(self, version: str) -> None:
        major, minor = version.split(".")
        self.write(
            self.common / "Makefile",
            f"VERSION = {major}\nPATCHLEVEL = {minor}\nSUBLEVEL = 0\n",
        )
        self.write(
            self.common / "security/Kconfig",
            'config LSM\n\tstring "Ordered list of enabled LSMs"\n'
            '\tdefault "yama,apparmor,selinux,bpf" if DEFAULT_SECURITY_APPARMOR\n'
            '\tdefault "yama,integrity,bpf" if DEFAULT_SECURITY_DAC\n'
            '\tdefault "lockdown,yama,integrity,selinux,bpf"\n',
        )
        self.write(
            self.common / "kernel/seccomp.c",
            """#include <linux/seccomp.h>
int __secure_computing(const struct seccomp_data *sd)
{
\tint mode = current->seccomp.mode;
\tint this_syscall;
\tthis_syscall = sd ? sd->nr :
\t\tsyscall_get_nr(current, current_pt_regs());
\treturn mode + this_syscall;
}
""",
        )
        self.write(
            self.common / "fs/namespace.c",
            """#include <linux/mount.h>
static int do_loopback(struct path *path, const char *old_name, int recurse)
{
\tstruct path old_path;
\tint err;
\terr = kern_path(old_name, LOOKUP_FOLLOW|LOOKUP_AUTOMOUNT, &old_path);
\tif (err)
\t\treturn err;
\terr = 0;
out:
\tpath_put(&old_path);
\treturn err;
}
static int can_umount(const struct path *path, int flags)
{
\tif (!may_mount())
\t\treturn -EPERM;
\treturn 0;
}
int path_umount(struct path *path, int flags)
{
\tstruct mount *mnt = real_mount(path->mnt);
\tint ret;
\tret = can_umount(path, flags);
\tif (!ret)
\t\tret = do_umount(mnt, flags);
\treturn ret;
}
static inline bool may_mount(void)
{
\treturn capable(CAP_SYS_ADMIN);
}
int path_mount(const char *dev_name, struct path *path,
\t\tconst char *type_page, unsigned long flags, void *data_page)
{
\tunsigned int mnt_flags = 0, sb_flags = 0;
\tint ret;
\tret = security_sb_mount(dev_name, path, type_page, flags, data_page);
\tif (ret)
\t\treturn ret;
\tif (!may_mount())
\t\treturn -EPERM;
\tif (flags & MS_BIND)
\t\treturn do_loopback(path, dev_name, flags & MS_REC);
\treturn do_new_mount(path, type_page, sb_flags, mnt_flags, dev_name,
\t\t\t    data_page);
}
""",
        )
        self.write(
            self.common / "kernel/ptrace.c",
            """#include <linux/ptrace.h>
static int ptrace_may_access(struct task_struct *task)
{
\tconst struct cred *tcred;
\tstruct mm_struct *mm = task->mm;
\tunsigned int mode = 0;
\ttcred = __task_cred(task);
\tif (uid_eq(current_uid(), tcred->uid))
\t\tgoto ok;
\treturn -EPERM;
ok:
\tif (mm &&
\t    ((get_dumpable(mm) != SUID_DUMP_USER) &&
\t     !ptrace_has_cap(mm->user_ns, mode)))
\t\treturn -EPERM;
\treturn 0;
}
""",
        )
        self.write(
            self.common / "kernel/signal.c",
            """#include <linux/sched/signal.h>
static int check_kill_permission(struct task_struct *t)
{
\tif (!same_thread_group(current, t) &&
\t    !kill_ok_by_cred(t)) {
\t\treturn -EPERM;
\t}
\treturn 0;
}
#ifdef CONFIG_KGDB_KDB
#include <linux/kdb.h>
#endif
""",
        )

    def _write_ksu(self, root: Path, variant: str, version: str = "6.6") -> None:
        variant_markers = {
            "official": "",
            "sukisu": "# SukiSU Ultra with SUSFS\n",
            "resukisu": "# ReSukiSU\n",
            "unknown": "# Unidentified fork\n",
        }
        marker = variant_markers[variant]
        objects = "kernelsu-objs := main.o\n" if variant != "unknown" else "obj-y := main.o\n"
        self.write(root / "Kbuild", marker + objects)
        self.write(
            root / "Kconfig",
            """menu "KernelSU"
config KSU
    bool "KernelSU"
endmenu
""",
        )
        if variant == "resukisu":
            self.write(
                root / "hook/lsm_hooks.c",
                """#include <linux/lsm_hooks.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0) || defined(KSU_COMPAT_HAS_LIST_OF_LSM_HOOKS)
#include <linux/lsm_hooks.h>
static struct security_hook_list ksu_hooks[] = {
    LSM_HOOK_INIT(inode_rename, ksu_inode_rename),
#ifdef CONFIG_KSU_MANUAL_HOOK_AUTO_SETUID_HOOK
    LSM_HOOK_INIT(task_fix_setuid, ksu_task_fix_setuid),
#endif
#ifdef CONFIG_KSU_MANUAL_HOOK_AUTO_INITRC_HOOK
    LSM_HOOK_INIT(file_permission, ksu_file_permission),
#endif
};
void __init ksu_lsm_hook_built_in_init(void)
{
    if (ARRAY_SIZE(ksu_hooks) == 0)
        return;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0) || defined(KSU_COMPAT_REQUIRE_PROVIDE_LSM_NAME)
    security_add_hooks(ksu_hooks, ARRAY_SIZE(ksu_hooks), "ksu");
#else
    security_add_hooks(ksu_hooks, ARRAY_SIZE(ksu_hooks));
#endif
}
#else
void __init ksu_lsm_hook_built_in_init(void)
{
}
#endif
""",
            )
        self.write(
            root / "policy/app_profile.c",
            """#include <linux/cred.h>
int escape_with_root_profile(void)
{
    return 0;
}
""",
        )
        self.write(root / "selinux/sepolicy.c", "/* synthetic sepolicy */\n")
        self.write(
            root / "selinux/rules.c",
            """#include \"sepolicy.h\"
void apply_kernelsu_rules()
{
    struct selinux_policy *pol, *old_pol = selinux_state.policy;
    struct policydb *db;
    mutex_lock(&selinux_state.policy_mutex);
    pol = ksu_dup_sepolicy(old_pol);
    db = &pol->policydb;
out_unlock:
    mutex_unlock(&selinux_state.policy_mutex);
    return;
}
""",
        )
        self.write(
            root / "policy/allowlist.c",
            """#include <linux/init.h>
int ksu_set_app_profile(struct app_profile *profile)
{
    int result = 0;
    return result;
}

void ksu_prune_allowlist(bool (*is_uid_valid)(uid_t uid, char *package, void *data))
{
    int uid = 10000;
    struct profile_node *np = 0;
            hlist_del_rcu(&np->list);
}

void __init ksu_allowlist_init(void)
{
}
""",
        )
        self.write(
            root / "infra/su_mount_ns.c",
            """#include <linux/nsproxy.h>
static long ksu_sys_setns(int fd, int flags)
{
    return 0;
}
""",
        )
        self.write(
            root / "supercall/dispatch.c",
            """#include <linux/cred.h>
#include "supercall/internal.h"
long ksu_supercall_handle_ioctl(unsigned int cmd, void __user *argp)
{
    int i;
    return i + cmd + (argp != 0);
}
""",
        )
        if variant == "resukisu":
            self.write(
                root / "feature/sucompat.c",
                """static inline int do_ksu_handle_execveat_sucompat(struct pt_regs *regs)
{
    escape_with_root_profile();
    return regs != 0;
}
""",
            )
        else:
            self.write(
                root / "feature/sucompat.c",
                """long ksu_handle_execve_sucompat(struct pt_regs *regs)
{
    long ret, orig_regs[5];
    int tmp_fd = 0;
    struct ksu_sulog_pending_event *pending_sucompat = 0;
    ret = escape_with_root_profile();
    if (ret) {
        pr_err("escape_with_root_profile failed: %ld\\n", ret);
    }
    ksu_sulog_emit_pending(pending_sucompat, ret, GFP_KERNEL);
    ret = ksu_syscall_table[__NR_execveat](regs);
    return ret;
}
""",
            )
        if version == "6.12":
            self.write(
                self.common / "include/linux/lsm_count.h",
                """#if IS_ENABLED(CONFIG_SECURITY_IPE)
#define IPE_ENABLED 1,
#else
#define IPE_ENABLED
#endif

/*
 *  There is a trailing comma that we need to be accounted for.
 */
#define MAX_LSM_COUNT \\
\tCOUNT_LSMS( \\
\t\tIPE_ENABLED)
""",
            )

    def add_second_ksu(self) -> Path:
        second = self.kernel_root / "KernelSU/kernel"
        self._write_ksu(second, "official")
        return second

    def command(
        self,
        operation: str,
        *,
        verify_config: bool = False,
        extra_env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        command = [
            sys.executable,
            str(INSTALLER),
            operation,
            "--kernel-root",
            str(self.kernel_root),
            "--module-root",
            str(self.module_root),
        ]
        if verify_config:
            command.extend(["--defconfig", str(self.kernel_root / "gki_defconfig")])
        env = os.environ.copy()
        env.pop("ABK_BUILD_WORK_MODE", None)
        if extra_env:
            env.update(extra_env)
        return subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            env=env,
        )

    def setup_stage(self, stage: str) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env.update(
            {
                "KERNEL_ROOT": str(self.kernel_root),
                "DEFCONFIG": str(self.kernel_root / "gki_defconfig"),
                "CUSTOM_EXTERNAL_MODULE_STAGE": stage,
            }
        )
        env.pop("ABK_BUILD_WORK_MODE", None)
        return subprocess.run(
            ["bash", str(SETUP)],
            check=False,
            capture_output=True,
            text=True,
            env=env,
            cwd=REPOSITORY,
        )

    def content_snapshot(self) -> dict[str, bytes]:
        return {
            str(path.relative_to(self.kernel_root)): path.read_bytes()
            for path in sorted(self.kernel_root.rglob("*"))
            if path.is_file()
        }


class InstallerTests(unittest.TestCase):
    def make_tree(
        self,
        variant: str = "official",
        version: str = "6.6",
        sandbox_enabled: bool = True,
    ) -> SyntheticTree:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        return SyntheticTree(Path(temporary.name), variant, version, sandbox_enabled)

    def assert_failed_with(
        self, result: subprocess.CompletedProcess[str], message: str
    ) -> None:
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(message, result.stderr)

    def test_detects_all_supported_variants(self) -> None:
        for variant in ("official", "sukisu", "resukisu"):
            with self.subTest(variant=variant):
                tree = self.make_tree(variant)
                result = tree.command("detect")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(f"variant={variant} kernel=6.6", result.stdout)

    def test_install_verify_and_reinstall_are_idempotent(self) -> None:
        for variant in ("official", "sukisu", "resukisu"):
            with self.subTest(variant=variant):
                tree = self.make_tree(variant)

                first = tree.command("install")
                self.assertEqual(first.returncode, 0, first.stderr)
                first_snapshot = tree.content_snapshot()

                verify = tree.command("verify", verify_config=True)
                self.assertEqual(verify.returncode, 0, verify.stderr)
                self.assertIn(f"verified variant={variant}", verify.stdout)

                second = tree.command("install")
                self.assertEqual(second.returncode, 0, second.stderr)
                self.assertEqual(first_snapshot, tree.content_snapshot())

                kbuild = (tree.ksu / "Kbuild").read_text()
                self.assertEqual(kbuild.count("ABK_KSU_SANDBOX_V1"), 1)

                dispatch = (tree.ksu / "supercall/dispatch.c").read_text()
                self.assertEqual(
                    dispatch.count("ABK_KSU_SANDBOX_V1: deny sandbox supercalls"),
                    1,
                )
                self.assertIn("abk_sandbox_current(NULL, NULL)", dispatch)

    def test_supercall_comment_anchor_is_not_patched(self) -> None:
        tree = self.make_tree()
        dispatch = tree.ksu / "supercall/dispatch.c"
        anchor = (
            "long ksu_supercall_handle_ioctl(unsigned int cmd, void __user *argp)\n"
            "{\n"
        )
        decoy = "/* decoy function anchor\n" + anchor + "*/\n"
        dispatch.write_text(decoy + dispatch.read_text())

        install = tree.command("install")

        self.assertEqual(install.returncode, 0, install.stderr)
        updated = dispatch.read_text()
        self.assertIn(decoy, updated)
        marker = "ABK_KSU_SANDBOX_V1: deny sandbox supercalls"
        self.assertEqual(updated.count(marker), 1)
        self.assertGreater(updated.index(marker), updated.index(decoy) + len(decoy))

    def test_verify_rejects_sucompat_injection_moved_under_if_zero(self) -> None:
        tree = self.make_tree()
        sucompat = tree.ksu / "feature/sucompat.c"
        unsafe = """    ret = escape_with_root_profile();
    if (ret) {
        pr_err("escape_with_root_profile failed: %ld\\n", ret);
    }"""
        install = tree.command("install")
        self.assertEqual(install.returncode, 0, install.stderr)
        baseline = tree.command("verify", verify_config=True)
        self.assertEqual(baseline.returncode, 0, baseline.stderr)
        installed = sucompat.read_text()
        start = installed.index("    ret = escape_with_root_profile();")
        end = installed.index(
            "\n    ksu_sulog_emit_pending(pending_sucompat, ret, GFP_KERNEL);",
            start,
        )
        injection = installed[start:end]
        sucompat.write_text(
            installed[:start]
            + "#if 0\n"
            + injection
            + "\n#endif\n"
            + unsafe
            + installed[end:]
        )

        verify = tree.command("verify", verify_config=True)

        self.assertNotEqual(verify.returncode, 0, verify.stdout)

    def test_verify_rejects_supercall_function_disabled_by_zero_suffix(self) -> None:
        tree = self.make_tree()
        dispatch = tree.ksu / "supercall/dispatch.c"
        install = tree.command("install")
        self.assertEqual(install.returncode, 0, install.stderr)
        installed = dispatch.read_text()
        function_start = installed.index("long ksu_supercall_handle_ioctl(")
        disabled = installed[function_start:]
        unsafe = """long
ksu_supercall_handle_ioctl(unsigned int cmd, void __user *argp)
{
    return cmd + (argp != 0);
}
"""
        dispatch.write_text(
            installed[:function_start]
            + "#if (0U)\n"
            + disabled
            + "#endif\n"
            + unsafe
        )

        verify = tree.command("verify", verify_config=True)

        self.assertNotEqual(verify.returncode, 0, verify.stdout)

    def test_rejects_unknown_ksu_source_shape(self) -> None:
        tree = self.make_tree("unknown")
        self.assert_failed_with(
            tree.command("detect"), "unrecognized KernelSU source shape"
        )

    def test_rejects_multiple_ksu_source_trees(self) -> None:
        tree = self.make_tree()
        second = tree.add_second_ksu()
        result = tree.command("detect")
        self.assert_failed_with(result, "expected exactly one built-in KernelSU source tree")
        self.assertIn(str(tree.ksu), result.stderr)
        self.assertIn(str(second), result.stderr)

    def test_rejects_lkm_mode(self) -> None:
        tree = self.make_tree()
        self.assert_failed_with(
            tree.command("detect", extra_env={"ABK_BUILD_WORK_MODE": "LKM"}),
            "KernelSU LKM mode is unsupported",
        )

    def test_install_fails_when_a_kernel_anchor_is_missing(self) -> None:
        tree = self.make_tree()
        tree.write(
            tree.common / "fs/namespace.c",
            "#include <linux/mount.h>\n/* may_mount was removed by this fork */\n",
        )
        before = tree.content_snapshot()
        result = tree.command("install")
        self.assert_failed_with(result, "path_mount privilege anchor not found")
        self.assertIn("installation rolled back", result.stderr)
        self.assertEqual(before, tree.content_snapshot())

    def test_late_install_failure_rolls_back_all_kernel_and_ksu_changes(self) -> None:
        tree = self.make_tree(version="6.12")
        tree.write(
            tree.common / "kernel/signal.c",
            "#include <linux/sched/signal.h>\n"
            "static int check_kill_permission(struct task_struct *t)\n"
            "{\n\treturn 0;\n}\n",
        )
        before = tree.content_snapshot()

        result = tree.command("install")

        self.assert_failed_with(
            result, "check_kill_permission credential anchor not found"
        )
        self.assertIn("installation rolled back", result.stderr)
        self.assertEqual(before, tree.content_snapshot())

    def test_rejects_partial_owned_injection(self) -> None:
        tree = self.make_tree()
        tree.write(
            tree.ksu / "Kbuild",
            "kernelsu-objs := main.o\n# ABK_KSU_SANDBOX_V1\n",
        )
        self.assert_failed_with(
            tree.command("install"), "conflicting or partial ABK Kbuild injection"
        )

    def test_legacy_kbuild_block_is_upgraded(self) -> None:
        tree = self.make_tree()
        legacy = """# ABK_KSU_SANDBOX_V1
ifneq ($(CONFIG_KSU_ABK_SANDBOX),y)
$(error ABK KSU Sandbox requires CONFIG_KSU_ABK_SANDBOX=y; run both ABK stages)
endif
kernelsu-objs += abk_sandbox/core.o
kernelsu-objs += abk_sandbox/policy.o
kernelsu-objs += abk_sandbox/namespace.o
kernelsu-objs += abk_sandbox/lsm.o
"""
        kbuild = tree.ksu / "Kbuild"
        kbuild.write_text(kbuild.read_text().rstrip() + "\n" + legacy)

        result = tree.command("install")

        self.assertEqual(result.returncode, 0, result.stderr)
        updated = kbuild.read_text()
        self.assertEqual(updated.count("ABK_KSU_SANDBOX_V1"), 1)
        self.assertIn("-DABK_KSU_RUNTIME_TAIL_SOURCE_VERIFIED=0", updated)

    def test_intermediate_kbuild_block_is_upgraded(self) -> None:
        tree = self.make_tree()
        intermediate = """# ABK_KSU_SANDBOX_V1
ifneq ($(CONFIG_KSU_ABK_SANDBOX),y)
$(error ABK KSU Sandbox requires CONFIG_KSU_ABK_SANDBOX=y; run both ABK stages)
endif
CFLAGS_abk_sandbox/lsm.o += -DABK_KSU_ALLOW_RUNTIME_KSU_TAIL=0
kernelsu-objs += abk_sandbox/core.o
kernelsu-objs += abk_sandbox/policy.o
kernelsu-objs += abk_sandbox/namespace.o
kernelsu-objs += abk_sandbox/lsm.o
"""
        kbuild = tree.ksu / "Kbuild"
        kbuild.write_text(kbuild.read_text().rstrip() + "\n" + intermediate)

        result = tree.command("install")

        self.assertEqual(result.returncode, 0, result.stderr)
        updated = kbuild.read_text()
        self.assertEqual(updated.count("ABK_KSU_SANDBOX_V1"), 1)
        self.assertNotIn("ABK_KSU_ALLOW_RUNTIME_KSU_TAIL", updated)
        self.assertIn("-DABK_KSU_RUNTIME_TAIL_SOURCE_VERIFIED=0", updated)

    def test_resukisu_intermediate_kbuild_block_is_upgraded_idempotently(self) -> None:
        tree = self.make_tree("resukisu", version="6.6")
        intermediate = """# ABK_KSU_SANDBOX_V1
ifneq ($(CONFIG_KSU_ABK_SANDBOX),y)
$(error ABK KSU Sandbox requires CONFIG_KSU_ABK_SANDBOX=y; run both ABK stages)
endif
ifeq ($(CONFIG_KSU_MANUAL_HOOK),y)
$(error ABK KSU Sandbox does not support ReSukiSU manual hook mode)
endif
ifeq ($(CONFIG_KSU_MANUAL_HOOK_AUTO_SETUID_HOOK),y)
$(error ABK KSU Sandbox does not support ReSukiSU manual setuid LSM hooks)
endif
ifeq ($(CONFIG_KSU_MANUAL_HOOK_AUTO_INITRC_HOOK),y)
$(error ABK KSU Sandbox does not support ReSukiSU manual initrc LSM hooks)
endif
ifeq ($(CONFIG_KSU_TRACEPOINT_HOOK),y)
CFLAGS_abk_sandbox/lsm.o += -DABK_KSU_ALLOW_RUNTIME_KSU_TAIL=0
else ifeq ($(CONFIG_KSU_SUSFS),y)
CFLAGS_abk_sandbox/lsm.o += -DABK_KSU_ALLOW_RUNTIME_KSU_TAIL=1
else
CFLAGS_abk_sandbox/lsm.o += -DABK_KSU_ALLOW_RUNTIME_KSU_TAIL=0
endif
kernelsu-objs += abk_sandbox/core.o
kernelsu-objs += abk_sandbox/policy.o
kernelsu-objs += abk_sandbox/namespace.o
kernelsu-objs += abk_sandbox/lsm.o
"""
        kbuild = tree.ksu / "Kbuild"
        kbuild.write_text(kbuild.read_text().rstrip() + "\n" + intermediate)

        migrated = tree.command("install")

        self.assertEqual(migrated.returncode, 0, migrated.stderr)
        updated = kbuild.read_text()
        self.assertEqual(updated.count("ABK_KSU_SANDBOX_V1"), 1)
        self.assertNotIn("ABK_KSU_ALLOW_RUNTIME_KSU_TAIL", updated)
        self.assertIn("-DABK_KSU_RUNTIME_TAIL_SOURCE_VERIFIED=1", updated)
        snapshot = tree.content_snapshot()

        verified = tree.command("verify", verify_config=True)
        self.assertEqual(verified.returncode, 0, verified.stderr)
        reinstalled = tree.command("install")
        self.assertEqual(reinstalled.returncode, 0, reinstalled.stderr)
        self.assertEqual(snapshot, tree.content_snapshot())

    def test_rejects_duplicate_current_kbuild_blocks(self) -> None:
        tree = self.make_tree()
        installed = tree.command("install")
        self.assertEqual(installed.returncode, 0, installed.stderr)
        kbuild = tree.ksu / "Kbuild"
        text = kbuild.read_text()
        block = text[text.index("# ABK_KSU_SANDBOX_V1") :]
        kbuild.write_text(text.rstrip() + "\n" + block)

        self.assert_failed_with(
            tree.command("install"), "conflicting or partial ABK Kbuild injection"
        )
        self.assert_failed_with(
            tree.command("verify", verify_config=True),
            "conflicting or partial ABK Kbuild injection",
        )

    def test_rejects_kbuild_block_nested_under_false_condition(self) -> None:
        tree = self.make_tree()
        installed = tree.command("install")
        self.assertEqual(installed.returncode, 0, installed.stderr)
        kbuild = tree.ksu / "Kbuild"
        text = kbuild.read_text()
        start = text.index("# ABK_KSU_SANDBOX_V1")
        kbuild.write_text(text[:start] + "ifeq (1,0)\n" + text[start:] + "endif\n")

        self.assert_failed_with(
            tree.command("verify", verify_config=True),
            "ABK Kbuild block is nested in a conditional",
        )

    def test_rejects_kbuild_override_directive(self) -> None:
        tree = self.make_tree()
        kbuild = tree.ksu / "Kbuild"
        kbuild.write_text(
            kbuild.read_text().replace(
                "kernelsu-objs := main.o", "override kernelsu-objs := main.o"
            )
        )

        self.assert_failed_with(
            tree.command("install"), "unsupported override directive"
        )

    def test_rejects_kconfig_block_nested_under_false_condition(self) -> None:
        tree = self.make_tree()
        installed = tree.command("install")
        self.assertEqual(installed.returncode, 0, installed.stderr)
        kconfig = tree.ksu / "Kconfig"
        text = kconfig.read_text()
        start = text.index("# ABK_KSU_SANDBOX_V1")
        end = text.index("endmenu", start)
        kconfig.write_text(
            text[:start] + "if BROKEN\n" + text[start:end] + "endif\n" + text[end:]
        )

        self.assert_failed_with(
            tree.command("verify", verify_config=True),
            "ABK Kconfig block is nested in a conditional",
        )

    def test_rejects_duplicate_required_defconfig_symbol(self) -> None:
        tree = self.make_tree()
        installed = tree.command("install")
        self.assertEqual(installed.returncode, 0, installed.stderr)
        config = tree.kernel_root / "gki_defconfig"
        config.write_text(config.read_text() + "# CONFIG_KSU is not set\n")

        self.assert_failed_with(
            tree.command("verify", verify_config=True),
            "defconfig contains duplicate CONFIG_KSU entries",
        )

    def test_rejects_duplicate_legacy_kbuild_blocks(self) -> None:
        tree = self.make_tree()
        legacy = """# ABK_KSU_SANDBOX_V1
ifneq ($(CONFIG_KSU_ABK_SANDBOX),y)
$(error ABK KSU Sandbox requires CONFIG_KSU_ABK_SANDBOX=y; run both ABK stages)
endif
kernelsu-objs += abk_sandbox/core.o
kernelsu-objs += abk_sandbox/policy.o
kernelsu-objs += abk_sandbox/namespace.o
kernelsu-objs += abk_sandbox/lsm.o
"""
        kbuild = tree.ksu / "Kbuild"
        kbuild.write_text(kbuild.read_text().rstrip() + "\n" + legacy + legacy)

        self.assert_failed_with(
            tree.command("install"), "conflicting or partial ABK Kbuild injection"
        )

    def test_rejects_conflicting_runtime_tail_kbuild_blocks(self) -> None:
        tree = self.make_tree(version="6.12")
        installed = tree.command("install")
        self.assertEqual(installed.returncode, 0, installed.stderr)

        resukisu = self.make_tree("resukisu", version="6.6")
        resukisu_installed = resukisu.command("install")
        self.assertEqual(resukisu_installed.returncode, 0, resukisu_installed.stderr)
        resukisu_text = (resukisu.ksu / "Kbuild").read_text()
        resukisu_block = resukisu_text[
            resukisu_text.index("# ABK_KSU_SANDBOX_V1") :
        ]

        kbuild = tree.ksu / "Kbuild"
        kbuild.write_text(kbuild.read_text().rstrip() + "\n" + resukisu_block)

        self.assert_failed_with(
            tree.command("install"), "conflicting or partial ABK Kbuild injection"
        )
        self.assert_failed_with(
            tree.command("verify", verify_config=True),
            "conflicting or partial ABK Kbuild injection",
        )

    def test_rejects_runtime_tail_definitions_outside_the_owned_block(self) -> None:
        definitions = (
            "subdir-ccflags-y += -DABK_KSU_RUNTIME_TAIL_SOURCE_VERIFIED=1",
            "CFLAGS_abk_sandbox/lsm.o += -DABK_KSU_ALLOW_RUNTIME_KSU_TAIL=1",
        )
        for definition in definitions:
            with self.subTest(definition=definition):
                tree = self.make_tree(version="6.12")
                installed = tree.command("install")
                self.assertEqual(installed.returncode, 0, installed.stderr)
                kbuild = tree.ksu / "Kbuild"
                kbuild.write_text(kbuild.read_text() + definition + "\n")

                self.assert_failed_with(
                    tree.command("install"),
                    "conflicting or partial ABK Kbuild injection",
                )
                self.assert_failed_with(
                    tree.command("verify", verify_config=True),
                    "conflicting or partial ABK Kbuild injection",
                )

    def test_runtime_ksu_tail_requires_audited_resukisu_configuration(self) -> None:
        tree = self.make_tree("resukisu", version="6.6")
        config = tree.kernel_root / "gki_defconfig"

        after_patch = tree.setup_stage("after_patch")

        self.assertEqual(after_patch.returncode, 0, after_patch.stderr)
        kbuild = (tree.ksu / "Kbuild").read_text()
        self.assertIn("subdir-ccflags-y", kbuild)
        self.assertIn("-DABK_KSU_RUNTIME_TAIL_SOURCE_VERIFIED=1", kbuild)
        config.write_text(config.read_text() + "CONFIG_KSU_SUSFS=y\n")
        before_build = tree.setup_stage("before_build")
        self.assertEqual(before_build.returncode, 0, before_build.stderr)

        def evaluate(
            target: SyntheticTree, *assignments: str
        ) -> subprocess.CompletedProcess[str]:
            harness = target.base / "kbuild-eval.mk"
            harness.write_text(
                f"include {target.ksu / 'Kbuild'}\n"
                "all:\n"
                "\t@printf '%s\\n' '$(subdir-ccflags-y)'\n"
            )
            return subprocess.run(
                [
                    "make",
                    "--no-print-directory",
                    "-s",
                    "-f",
                    str(harness),
                    "CONFIG_KSU_ABK_SANDBOX=y",
                    *assignments,
                ],
                check=False,
                capture_output=True,
                text=True,
            )

        susfs = evaluate(tree, "CONFIG_KSU_SUSFS=y")
        self.assertEqual(susfs.returncode, 0, susfs.stderr)
        self.assertEqual(
            susfs.stdout.strip(), "-DABK_KSU_RUNTIME_TAIL_SOURCE_VERIFIED=1"
        )
        tracepoint = evaluate(
            tree, "CONFIG_KSU_TRACEPOINT_HOOK=y", "CONFIG_KSU_SUSFS=y"
        )
        self.assertEqual(tracepoint.returncode, 0, tracepoint.stderr)
        self.assertEqual(
            tracepoint.stdout.strip(),
            "-DABK_KSU_RUNTIME_TAIL_SOURCE_VERIFIED=1",
        )
        manual = evaluate(tree, "CONFIG_KSU_MANUAL_HOOK=y")
        self.assertNotEqual(manual.returncode, 0, manual.stdout)
        self.assertIn("does not support ReSukiSU manual hook mode", manual.stderr)

        for variant in ("official", "sukisu"):
            with self.subTest(variant=variant):
                other = self.make_tree(variant, version="6.6")
                result = other.command("install", verify_config=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(
                    "-DABK_KSU_RUNTIME_TAIL_SOURCE_VERIFIED=0",
                    (other.ksu / "Kbuild").read_text(),
                )
                evaluated = evaluate(other, "CONFIG_KSU_SUSFS=y")
                self.assertEqual(evaluated.returncode, 0, evaluated.stderr)
                self.assertEqual(
                    evaluated.stdout.strip(),
                    "-DABK_KSU_RUNTIME_TAIL_SOURCE_VERIFIED=0",
                )

        modern = self.make_tree("resukisu", version="6.12")
        modern_config = modern.kernel_root / "gki_defconfig"
        modern_config.write_text(modern_config.read_text() + "CONFIG_KSU_SUSFS=y\n")
        result = modern.command("install", verify_config=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(
            "-DABK_KSU_RUNTIME_TAIL_SOURCE_VERIFIED=0",
            (modern.ksu / "Kbuild").read_text(),
        )

    def test_runtime_ksu_tail_rejects_changed_or_overlapping_hooks(self) -> None:
        changed = self.make_tree("resukisu", version="6.6")
        changed_config = changed.kernel_root / "gki_defconfig"
        changed_config.write_text(changed_config.read_text() + "CONFIG_KSU_SUSFS=y\n")
        hooks = changed.ksu / "hook/lsm_hooks.c"
        hooks.write_text(
            hooks.read_text().replace(
                "    LSM_HOOK_INIT(inode_rename, ksu_inode_rename),\n",
                "    LSM_HOOK_INIT(inode_rename, ksu_inode_rename),\n"
                "    LSM_HOOK_INIT(bprm_committing_creds, ksu_bprm_committing_creds),\n",
            )
        )
        self.assert_failed_with(
            changed.command("install", verify_config=True),
            "unsupported ReSukiSU runtime LSM hook shape",
        )

        manual = self.make_tree("resukisu", version="6.6")
        manual_config = manual.kernel_root / "gki_defconfig"
        manual_config.write_text(manual_config.read_text() + "CONFIG_KSU_MANUAL_HOOK=y\n")
        self.assert_failed_with(
            manual.command("install", verify_config=True),
            "ReSukiSU manual LSM credential hooks are unsupported",
        )

    def test_rejects_foreign_sandbox_directory(self) -> None:
        tree = self.make_tree()
        tree.write(tree.ksu / "abk_sandbox/core.c", "/* foreign source */\n")
        self.assert_failed_with(
            tree.command("install"), "refusing non-ABK file in sandbox source target"
        )

    def test_preserves_trusted_kbuild_artifacts_on_reinstall(self) -> None:
        tree = self.make_tree()
        first = tree.command("install")
        self.assertEqual(first.returncode, 0, first.stderr)
        artifacts = {
            tree.ksu / "abk_sandbox/core.o": b"\x7fELF synthetic object\x00",
            tree.ksu / "abk_sandbox/.core.o.cmd": b"cmd_core.o := cc core.c\n",
            tree.ksu / "abk_sandbox/.policy.o.d": b"policy.o: policy.c\n",
        }
        for path, content in artifacts.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)

        install = tree.command("install")

        self.assertEqual(install.returncode, 0, install.stderr)
        for path, content in artifacts.items():
            self.assertEqual(path.read_bytes(), content)
        verify = tree.command("verify", verify_config=True)
        self.assertEqual(verify.returncode, 0, verify.stderr)

    def test_changed_template_source_gets_a_fresh_installed_mtime(self) -> None:
        tree = self.make_tree()
        first = tree.command("install")
        self.assertEqual(first.returncode, 0, first.stderr)

        template = tree.module_root / "files/abk_ksu_sandbox/core.c"
        installed = tree.ksu / "abk_sandbox/core.c"
        template.write_text(template.read_text() + "/* template update */\n")
        os.utime(template, (1, 1))
        os.utime(installed, (1000, 1000))

        second = tree.command("install")

        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(installed.read_text(), template.read_text())
        self.assertGreater(installed.stat().st_mtime, 1000)

    def test_changed_template_source_invalidates_trusted_build_artifacts(self) -> None:
        tree = self.make_tree()
        first = tree.command("install")
        self.assertEqual(first.returncode, 0, first.stderr)
        artifact = tree.ksu / "abk_sandbox/core.o"
        dependency = tree.ksu / "abk_sandbox/.core.o.cmd"
        artifact.write_bytes(b"stale object")
        dependency.write_text("cmd_core.o := stale\n")
        template = tree.module_root / "files/abk_ksu_sandbox/core.c"
        template.write_text(template.read_text() + "/* security update */\n")

        second = tree.command("install")

        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertFalse(artifact.exists())
        self.assertFalse(dependency.exists())

    def test_failed_upgrade_restores_removed_build_artifacts(self) -> None:
        tree = self.make_tree()
        first = tree.command("install")
        self.assertEqual(first.returncode, 0, first.stderr)
        artifact = tree.ksu / "abk_sandbox/core.o"
        artifact.write_bytes(b"existing object")
        template = tree.module_root / "files/abk_ksu_sandbox/core.c"
        template.write_text(template.read_text() + "/* update before failure */\n")
        signal = tree.common / "kernel/signal.c"
        signal.write_text(
            signal.read_text().replace(
                "\t    !abk_ksu_sandbox_may_signal(t) &&\n", "", 1
            )
        )
        before = tree.content_snapshot()

        failed = tree.command("install")

        self.assert_failed_with(failed, "conflicting or partial ABK injection")
        self.assertIn("installation rolled back", failed.stderr)
        self.assertEqual(before, tree.content_snapshot())

    def test_rejects_unexpected_sandbox_source_and_directory(self) -> None:
        for entry_type in ("source", "directory"):
            with self.subTest(entry_type=entry_type):
                tree = self.make_tree()
                if entry_type == "source":
                    tree.write(
                        tree.ksu / "abk_sandbox/backdoor.c",
                        "/* ABK_KSU_SANDBOX_V1 */\n",
                    )
                    expected = "refusing unexpected file in sandbox source target"
                else:
                    (tree.ksu / "abk_sandbox/generated").mkdir(parents=True)
                    expected = "refusing unexpected directory in sandbox source target"
                self.assert_failed_with(tree.command("install"), expected)

    def test_known_legacy_source_is_removed_but_foreign_content_is_rejected(self) -> None:
        tree = self.make_tree()
        first = tree.command("install")
        self.assertEqual(first.returncode, 0, first.stderr)
        legacy = tree.ksu / "abk_sandbox/abk_ksu_sandbox_api.h"
        artifact = tree.ksu / "abk_sandbox/core.o"
        legacy.write_text("/* ABK_KSU_SANDBOX_V1: legacy private copy */\n")
        artifact.write_bytes(b"current object")

        migrated = tree.command("install")

        self.assertEqual(migrated.returncode, 0, migrated.stderr)
        self.assertFalse(legacy.exists())
        self.assertTrue(artifact.exists())

        legacy.write_text("/* foreign replacement */\n")
        rejected = tree.command("install")
        self.assert_failed_with(rejected, "refusing non-ABK legacy file")

    def test_kernel_hook_include_is_normalized_and_old_marker_self_heals(self) -> None:
        tree = self.make_tree()
        first = tree.command("install")
        self.assertEqual(first.returncode, 0, first.stderr)
        signal_path = tree.common / "kernel/signal.c"
        include = "#include <linux/abk_ksu_sandbox.h>\n"
        signal = signal_path.read_text()
        self.assertEqual(signal.count(include), 1)
        self.assertLess(signal.index(include), signal.index("static int check_kill_permission"))
        self.assertLess(signal.index(include), signal.index("#include <linux/kdb.h>"))

        signal_path.write_text(signal.replace(include, "", 1) + include)
        second = tree.command("install")

        self.assertEqual(second.returncode, 0, second.stderr)
        repaired = signal_path.read_text()
        self.assertEqual(repaired.count(include), 1)
        self.assertLess(
            repaired.index(include), repaired.index("static int check_kill_permission")
        )
        self.assertLess(repaired.index(include), repaired.index("#include <linux/kdb.h>"))

    def test_old_bind_validation_hook_is_upgraded(self) -> None:
        tree = self.make_tree()
        first = tree.command("install")
        self.assertEqual(first.returncode, 0, first.stderr)
        namespace = tree.common / "fs/namespace.c"
        current = namespace.read_text()
        namespace.write_text(
            current.replace(
                "abk_ksu_sandbox_bind_validate(&old_path, path, recurse)",
                "abk_ksu_sandbox_bind_validate(&old_path, path)",
                1,
            )
        )

        second = tree.command("install")

        self.assertEqual(second.returncode, 0, second.stderr)
        upgraded = namespace.read_text()
        self.assertIn(
            "abk_ksu_sandbox_bind_validate(&old_path, path, recurse)", upgraded
        )
        self.assertNotIn(
            "abk_ksu_sandbox_bind_validate(&old_path, path);", upgraded
        )

    def test_verify_rejects_a_marker_with_a_missing_hook_call(self) -> None:
        tree = self.make_tree()
        install = tree.command("install")
        self.assertEqual(install.returncode, 0, install.stderr)
        seccomp = tree.common / "kernel/seccomp.c"
        seccomp.write_text(
            seccomp.read_text().replace(
                "\tif (abk_ksu_sandbox_seccomp_allow_syscall(this_syscall))\n"
                "\t\treturn 0;\n",
                "",
                1,
            )
        )

        verify = tree.command("verify", verify_config=True)

        self.assert_failed_with(
            verify, "abk_ksu_sandbox_seccomp_allow_syscall(this_syscall)"
        )

    def test_setup_runs_both_required_stages(self) -> None:
        tree = self.make_tree(sandbox_enabled=False)

        after_patch = tree.setup_stage("after_patch")
        self.assertEqual(after_patch.returncode, 0, after_patch.stderr)
        self.assertIn("installed variant=official", after_patch.stdout)

        before_build = tree.setup_stage("before_build")
        self.assertEqual(before_build.returncode, 0, before_build.stderr)
        self.assertIn("verified variant=official", before_build.stdout)
        config = (tree.kernel_root / "gki_defconfig").read_text()
        self.assertIn("CONFIG_KSU_ABK_SANDBOX=y", config)
        self.assertIn('CONFIG_LSM="selinux,abk_ksu_sandbox"', config)
        self.assertIn("run both ABK stages", (tree.ksu / "Kbuild").read_text())

        repeated = tree.setup_stage("before_build")
        self.assertEqual(repeated.returncode, 0, repeated.stderr)
        config = (tree.kernel_root / "gki_defconfig").read_text()
        self.assertEqual(config.count("abk_ksu_sandbox"), 1)

    def test_setup_moves_existing_sandbox_lsm_to_the_end(self) -> None:
        tree = self.make_tree(sandbox_enabled=False)
        config_path = tree.kernel_root / "gki_defconfig"
        config_path.write_text(
            config_path.read_text().replace(
                'CONFIG_LSM="selinux"',
                'CONFIG_LSM="abk_ksu_sandbox,yama,selinux,bpf"',
            )
        )
        self.assertEqual(tree.setup_stage("after_patch").returncode, 0)

        before_build = tree.setup_stage("before_build")

        self.assertEqual(before_build.returncode, 0, before_build.stderr)
        self.assertIn(
            'CONFIG_LSM="yama,selinux,bpf,abk_ksu_sandbox"',
            config_path.read_text(),
        )

    def test_setup_uses_kernel_lsm_default_when_defconfig_omits_it(self) -> None:
        tree = self.make_tree(sandbox_enabled=False)
        config_path = tree.kernel_root / "gki_defconfig"
        config_path.write_text(
            config_path.read_text().replace('CONFIG_LSM="selinux"\n', "")
        )
        self.assertEqual(tree.setup_stage("after_patch").returncode, 0)

        before_build = tree.setup_stage("before_build")

        self.assertEqual(before_build.returncode, 0, before_build.stderr)
        self.assertIn(
            'CONFIG_LSM="lockdown,yama,integrity,selinux,bpf,abk_ksu_sandbox"',
            config_path.read_text(),
        )

    def test_setup_rejects_lsm_list_without_selinux(self) -> None:
        tree = self.make_tree(sandbox_enabled=False)
        config_path = tree.kernel_root / "gki_defconfig"
        config_path.write_text(
            config_path.read_text().replace(
                'CONFIG_LSM="selinux"', 'CONFIG_LSM="yama,integrity"'
            )
        )
        self.assertEqual(tree.setup_stage("after_patch").returncode, 0)

        self.assert_failed_with(
            tree.setup_stage("before_build"), "CONFIG_LSM must include selinux"
        )

    def test_setup_uses_selected_conditional_lsm_default(self) -> None:
        tree = self.make_tree(sandbox_enabled=False)
        config_path = tree.kernel_root / "gki_defconfig"
        config_path.write_text(
            config_path.read_text().replace(
                'CONFIG_LSM="selinux"\n',
                "CONFIG_DEFAULT_SECURITY_APPARMOR=y\n",
            )
        )
        self.assertEqual(tree.setup_stage("after_patch").returncode, 0)

        before_build = tree.setup_stage("before_build")

        self.assertEqual(before_build.returncode, 0, before_build.stderr)
        self.assertIn(
            'CONFIG_LSM="yama,apparmor,selinux,bpf,abk_ksu_sandbox"',
            config_path.read_text(),
        )

    def test_setup_rejects_selected_default_without_selinux(self) -> None:
        tree = self.make_tree(sandbox_enabled=False)
        config_path = tree.kernel_root / "gki_defconfig"
        config_path.write_text(
            config_path.read_text().replace(
                'CONFIG_LSM="selinux"\n',
                "CONFIG_DEFAULT_SECURITY_DAC=y\n",
            )
        )
        self.assertEqual(tree.setup_stage("after_patch").returncode, 0)

        self.assert_failed_with(
            tree.setup_stage("before_build"), "CONFIG_LSM must include selinux"
        )

    def test_verify_rejects_empty_or_duplicate_lsm_entries(self) -> None:
        for lsm_list, expected in (
            ("selinux,,abk_ksu_sandbox", "must not contain empty entries"),
            (
                "selinux,abk_ksu_sandbox,selinux",
                "must not contain duplicate entries",
            ),
        ):
            with self.subTest(lsm_list=lsm_list):
                tree = self.make_tree()
                self.assertEqual(tree.command("install").returncode, 0)
                config_path = tree.kernel_root / "gki_defconfig"
                config_path.write_text(
                    config_path.read_text().replace(
                        'CONFIG_LSM="selinux,abk_ksu_sandbox"',
                        f'CONFIG_LSM="{lsm_list}"',
                    )
                )

                self.assert_failed_with(
                    tree.command("verify", verify_config=True), expected
                )

    def test_verify_rejects_missing_sandbox_lsm(self) -> None:
        tree = self.make_tree()
        self.assertEqual(tree.command("install").returncode, 0)
        config_path = tree.kernel_root / "gki_defconfig"
        config_path.write_text(
            config_path.read_text().replace(
                'CONFIG_LSM="selinux,abk_ksu_sandbox"',
                'CONFIG_LSM="selinux"',
            )
        )

        self.assert_failed_with(
            tree.command("verify", verify_config=True),
            "CONFIG_LSM must include abk_ksu_sandbox exactly once",
        )

    def test_setup_enables_default_builtin_ksu_when_defconfig_omits_it(self) -> None:
        tree = self.make_tree()
        config_path = tree.kernel_root / "gki_defconfig"
        config_path.write_text(config_path.read_text().replace("CONFIG_KSU=y\n", ""))

        after_patch = tree.setup_stage("after_patch")

        self.assertEqual(after_patch.returncode, 0, after_patch.stderr)
        self.assertIn("CONFIG_KSU=y", config_path.read_text())

    def test_setup_rejects_modular_or_disabled_ksu(self) -> None:
        for value in ("m", "n"):
            with self.subTest(value=value):
                tree = self.make_tree()
                config_path = tree.kernel_root / "gki_defconfig"
                config_path.write_text(
                    config_path.read_text().replace("CONFIG_KSU=y", f"CONFIG_KSU={value}")
                )

                result = tree.setup_stage("after_patch")

                self.assert_failed_with(result, "CONFIG_KSU must be built-in")

    def test_before_build_without_after_patch_fails(self) -> None:
        tree = self.make_tree(sandbox_enabled=False)
        self.assert_failed_with(
            tree.setup_stage("before_build"), "incomplete sandbox injection"
        )

    def test_rejects_missing_required_base_config(self) -> None:
        tree = self.make_tree()
        config = tree.kernel_root / "gki_defconfig"
        config.write_text(config.read_text().replace("CONFIG_SECURITY_SELINUX=y\n", ""))
        self.assert_failed_with(
            tree.command("install", verify_config=True),
            "CONFIG_SECURITY_SELINUX=y is required",
        )

    def test_linux_612_lsm_count_injection_is_idempotent(self) -> None:
        tree = self.make_tree(version="6.12")
        first = tree.command("install")
        self.assertEqual(first.returncode, 0, first.stderr)
        snapshot = tree.content_snapshot()
        second = tree.command("install")
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(snapshot, tree.content_snapshot())
        verify = tree.command("verify", verify_config=True)
        self.assertEqual(verify.returncode, 0, verify.stderr)
        lsm_count = (tree.common / "include/linux/lsm_count.h").read_text()
        self.assertEqual(lsm_count.count("ABK_KSU_SANDBOX_V1: lsm count"), 1)

    def test_verify_rejects_lsm_count_comment_spoof(self) -> None:
        tree = self.make_tree(version="6.12")
        lsm_count = tree.common / "include/linux/lsm_count.h"
        original = lsm_count.read_text()
        install = tree.command("install")
        self.assertEqual(install.returncode, 0, install.stderr)
        baseline = tree.command("verify", verify_config=True)
        self.assertEqual(baseline.returncode, 0, baseline.stderr)
        lsm_count.write_text(
            original
            + "\n/* ABK_KSU_SANDBOX_V1: lsm count */\n"
            + "/* ABK_KSU_SANDBOX_ENABLED ABK_KSU_SANDBOX_ENABLED "
            + "ABK_KSU_SANDBOX_ENABLED */\n"
        )

        verify = tree.command("verify", verify_config=True)

        self.assertNotEqual(verify.returncode, 0, verify.stdout)

    def test_verify_rejects_missing_mount_result_call(self) -> None:
        tree = self.make_tree()
        namespace = tree.common / "fs/namespace.c"
        install = tree.command("install")
        self.assertEqual(install.returncode, 0, install.stderr)
        baseline = tree.command("verify", verify_config=True)
        self.assertEqual(baseline.returncode, 0, baseline.stderr)
        installed = namespace.read_text()
        call = "abk_ksu_sandbox_mount_result(path, ret);"
        self.assertEqual(installed.count(call), 3)
        namespace.write_text(installed.replace(call, "/* removed mount-result */", 1))

        verify = tree.command("verify", verify_config=True)

        self.assertNotEqual(verify.returncode, 0, verify.stdout)

    def test_resukisu_rejects_extra_security_hook_registration(self) -> None:
        cases = (
            ("c", "security_add_hooks"),
            ("h", "security_add_hooks"),
            ("inc", "security_add_hooks"),
            ("c", "security_add_\\\nhooks"),
        )
        for suffix, registration in cases:
            with self.subTest(suffix=suffix, registration=registration):
                tree = self.make_tree("resukisu")
                extra = tree.ksu / f"feature/extra_registration.{suffix}"
                extra.write_text(
                    "static struct security_hook_list extra_hooks[];\n"
                    "static void extra_registration(void)\n"
                    "{\n"
                    f"    {registration}(extra_hooks, ARRAY_SIZE(extra_hooks), "
                    '"k" "su");\n'
                    "}\n"
                )

                result = tree.command("install", verify_config=True)

                self.assert_failed_with(
                    result, "unsupported ReSukiSU runtime LSM hook shape"
                )

    def test_resukisu_rejects_disabled_audited_hook_array(self) -> None:
        for guard in ("#if 0U", "#ifdef CONFIG_NEVER_ENABLED"):
            with self.subTest(guard=guard):
                tree = self.make_tree("resukisu")
                hooks = tree.ksu / "hook/lsm_hooks.c"
                original = hooks.read_text()
                array_start = original.index(
                    "static struct security_hook_list ksu_hooks[]"
                )
                array_end = original.index(
                    "void __init ksu_lsm_hook_built_in_init", array_start
                )
                audited_array = original[array_start:array_end]
                unsafe_array = """static struct security_hook_list ksu_hooks[] __ro_after_init = {
    LSM_HOOK_INIT(inode_rename, ksu_inode_rename),
    LSM_HOOK_INIT(task_fix_setuid, ksu_task_fix_setuid),
};
"""
                hooks.write_text(
                    original[:array_start]
                    + guard
                    + "\n"
                    + audited_array
                    + "#endif\n"
                    + unsafe_array
                    + original[array_end:]
                )

                result = tree.command("install", verify_config=True)

                self.assert_failed_with(
                    result, "unsupported ReSukiSU runtime LSM hook shape"
                )

    def test_template_keeps_runtime_security_guards(self) -> None:
        sources = REPOSITORY / "files/abk_ksu_sandbox"
        core = (sources / "core.c").read_text()
        lsm = (sources / "lsm.c").read_text()
        namespace = (sources / "namespace.c").read_text()
        policy = (sources / "policy.c").read_text()

        self.assertIn("if (!abk_sandbox_lsm_ready())", core)
        self.assertIn(".order = LSM_ORDER_MUTABLE", lsm)
        self.assertIn("WRITE_ONCE(abk_lsm_ready, true)", lsm)
        self.assertIn("late_initcall(abk_lsm_finalize)", lsm)
        self.assertIn("ABK_KSU_ALLOW_RUNTIME_KSU_TAIL", lsm)
        self.assertIn("abk_lsm_order_is_safe(lsm_names,", lsm)
        self.assertIn('expected sandbox%s', lsm)
        self.assertNotIn("MNT_DETACH", lsm)
        self.assertNotIn("MNT_DETACH", namespace)
        self.assertIn("bitmap_weight(abk_owned_types", policy)
        self.assertIn("ABK_SANDBOX_MAX_INSTANCES", policy)

    def test_runtime_lsm_build_config_requires_source_and_susfs(self) -> None:
        source_dir = REPOSITORY / "files/abk_ksu_sandbox"
        cases = (
            ((), 0),
            (("ABK_KSU_RUNTIME_TAIL_SOURCE_VERIFIED=1",), 0),
            (
                (
                    "ABK_KSU_RUNTIME_TAIL_SOURCE_VERIFIED=1",
                    "CONFIG_KSU_SUSFS=1",
                ),
                1,
            ),
            (
                (
                    "ABK_KSU_RUNTIME_TAIL_SOURCE_VERIFIED=1",
                    "CONFIG_KSU_SUSFS=1",
                    "CONFIG_KSU_TRACEPOINT_HOOK=1",
                ),
                0,
            ),
            (
                (
                    "ABK_KSU_RUNTIME_TAIL_SOURCE_VERIFIED=1",
                    "CONFIG_KSU_SUSFS=1",
                    "CONFIG_KSU_MANUAL_HOOK=1",
                ),
                0,
            ),
            (
                (
                    "ABK_KSU_RUNTIME_TAIL_SOURCE_VERIFIED=1",
                    "CONFIG_KSU_SUSFS=1",
                    "CONFIG_KSU_MANUAL_HOOK_AUTO_SETUID_HOOK=1",
                ),
                0,
            ),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            harness = root / "lsm_build_config_test.c"
            harness.write_text(
                """#include "lsm_build_config.h"
#if ABK_KSU_ALLOW_RUNTIME_KSU_TAIL != EXPECTED
#error "unexpected runtime KSU tail policy"
#endif
int main(void) { return 0; }
"""
            )
            for index, (defines, expected) in enumerate(cases):
                with self.subTest(defines=defines, expected=expected):
                    binary = root / f"lsm_build_config_test_{index}"
                    command = [
                        os.environ.get("CC", "cc"),
                        "-std=c11",
                        "-Wall",
                        "-Wextra",
                        "-Werror",
                        "-I",
                        str(source_dir),
                        f"-DEXPECTED={expected}",
                    ]
                    command.extend(f"-D{define}" for define in defines)
                    command.extend((str(harness), "-o", str(binary)))
                    result = subprocess.run(
                        command, check=False, capture_output=True, text=True
                    )
                    self.assertEqual(
                        result.returncode, 0, result.stdout + result.stderr
                    )

    def test_runtime_lsm_order_accepts_only_optional_ksu_tail(self) -> None:
        source_dir = REPOSITORY / "files/abk_ksu_sandbox"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            harness = root / "lsm_order_test.c"
            binary = root / "lsm_order_test"
            harness.write_text(
                """#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "lsm_order.h"

struct test_case {
    const char *list;
    bool allow_ksu_tail;
    bool expected;
};

int main(void)
{
    static const struct test_case cases[] = {
        { "capability,selinux,abk_ksu_sandbox", false, true },
        { "capability,selinux,abk_ksu_sandbox,ksu", true, true },
        { "capability,selinux,abk_ksu_sandbox,ksu", false, false },
        { "capability,selinux,ksu,abk_ksu_sandbox", false, true },
        { "capability,selinux,abk_ksu_sandbox,bpf", true, false },
        { "capability,selinux,abk_ksu_sandbox,ksu,bpf", true, false },
        { "capability,selinux,abk_ksu_sandbox,ksu,ksu", true, false },
        { "capability,selinux,abk_ksu_sandbox,abk_ksu_sandbox", true, false },
        { "capability,selinux,abk_ksu_sandbox,landlock,ksu", true, false },
        { "capability,selinux,selinux,abk_ksu_sandbox", false, false },
        { "capability,bpf,bpf,selinux,abk_ksu_sandbox", false, false },
        { "capability,selinux,,abk_ksu_sandbox", false, false },
        { "capability,selinux,abk_ksu_sandbox,", false, false },
        { "capability,selinux,ksu", true, false },
        { "", false, false },
    };
    size_t index;

    for (index = 0; index < sizeof(cases) / sizeof(cases[0]); index++) {
        bool actual = abk_lsm_order_is_safe(
            cases[index].list, cases[index].allow_ksu_tail);

        if (actual != cases[index].expected) {
            fprintf(stderr, "case %zu failed: %s\\n", index, cases[index].list);
            return (int)index + 1;
        }
    }
    return 0;
}
"""
            )
            compile_result = subprocess.run(
                [
                    os.environ.get("CC", "cc"),
                    "-std=c11",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-I",
                    str(source_dir),
                    str(harness),
                    "-o",
                    str(binary),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(
                compile_result.returncode,
                0,
                compile_result.stdout + compile_result.stderr,
            )
            run_result = subprocess.run(
                [str(binary)], check=False, capture_output=True, text=True
            )
            self.assertEqual(
                run_result.returncode,
                0,
                run_result.stdout + run_result.stderr,
            )

    def test_device_runners_require_the_kernel_su_entrypoint(self) -> None:
        direct = (
            REPOSITORY
            / "test-apps/direct/src/main/java/dev/anybase/abksandbox/direct/DirectSuRunner.java"
        ).read_text()
        libsu = (
            REPOSITORY
            / "test-apps/libsu/src/main/java/dev/anybase/abksandbox/libsu/LibsuRunner.java"
        ).read_text()
        probe = (
            REPOSITORY
            / "test-apps/shared/src/main/java/dev/anybase/abksandbox/smoke/ProbeScript.java"
        ).read_text()

        self.assertIn('new ProcessBuilder("/system/bin/su", "-c",', direct)
        self.assertIn('.build("/system/bin/su")', libsu)
        self.assertIn("if (!shell.isRoot())", libsu)
        self.assertNotIn("id -G", probe)
        self.assertIn("'^Groups:'", probe)

    def test_rejects_unsupported_kernel_line(self) -> None:
        tree = self.make_tree(version="6.5")
        self.assert_failed_with(tree.command("detect"), "unsupported kernel line 6.5")


if __name__ == "__main__":
    unittest.main()
