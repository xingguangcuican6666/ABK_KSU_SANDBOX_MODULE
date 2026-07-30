#!/usr/bin/env python3
"""Install and verify the ABK KernelSU sandbox source integration."""

from __future__ import annotations

import argparse
import os
import re
import shutil
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path


SUPPORTED_KERNELS = {"5.10", "5.15", "6.1", "6.6", "6.12"}
MARKER = "ABK_KSU_SANDBOX_V1"
KBUILD_BLOCK = f"""

# {MARKER}
ifneq ($(CONFIG_KSU_ABK_SANDBOX),y)
$(error ABK KSU Sandbox requires CONFIG_KSU_ABK_SANDBOX=y; run both ABK stages)
endif
kernelsu-objs += abk_sandbox/core.o
kernelsu-objs += abk_sandbox/policy.o
kernelsu-objs += abk_sandbox/namespace.o
kernelsu-objs += abk_sandbox/lsm.o
"""
KCONFIG_BLOCK = f"""

# {MARKER}
config KSU_ABK_SANDBOX
    bool "ABK per-app KernelSU sandbox"
    depends on KSU=y && SECURITY_SELINUX && NAMESPACES
    default n
    help
      Put authorized untrusted-app su sessions in per-app SELinux and
      mount namespaces. Unsupported or incomplete initialization fails closed.
"""


class InstallError(RuntimeError):
    pass


_ACTIVE_TRANSACTION: InstallTransaction | None = None


class InstallTransaction:
    """Restore every installer-owned write if installation does not complete."""

    def __init__(self) -> None:
        self._temporary: tempfile.TemporaryDirectory[str] | None = None
        self._backup_root: Path | None = None
        self._files: dict[Path, Path | None] = {}
        self._missing_directories: set[Path] = set()

    def __enter__(self) -> InstallTransaction:
        global _ACTIVE_TRANSACTION

        if _ACTIVE_TRANSACTION is not None:
            raise InstallError("nested installer transaction is unsupported")
        self._temporary = tempfile.TemporaryDirectory(prefix="abk-ksu-sandbox-install-")
        self._backup_root = Path(self._temporary.name)
        _ACTIVE_TRANSACTION = self
        return self

    def _record_missing_directories(self, path: Path) -> None:
        cursor = path
        while not cursor.exists():
            if cursor.is_symlink():
                raise InstallError(f"refusing broken symlink in installer target: {cursor}")
            self._missing_directories.add(cursor)
            parent = cursor.parent
            if parent == cursor:
                break
            cursor = parent
        if cursor.exists() and not cursor.is_dir():
            raise InstallError(f"installer target parent is not a directory: {cursor}")

    def record_directory(self, path: Path) -> None:
        if path.is_symlink():
            raise InstallError(f"refusing symlink installer directory target: {path}")
        if path.exists():
            if not path.is_dir():
                raise InstallError(f"installer directory target is not a directory: {path}")
            return
        self._record_missing_directories(path)

    def record_file(self, path: Path) -> None:
        if path in self._files:
            return
        if path.is_symlink():
            raise InstallError(f"refusing symlink installer file target: {path}")
        self._record_missing_directories(path.parent)
        if path.exists():
            if not path.is_file():
                raise InstallError(f"installer file target is not a regular file: {path}")
            assert self._backup_root is not None
            backup = self._backup_root / str(len(self._files))
            shutil.copy2(path, backup)
            self._files[path] = backup
        else:
            self._files[path] = None

    def _rollback(self) -> None:
        failures: list[str] = []
        for path, backup in reversed(tuple(self._files.items())):
            try:
                if backup is None:
                    if path.is_symlink() or path.is_file():
                        path.unlink()
                    elif path.exists():
                        raise OSError("new installer file was replaced by a directory")
                    continue
                if path.is_symlink():
                    path.unlink()
                elif path.exists() and not path.is_file():
                    raise OSError("installer file was replaced by a directory")
                path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(backup, path)
            except OSError as exc:
                failures.append(f"{path}: {exc}")

        for path in sorted(
            self._missing_directories, key=lambda item: len(item.parts), reverse=True
        ):
            try:
                path.rmdir()
            except FileNotFoundError:
                pass
            except OSError as exc:
                failures.append(f"{path}: {exc}")

        if failures:
            raise InstallError("installation rollback failed: " + "; ".join(failures))

    def __exit__(self, exc_type: object, exc: BaseException | None, traceback: object) -> bool:
        global _ACTIVE_TRANSACTION

        rollback_error: InstallError | None = None
        try:
            if exc is not None:
                try:
                    self._rollback()
                except InstallError as rollback_exc:
                    rollback_error = rollback_exc
                else:
                    if self._files or self._missing_directories:
                        print("ABK KSU Sandbox: installation rolled back", file=sys.stderr)
        finally:
            _ACTIVE_TRANSACTION = None
            if self._temporary is not None:
                self._temporary.cleanup()

        if rollback_error is not None:
            raise rollback_error from exc
        return False


@dataclass(frozen=True)
class Layout:
    kernel_root: Path
    common: Path
    ksu: Path
    variant: str
    version: str


def read(path: Path) -> str:
    try:
        return path.read_text()
    except FileNotFoundError as exc:
        raise InstallError(f"required file not found: {path}") from exc


def write(path: Path, text: str) -> None:
    old = path.read_text() if path.exists() else None
    if old == text:
        return
    if _ACTIVE_TRANSACTION is not None:
        _ACTIVE_TRANSACTION.record_file(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    print(f"ABK KSU Sandbox: updated {path}")


def remove_file(path: Path, description: str = "stale build artifact") -> None:
    if not path.exists():
        return
    if path.is_symlink() or not path.is_file():
        raise InstallError(f"refusing non-regular installer removal target: {path}")
    if _ACTIVE_TRANSACTION is not None:
        _ACTIVE_TRANSACTION.record_file(path)
    path.unlink()
    print(f"ABK KSU Sandbox: removed {description} {path}")


def installed_or_fail(path: Path, text: str, marker: str, needles: tuple[str, ...]) -> bool:
    if marker not in text:
        return False
    missing = [needle for needle in needles if needle not in text]
    if missing:
        raise InstallError(
            f"conflicting or partial ABK injection in {path}: missing {', '.join(repr(item) for item in missing)}"
        )
    return True


def kernel_common(root: Path) -> Path:
    common = root / "common"
    if (common / "Makefile").is_file():
        return common
    if (root / "Makefile").is_file():
        return root
    raise InstallError(f"kernel Makefile not found below {root}")


def kernel_version(common: Path) -> str:
    makefile = read(common / "Makefile")
    values: dict[str, str] = {}
    for key in ("VERSION", "PATCHLEVEL"):
        match = re.search(rf"(?m)^{key}\s*=\s*(\d+)\s*$", makefile)
        if not match:
            raise InstallError(f"cannot read {key} from {common / 'Makefile'}")
        values[key] = match.group(1)
    version = f"{values['VERSION']}.{values['PATCHLEVEL']}"
    if version not in SUPPORTED_KERNELS:
        raise InstallError(
            f"unsupported kernel line {version}; expected one of {', '.join(sorted(SUPPORTED_KERNELS))}"
        )
    return version


def ksu_candidates(root: Path, common: Path) -> list[Path]:
    preferred = [
        common / "drivers/kernelsu",
        root / "drivers/kernelsu",
        root / "KernelSU/kernel",
        root / "kernel",
    ]
    found: list[Path] = []
    seen: set[Path] = set()
    for candidate in preferred:
        if not (candidate / "Kbuild").is_file():
            continue
        if not (candidate / "policy/app_profile.c").is_file():
            continue
        if not (candidate / "selinux/sepolicy.c").is_file():
            continue
        resolved = candidate.resolve()
        if resolved not in seen:
            seen.add(resolved)
            found.append(candidate)
    return found


def detect_variant(ksu: Path) -> str:
    corpus = "\n".join(
        read(path)
        for path in (ksu / "Kbuild", ksu / "Kconfig", ksu / "policy/app_profile.c")
    )
    if "ReSukiSU" in corpus or "REPO_NAME := ReSukiSU" in corpus:
        return "resukisu"
    if "SukiSU" in corpus or "SUSFS" in corpus:
        return "sukisu"
    if "escape_with_root_profile" in corpus and "kernelsu-objs" in corpus:
        return "official"
    raise InstallError(f"unrecognized KernelSU source shape: {ksu}")


def discover(root: Path) -> Layout:
    common = kernel_common(root)
    if os.environ.get("ABK_BUILD_WORK_MODE", "").lower() == "lkm":
        raise InstallError("KernelSU LKM mode is unsupported; ABK KSU Sandbox requires built-in KSU")
    candidates = ksu_candidates(root, common)
    if len(candidates) != 1:
        rendered = ", ".join(str(path) for path in candidates) or "none"
        raise InstallError(f"expected exactly one built-in KernelSU source tree, found: {rendered}")
    return Layout(root, common, candidates[0], detect_variant(candidates[0]), kernel_version(common))


def append_once(path: Path, block: str) -> None:
    text = read(path)
    if MARKER in text:
        if block.strip() not in text:
            raise InstallError(f"conflicting or partial ABK Kbuild injection in {path}")
        return
    write(path, text.rstrip() + "\n" + block.lstrip("\n"))


def insert_before_last(path: Path, needle: str, block: str) -> None:
    text = read(path)
    if MARKER in text:
        if block.strip() not in text:
            raise InstallError(f"conflicting or partial ABK Kconfig injection in {path}")
        return
    index = text.rfind(needle)
    if index < 0:
        raise InstallError(f"injection anchor {needle!r} not found in {path}")
    write(path, text[:index] + block + "\n" + text[index:])


def add_include(text: str, include: str, path: Path) -> str:
    lines = text.splitlines(keepends=True)
    lines = [line for line in lines if line.strip() != include]
    include_pattern = re.compile(r"^[ \t]*#[ \t]*include\b")
    try:
        first = next(index for index, line in enumerate(lines) if include_pattern.match(line))
    except StopIteration:
        raise InstallError(f"include anchor not found in {path}")
    end = first + 1
    while end < len(lines) and include_pattern.match(lines[end]):
        end += 1
    newline = "\r\n" if lines[first].endswith("\r\n") else "\n"
    lines.insert(end, include + newline)
    return "".join(lines)


def patch_escape(ksu: Path) -> None:
    path = ksu / "policy/app_profile.c"
    text = read(path)
    if installed_or_fail(
        path,
        text,
        f"{MARKER}: escape",
        ('#include "abk_sandbox/abk_sandbox.h"', "abk_sandbox_try_escape(&handled)"),
    ):
        return
    text = add_include(text, '#include "abk_sandbox/abk_sandbox.h"', path)
    pattern = re.compile(r"(?m)^int escape_with_root_profile\(void\)\n\{")
    match = pattern.search(text)
    if not match:
        raise InstallError(f"escape_with_root_profile anchor not found in {path}")
    hook = f"""

#ifdef CONFIG_KSU_ABK_SANDBOX
    /* {MARKER}: escape */
    {{
        bool handled = false;
        int sandbox_ret = abk_sandbox_try_escape(&handled);

        if (handled)
            return sandbox_ret;
    }}
#endif"""
    text = text[: match.end()] + hook + text[match.end() :]
    write(path, text)


def patch_supercall_dispatch(ksu: Path) -> None:
    path = ksu / "supercall/dispatch.c"
    text = read(path)
    marker = f"{MARKER}: deny sandbox supercalls"
    if installed_or_fail(
        path,
        text,
        marker,
        ('#include "abk_sandbox/abk_sandbox.h"', "abk_sandbox_current(NULL, NULL)"),
    ):
        return

    text = add_include(text, '#include "abk_sandbox/abk_sandbox.h"', path)
    anchor = (
        "long ksu_supercall_handle_ioctl(unsigned int cmd, void __user *argp)\n"
        "{\n"
    )
    if anchor not in text:
        raise InstallError(f"KernelSU supercall dispatch anchor not found in {path}")
    hook = f"""{anchor}#ifdef CONFIG_KSU_ABK_SANDBOX
    /* {marker} */
    if (abk_sandbox_current(NULL, NULL))
        return -EPERM;
#endif
"""
    write(path, text.replace(anchor, hook, 1))


def patch_allowlist(ksu: Path) -> None:
    path = ksu / "policy/allowlist.c"
    text = read(path)
    if installed_or_fail(
        path,
        text,
        f"{MARKER}: revoke",
        (
            f"{MARKER}: prune",
            "abk_sandbox_revoke_uid_async(profile->curr_uid)",
            "abk_sandbox_revoke_uid_async(uid)",
        ),
    ):
        return
    if f"{MARKER}: prune" in text:
        raise InstallError(f"conflicting or partial ABK allowlist injection in {path}")
    text = add_include(text, '#include "abk_sandbox/abk_sandbox.h"', path)
    function = text.find("int ksu_set_app_profile(struct app_profile *profile)")
    if function < 0:
        raise InstallError(f"ksu_set_app_profile anchor not found in {path}")
    return_pos = text.find("    return result;", function)
    if return_pos < 0:
        raise InstallError(f"ksu_set_app_profile return anchor not found in {path}")
    hook = f"""#ifdef CONFIG_KSU_ABK_SANDBOX
    /* {MARKER}: revoke */
    if (!result && !profile->allow_su)
        abk_sandbox_revoke_uid_async(profile->curr_uid);
#endif
"""
    text = text[:return_pos] + hook + text[return_pos:]

    prune = text.find("void ksu_prune_allowlist(")
    prune_end = text.find("void __init ksu_allowlist_init", prune)
    if prune < 0 or prune_end < 0:
        raise InstallError(f"ksu_prune_allowlist anchor not found in {path}")
    removal = text.find("            hlist_del_rcu(&np->list);", prune, prune_end)
    if removal < 0:
        raise InstallError(f"allowlist prune removal anchor not found in {path}")
    prune_hook = f"""#ifdef CONFIG_KSU_ABK_SANDBOX
            /* {MARKER}: prune */
            abk_sandbox_revoke_uid_async(uid);
#endif
"""
    text = text[:removal] + prune_hook + text[removal:]
    write(path, text)


def patch_policy_lock_order(ksu: Path) -> None:
    path = ksu / "selinux/rules.c"
    text = read(path)
    marker = f"{MARKER}: policy snapshot under lock"
    if installed_or_fail(
        path,
        text,
        marker,
        (
            "struct selinux_policy *pol, *old_pol;",
            "old_pol = rcu_dereference_protected(selinux_state.policy,",
        ),
    ):
        return

    function = text.find("void apply_kernelsu_rules()")
    if function < 0:
        raise InstallError(f"apply_kernelsu_rules anchor not found in {path}")
    declaration = "struct selinux_policy *pol, *old_pol = selinux_state.policy;"
    declaration_pos = text.find(declaration, function)
    lock = "    mutex_lock(&selinux_state.policy_mutex);"
    lock_pos = text.find(lock, function)
    if declaration_pos < 0 or lock_pos < 0 or declaration_pos > lock_pos:
        raise InstallError(f"SELinux policy snapshot anchor not found in {path}")

    text = text[:declaration_pos] + "struct selinux_policy *pol, *old_pol;" + text[
        declaration_pos + len(declaration) :
    ]
    lock_pos = text.find(lock, function)
    assignment = f"""
    /* {marker} */
    old_pol = rcu_dereference_protected(selinux_state.policy,
                    lockdep_is_held(&selinux_state.policy_mutex));"""
    text = text[: lock_pos + len(lock)] + assignment + text[lock_pos + len(lock) :]
    write(path, text)


def patch_policy_reapply(ksu: Path) -> None:
    path = ksu / "selinux/rules.c"
    text = read(path)
    if installed_or_fail(
        path,
        text,
        f"{MARKER}: policy reapply",
        ('#include "abk_sandbox/abk_sandbox.h"', "abk_sandbox_policy_reapply(db)"),
    ):
        return
    text = add_include(text, '#include "abk_sandbox/abk_sandbox.h"', path)
    function = text.find("void apply_kernelsu_rules()")
    if function < 0:
        raise InstallError(f"apply_kernelsu_rules anchor not found in {path}")
    assignment = text.find("    db = &pol->policydb;", function)
    if assignment < 0:
        raise InstallError(f"policy database anchor not found in {path}")
    assignment_end = assignment + len("    db = &pol->policydb;")
    hook = f"""
#ifdef CONFIG_KSU_ABK_SANDBOX
    /* {MARKER}: policy reapply */
    if (abk_sandbox_policy_reapply(db)) {{
        ksu_destroy_sepolicy(pol);
        goto out_unlock;
    }}
#endif"""
    text = text[:assignment_end] + hook + text[assignment_end:]
    write(path, text)


def patch_sucompat_fail_closed(layout: Layout) -> None:
    if layout.variant not in {"official", "sukisu"}:
        return
    path = layout.ksu / "feature/sucompat.c"
    text = read(path)
    marker = f"{MARKER}: sucompat fail closed"
    if installed_or_fail(
        path,
        text,
        marker,
        ("ksu_close_fd(tmp_fd);", "return ret;"),
    ):
        return
    anchor = """    ret = escape_with_root_profile();
    if (ret) {
        pr_err("escape_with_root_profile failed: %ld\\n", ret);
    }"""
    if anchor not in text:
        raise InstallError(f"sucompat fail-closed anchor not found in {path}")
    replacement = f"""    ret = escape_with_root_profile();
    if (ret) {{
        /* {marker} */
        pr_err("escape_with_root_profile failed: %ld\\n", ret);
        ksu_sulog_emit_pending(pending_sucompat, ret, GFP_KERNEL);
        ksu_close_fd(tmp_fd);
        regs->__PT_PARM1_REG = orig_regs[0];
        regs->__PT_PARM2_REG = orig_regs[1];
        regs->__PT_PARM3_REG = orig_regs[2];
        regs->__PT_SYSCALL_PARM4_REG = orig_regs[3];
        regs->__PT_PARM5_REG = orig_regs[4];
        return ret;
    }}"""
    write(path, text.replace(anchor, replacement, 1))


def patch_resukisu_manual_fail_closed(layout: Layout) -> None:
    if layout.variant != "resukisu":
        return
    path = layout.ksu / "feature/sucompat.c"
    text = read(path)
    marker = f"{MARKER}: manual su fail closed"
    if installed_or_fail(path, text, marker, ("return sandbox_ret;",)):
        return
    anchor = "    escape_with_root_profile();"
    if anchor not in text:
        raise InstallError(f"ReSukiSU manual su anchor not found in {path}")
    hook = f"""    /* {marker} */
    {{
        int sandbox_ret = escape_with_root_profile();

        if (sandbox_ret)
            return sandbox_ret;
    }}"""
    write(path, text.replace(anchor, hook, 1))


def patch_common_header(common: Path, module_root: Path) -> None:
    source = module_root / "files/abk_ksu_sandbox/abk_ksu_sandbox_api.h"
    target = common / "include/linux/abk_ksu_sandbox.h"
    if target.exists() and MARKER not in read(target):
        raise InstallError(f"refusing to overwrite non-ABK header: {target}")
    write(target, read(source))


def patch_lsm_count(common: Path, version: str) -> None:
    if version != "6.12":
        return
    path = common / "include/linux/lsm_count.h"
    text = read(path)
    if installed_or_fail(
        path,
        text,
        f"{MARKER}: lsm count",
        ("#define ABK_KSU_SANDBOX_ENABLED", "ABK_KSU_SANDBOX_ENABLED\\"),
    ):
        return
    definition_anchor = "/*\n *  There is a trailing comma that we need to be accounted for."
    list_anchor = "\t\tIPE_ENABLED)"
    if definition_anchor not in text or list_anchor not in text:
        raise InstallError(f"LSM count anchor not found in {path}")
    definition = f"""/* {MARKER}: lsm count */
#if IS_ENABLED(CONFIG_KSU_ABK_SANDBOX)
#define ABK_KSU_SANDBOX_ENABLED 1,
#else
#define ABK_KSU_SANDBOX_ENABLED
#endif

"""
    text = text.replace(definition_anchor, definition + definition_anchor, 1)
    text = text.replace(
        list_anchor,
        "\t\tABK_KSU_SANDBOX_ENABLED\\\n" + list_anchor,
        1,
    )
    write(path, text)


def patch_kernel_hooks(common: Path) -> None:
    seccomp = common / "kernel/seccomp.c"
    text = read(seccomp)
    normalized = add_include(text, "#include <linux/abk_ksu_sandbox.h>", seccomp)
    if normalized != text:
        write(seccomp, normalized)
        text = normalized
    if not installed_or_fail(
        seccomp,
        text,
        f"{MARKER}: seccomp entry",
        ("abk_ksu_sandbox_seccomp_allow_syscall(this_syscall)",),
    ):
        hook = (
            f"\n\t/* {MARKER}: seccomp entry */\n"
            "\tif (abk_ksu_sandbox_seccomp_allow_syscall(this_syscall))\n"
            "\t\treturn 0;\n"
        )
        pattern = re.compile(
            r"(?m)^(\s*this_syscall = sd \? sd->nr :\n"
            r"\s*syscall_get_nr\(current, current_pt_regs\(\)\);)$"
        )
        text, count = pattern.subn(lambda match: match.group(1) + hook, text, count=1)
        if count != 1:
            raise InstallError(f"__secure_computing entry anchor not found in {seccomp}")
        write(seccomp, text)

    namespace = common / "fs/namespace.c"
    text = read(namespace)
    normalized = add_include(text, "#include <linux/abk_ksu_sandbox.h>", namespace)
    if normalized != text:
        write(namespace, normalized)
        text = normalized
    if not installed_or_fail(
        namespace,
        text,
        f"{MARKER}: legacy mount privilege",
        ("abk_ksu_sandbox_may_mount()",),
    ):
        function = text.find("int path_mount(")
        anchor = "\tif (!may_mount())\n\t\treturn -EPERM;"
        anchor_pos = text.find(anchor, function)
        if function < 0 or anchor_pos < 0:
            raise InstallError(f"path_mount privilege anchor not found in {namespace}")
        code = (
            f"\t/* {MARKER}: legacy mount privilege */\n"
            "\tif (!may_mount() && !abk_ksu_sandbox_may_mount())\n"
            "\t\treturn -EPERM;"
        )
        text = text[:anchor_pos] + code + text[anchor_pos + len(anchor) :]
        write(namespace, text)

    text = read(namespace)
    old_bind_validation = "abk_ksu_sandbox_bind_validate(&old_path, path)"
    new_bind_validation = (
        "abk_ksu_sandbox_bind_validate(&old_path, path, recurse)"
    )
    if f"{MARKER}: resolved bind source" in text and old_bind_validation in text:
        text = text.replace(old_bind_validation, new_bind_validation, 1)
        write(namespace, text)
    if not installed_or_fail(
        namespace,
        text,
        f"{MARKER}: resolved bind source",
        (new_bind_validation,),
    ):
        function = text.find("static int do_loopback(")
        pattern = re.compile(
            r"(\terr = kern_path\(old_name, LOOKUP_FOLLOW\|LOOKUP_AUTOMOUNT, &old_path\);\n"
            r"\tif \(err\)\n\t\treturn err;)"
        )
        match = pattern.search(text, function)
        if function < 0 or not match:
            raise InstallError(f"do_loopback resolved-source anchor not found in {namespace}")
        hook = (
            match.group(1)
            + f"\n\n\t/* {MARKER}: resolved bind source */"
            + "\n\terr = abk_ksu_sandbox_bind_validate(&old_path, path, recurse);"
            + "\n\tif (err)"
            + "\n\t\tgoto out;"
        )
        text = text[: match.start()] + hook + text[match.end() :]
        write(namespace, text)

    text = read(namespace)
    if not installed_or_fail(
        namespace,
        text,
        f"{MARKER}: legacy umount privilege",
        ("!abk_ksu_sandbox_may_mount()",),
    ):
        function = text.find("static int can_umount(")
        anchor = "\tif (!may_mount())\n\t\treturn -EPERM;"
        anchor_pos = text.find(anchor, function)
        if function < 0 or anchor_pos < 0:
            raise InstallError(f"can_umount privilege anchor not found in {namespace}")
        code = (
            f"\t/* {MARKER}: legacy umount privilege */\n"
            "\tif (!may_mount() && !abk_ksu_sandbox_may_mount())\n"
            "\t\treturn -EPERM;"
        )
        text = text[:anchor_pos] + code + text[anchor_pos + len(anchor) :]
        write(namespace, text)

    text = read(namespace)
    if not installed_or_fail(
        namespace,
        text,
        f"{MARKER}: mount result",
        ("abk_ksu_sandbox_mount_result(path, ret)",),
    ):
        security_anchor = (
            "\tret = security_sb_mount(dev_name, path, type_page, flags, data_page);\n"
            "\tif (ret)\n"
            "\t\treturn ret;"
        )
        if security_anchor not in text:
            raise InstallError(f"path_mount security anchor not found in {namespace}")
        security_hook = (
            "\tret = security_sb_mount(dev_name, path, type_page, flags, data_page);\n"
            "\tif (ret) {\n"
            f"\t\t/* {MARKER}: mount result */\n"
            "\t\tabk_ksu_sandbox_mount_result(path, ret);\n"
            "\t\treturn ret;\n"
            "\t}"
        )
        text = text.replace(security_anchor, security_hook, 1)

        bind_anchor = (
            "\tif (flags & MS_BIND)\n"
            "\t\treturn do_loopback(path, dev_name, flags & MS_REC);"
        )
        if bind_anchor not in text:
            raise InstallError(f"path_mount bind anchor not found in {namespace}")
        bind_hook = (
            "\tif (flags & MS_BIND) {\n"
            "\t\tret = do_loopback(path, dev_name, flags & MS_REC);\n"
            "\t\tabk_ksu_sandbox_mount_result(path, ret);\n"
            "\t\treturn ret;\n"
            "\t}"
        )
        text = text.replace(bind_anchor, bind_hook, 1)

        new_mount_pattern = re.compile(
            r"(?m)^\treturn do_new_mount\(path, type_page, sb_flags, mnt_flags, dev_name,\n"
            r"\s+data_page\);$"
        )
        new_mount_hook = (
            "\tret = do_new_mount(path, type_page, sb_flags, mnt_flags, dev_name,\n"
            "\t\t\t   data_page);\n"
            "\tabk_ksu_sandbox_mount_result(path, ret);\n"
            "\treturn ret;"
        )
        text, count = new_mount_pattern.subn(new_mount_hook, text, count=1)
        if count != 1:
            raise InstallError(f"path_mount new-mount anchor not found in {namespace}")
        write(namespace, text)

    text = read(namespace)
    if not installed_or_fail(
        namespace,
        text,
        f"{MARKER}: umount validate",
        (
            "abk_ksu_sandbox_umount_validate(path, flags)",
            "abk_ksu_sandbox_umount_result(path, ret)",
        ),
    ):
        umount_anchor = (
            "\tret = can_umount(path, flags);\n"
            "\tif (!ret)\n"
            "\t\tret = do_umount(mnt, flags);"
        )
        if umount_anchor not in text:
            raise InstallError(f"path_umount anchor not found in {namespace}")
        umount_hook = (
            f"\t/* {MARKER}: umount validate */\n"
            "\tret = abk_ksu_sandbox_umount_validate(path, flags);\n"
            "\tif (!ret)\n"
            "\t\tret = can_umount(path, flags);\n"
            "\tif (!ret)\n"
            "\t\tret = do_umount(mnt, flags);\n"
            "\tabk_ksu_sandbox_umount_result(path, ret);"
        )
        text = text.replace(umount_anchor, umount_hook, 1)
        write(namespace, text)

    ptrace = common / "kernel/ptrace.c"
    text = read(ptrace)
    normalized = add_include(text, "#include <linux/abk_ksu_sandbox.h>", ptrace)
    if normalized != text:
        write(ptrace, normalized)
        text = normalized
    if not installed_or_fail(
        ptrace,
        text,
        f"{MARKER}: ptrace",
        (
            "abk_ksu_sandbox_may_ptrace(tcred)",
            "abk_ksu_sandbox_may_ptrace_task(task)",
        ),
    ):
        anchor = "\ttcred = __task_cred(task);"
        if anchor not in text:
            raise InstallError(f"ptrace target credential anchor not found in {ptrace}")
        code = (
            anchor
            + f"\n\t/* {MARKER}: ptrace */"
            + "\n\tif (abk_ksu_sandbox_may_ptrace(tcred))"
            + "\n\t\tgoto ok;"
        )
        text = text.replace(anchor, code, 1)
        dumpable = (
            "\tif (mm &&\n"
            "\t    ((get_dumpable(mm) != SUID_DUMP_USER) &&\n"
            "\t     !ptrace_has_cap(mm->user_ns, mode)))"
        )
        if dumpable not in text:
            raise InstallError(f"ptrace dumpability anchor not found in {ptrace}")
        dumpable_hook = (
            "\tif (mm &&\n"
            "\t    ((get_dumpable(mm) != SUID_DUMP_USER) &&\n"
            "\t     !abk_ksu_sandbox_may_ptrace_task(task) &&\n"
            "\t     !ptrace_has_cap(mm->user_ns, mode)))"
        )
        text = text.replace(dumpable, dumpable_hook, 1)
        write(ptrace, text)

    signal = common / "kernel/signal.c"
    text = read(signal)
    normalized = add_include(text, "#include <linux/abk_ksu_sandbox.h>", signal)
    if normalized != text:
        write(signal, normalized)
        text = normalized
    if not installed_or_fail(
        signal,
        text,
        f"{MARKER}: signal",
        ("abk_ksu_sandbox_may_signal(t)",),
    ):
        pattern = re.compile(
            r"if \(!same_thread_group\(current, t\) &&\n"
            r"\s*!kill_ok_by_cred\(t\)\) \{"
        )
        replacement = (
            "if (!same_thread_group(current, t) &&\n"
            f"\t    /* {MARKER}: signal */\n"
            "\t    !abk_ksu_sandbox_may_signal(t) &&\n"
            "\t    !kill_ok_by_cred(t)) {"
        )
        text, count = pattern.subn(replacement, text, count=1)
        if count != 1:
            raise InstallError(f"check_kill_permission credential anchor not found in {signal}")
        write(signal, text)


KBUILD_ARTIFACT_PATTERNS = tuple(
    re.compile(pattern)
    for pattern in (
        r"(?:core|policy|namespace|lsm)\.o",
        r"\.(?:core|policy|namespace|lsm)\.o\.(?:cmd|d)",
        r"(?:core|policy|namespace|lsm)\.(?:ko|mod|mod\.c|mod\.o)",
        r"\.(?:core|policy|namespace|lsm)\.(?:ko|mod|mod\.o)\.cmd",
        r"built-in\.a",
        r"\.built-in\.a\.cmd",
        r"modules\.order",
        r"\.modules\.order\.cmd",
        r"Module\.symvers",
    )
)

LEGACY_SOURCE_NAMES = {"abk_ksu_sandbox_api.h"}


def trusted_kbuild_artifact(path: Path) -> bool:
    return any(pattern.fullmatch(path.name) for pattern in KBUILD_ARTIFACT_PATTERNS)


def copy_sources(ksu: Path, module_root: Path) -> None:
    source = module_root / "files/abk_ksu_sandbox"
    target = ksu / "abk_sandbox"
    if not source.is_dir():
        raise InstallError(f"module source directory missing: {source}")
    if target.is_symlink() or (target.exists() and not target.is_dir()):
        raise InstallError(f"refusing conflicting sandbox source target: {target}")
    source_files = {
        item.name: item
        for item in source.iterdir()
        if item.name != "abk_ksu_sandbox_api.h" and item.is_file()
    }
    owned_names = set(source_files)
    build_artifacts: list[Path] = []
    legacy_sources: list[Path] = []
    if target.is_dir():
        for existing in target.iterdir():
            if existing.is_symlink():
                raise InstallError(f"refusing symlink in sandbox source target: {existing}")
            if existing.is_dir():
                raise InstallError(f"refusing unexpected directory in sandbox source target: {existing}")
            if not existing.is_file():
                raise InstallError(f"refusing unexpected entry in sandbox source target: {existing}")
            if existing.name in owned_names:
                if MARKER in read(existing):
                    continue
                raise InstallError(f"refusing non-ABK file in sandbox source target: {existing}")
            if existing.name in LEGACY_SOURCE_NAMES:
                if MARKER not in read(existing):
                    raise InstallError(f"refusing non-ABK legacy file in sandbox source target: {existing}")
                legacy_sources.append(existing)
                continue
            if not trusted_kbuild_artifact(existing):
                raise InstallError(f"refusing unexpected file in sandbox source target: {existing}")
            build_artifacts.append(existing)

    source_texts = {name: read(path) for name, path in source_files.items()}
    sources_changed = any(
        not (target / name).is_file()
        or read(target / name) != source_text
        for name, source_text in source_texts.items()
    )
    if sources_changed:
        for artifact in build_artifacts:
            remove_file(artifact)
    for legacy_source in legacy_sources:
        remove_file(legacy_source, "legacy source")
    if _ACTIVE_TRANSACTION is not None:
        _ACTIVE_TRANSACTION.record_directory(target)
    target.mkdir(parents=True, exist_ok=True)
    for name, item in source_files.items():
        source_text = source_texts[name]
        if MARKER not in source_text:
            raise InstallError(f"module source is missing ownership marker: {item}")
        destination = target / item.name
        # Do not preserve the template checkout's mtime.  If content changes,
        # Kbuild must observe a fresh source timestamp and rebuild stale objects.
        write(destination, source_text)
    print(f"ABK KSU Sandbox: synchronized sources to {target}")


def validate_defconfig(defconfig: Path, *, require_sandbox: bool) -> None:
    config = read(defconfig)
    if re.search(r"(?m)^CONFIG_KSU=m$", config):
        raise InstallError("CONFIG_KSU=m is unsupported; built-in CONFIG_KSU=y is required")
    for symbol, message in (
        ("CONFIG_KSU", "built-in CONFIG_KSU=y is required"),
        ("CONFIG_SECURITY_SELINUX", "CONFIG_SECURITY_SELINUX=y is required"),
        ("CONFIG_NAMESPACES", "CONFIG_NAMESPACES=y is required"),
    ):
        if not re.search(rf"(?m)^{symbol}=y$", config):
            raise InstallError(message)
    if require_sandbox and not re.search(
        r"(?m)^CONFIG_KSU_ABK_SANDBOX=y$", config
    ):
        raise InstallError("CONFIG_KSU_ABK_SANDBOX=y is missing from defconfig")
    if require_sandbox:
        lsm_lines = re.findall(r"(?m)^CONFIG_LSM=.*$", config)
        if len(lsm_lines) != 1:
            raise InstallError(
                "defconfig must contain exactly one quoted CONFIG_LSM assignment"
            )
        match = re.fullmatch(r'CONFIG_LSM="([A-Za-z0-9_,.-]+)"', lsm_lines[0])
        if not match:
            raise InstallError("CONFIG_LSM must be a quoted comma-separated list")
        lsms = match.group(1).split(",")
        if any(not lsm for lsm in lsms):
            raise InstallError("CONFIG_LSM must not contain empty entries")
        if len(set(lsms)) != len(lsms):
            raise InstallError("CONFIG_LSM must not contain duplicate entries")
        if "selinux" not in lsms:
            raise InstallError("CONFIG_LSM must include selinux")
        if lsms.count("abk_ksu_sandbox") != 1:
            raise InstallError("CONFIG_LSM must include abk_ksu_sandbox exactly once")
        if lsms[-1] != "abk_ksu_sandbox":
            raise InstallError("abk_ksu_sandbox must be the last CONFIG_LSM entry")


def install(layout: Layout, module_root: Path, defconfig: Path | None) -> None:
    if defconfig:
        validate_defconfig(defconfig, require_sandbox=False)
    with InstallTransaction():
        copy_sources(layout.ksu, module_root)
        append_once(layout.ksu / "Kbuild", KBUILD_BLOCK)
        insert_before_last(layout.ksu / "Kconfig", "endmenu", KCONFIG_BLOCK)
        patch_escape(layout.ksu)
        patch_supercall_dispatch(layout.ksu)
        patch_allowlist(layout.ksu)
        patch_policy_lock_order(layout.ksu)
        patch_policy_reapply(layout.ksu)
        patch_sucompat_fail_closed(layout)
        patch_resukisu_manual_fail_closed(layout)
        patch_common_header(layout.common, module_root)
        patch_lsm_count(layout.common, layout.version)
        patch_kernel_hooks(layout.common)
    print(
        f"ABK KSU Sandbox: installed variant={layout.variant} kernel={layout.version} ksu={layout.ksu}"
    )


def verify(layout: Layout, module_root: Path, defconfig: Path | None) -> None:
    checks = {
        layout.ksu / "Kbuild": [
            MARKER,
            "requires CONFIG_KSU_ABK_SANDBOX=y",
            "abk_sandbox/core.o",
            "abk_sandbox/policy.o",
            "abk_sandbox/namespace.o",
            "abk_sandbox/lsm.o",
        ],
        layout.ksu / "Kconfig": [
            MARKER,
            "config KSU_ABK_SANDBOX",
            "depends on KSU=y && SECURITY_SELINUX && NAMESPACES",
        ],
        layout.ksu / "policy/app_profile.c": [
            f"{MARKER}: escape",
            "abk_sandbox_try_escape(&handled)",
            "if (handled)",
            "return sandbox_ret;",
        ],
        layout.ksu / "supercall/dispatch.c": [
            f"{MARKER}: deny sandbox supercalls",
            '#include "abk_sandbox/abk_sandbox.h"',
            "abk_sandbox_current(NULL, NULL)",
            "return -EPERM;",
        ],
        layout.ksu / "policy/allowlist.c": [
            f"{MARKER}: revoke",
            f"{MARKER}: prune",
            "abk_sandbox_revoke_uid_async(profile->curr_uid)",
            "abk_sandbox_revoke_uid_async(uid)",
        ],
        layout.ksu / "selinux/rules.c": [
            f"{MARKER}: policy snapshot under lock",
            "old_pol = rcu_dereference_protected(selinux_state.policy,",
            f"{MARKER}: policy reapply",
            "abk_sandbox_policy_reapply(db)",
        ],
        layout.common / "kernel/seccomp.c": [
            f"{MARKER}: seccomp entry",
            "abk_ksu_sandbox_seccomp_allow_syscall(this_syscall)",
        ],
        layout.common / "fs/namespace.c": [
            f"{MARKER}: legacy mount privilege",
            "!may_mount() && !abk_ksu_sandbox_may_mount()",
            f"{MARKER}: resolved bind source",
            "abk_ksu_sandbox_bind_validate(&old_path, path, recurse)",
            f"{MARKER}: legacy umount privilege",
            f"{MARKER}: mount result",
            "abk_ksu_sandbox_mount_result(path, ret)",
            f"{MARKER}: umount validate",
            "abk_ksu_sandbox_umount_validate(path, flags)",
            "abk_ksu_sandbox_umount_result(path, ret)",
        ],
        layout.common / "kernel/ptrace.c": [
            f"{MARKER}: ptrace",
            "abk_ksu_sandbox_may_ptrace(tcred)",
            "abk_ksu_sandbox_may_ptrace_task(task)",
        ],
        layout.common / "kernel/signal.c": [
            f"{MARKER}: signal",
            "abk_ksu_sandbox_may_signal(t)",
        ],
        layout.common / "include/linux/abk_ksu_sandbox.h": [MARKER],
    }
    for path, needles in checks.items():
        text = read(path)
        for needle in needles:
            if needle not in text:
                raise InstallError(f"incomplete sandbox injection: {needle!r} missing from {path}")

    common_include = "#include <linux/abk_ksu_sandbox.h>"
    for relative, marker in (
        ("kernel/seccomp.c", f"{MARKER}: seccomp entry"),
        ("fs/namespace.c", f"{MARKER}: legacy mount privilege"),
        ("kernel/ptrace.c", f"{MARKER}: ptrace"),
        ("kernel/signal.c", f"{MARKER}: signal"),
    ):
        path = layout.common / relative
        text = read(path)
        if common_include not in text or text.index(common_include) > text.index(marker):
            raise InstallError(f"ABK public header is missing or appears after its hook in {path}")
    if layout.version == "6.12":
        text = read(layout.common / "include/linux/lsm_count.h")
        if f"{MARKER}: lsm count" not in text:
            raise InstallError("ABK LSM slot is missing from include/linux/lsm_count.h")
    if layout.variant == "resukisu":
        text = read(layout.ksu / "feature/sucompat.c")
        if (
            f"{MARKER}: manual su fail closed" not in text
            or "return sandbox_ret;" not in text
        ):
            raise InstallError("ReSukiSU manual su path is not fail closed")
    else:
        text = read(layout.ksu / "feature/sucompat.c")
        if (
            f"{MARKER}: sucompat fail closed" not in text
            or "ksu_close_fd(tmp_fd);" not in text
            or "return ret;" not in text
        ):
            raise InstallError("KernelSU sucompat path is not fail closed")
    source_dir = module_root / "files/abk_ksu_sandbox"
    for source in ("Makefile", "core.c", "policy.c", "namespace.c", "lsm.c", "abk_sandbox.h"):
        installed = layout.ksu / "abk_sandbox" / source
        if read(installed) != read(source_dir / source):
            raise InstallError(f"installed source differs from module template: {installed}")
    header = layout.common / "include/linux/abk_ksu_sandbox.h"
    if read(header) != read(source_dir / "abk_ksu_sandbox_api.h"):
        raise InstallError(f"installed public header differs from module template: {header}")
    if defconfig:
        validate_defconfig(defconfig, require_sandbox=True)
    print(
        f"ABK KSU Sandbox: verified variant={layout.variant} kernel={layout.version} ksu={layout.ksu}"
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("install", "verify", "detect"))
    parser.add_argument("--kernel-root", required=True, type=Path)
    parser.add_argument("--module-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--defconfig", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        layout = discover(args.kernel_root.resolve())
        if args.command == "detect":
            print(f"variant={layout.variant} kernel={layout.version} ksu={layout.ksu}")
        elif args.command == "install":
            install(layout, args.module_root.resolve(), args.defconfig)
        else:
            verify(layout, args.module_root.resolve(), args.defconfig)
        return 0
    except InstallError as exc:
        print(f"ABK KSU Sandbox: error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
