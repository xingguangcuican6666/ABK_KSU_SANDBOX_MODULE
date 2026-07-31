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
KBUILD_BLOCK_LEGACY = f"""

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


RUNTIME_KSU_TAIL_NEVER = "never"
RUNTIME_KSU_TAIL_RESUKISU_SUSFS = "resukisu-susfs"


def render_kbuild_block(tail_flags: str) -> str:
    return f"""

# {MARKER}
ifneq ($(CONFIG_KSU_ABK_SANDBOX),y)
$(error ABK KSU Sandbox requires CONFIG_KSU_ABK_SANDBOX=y; run both ABK stages)
endif
{tail_flags}
kernelsu-objs += abk_sandbox/core.o
kernelsu-objs += abk_sandbox/policy.o
kernelsu-objs += abk_sandbox/namespace.o
kernelsu-objs += abk_sandbox/lsm.o
"""


def kbuild_block(runtime_ksu_tail_policy: str) -> str:
    if runtime_ksu_tail_policy == RUNTIME_KSU_TAIL_NEVER:
        tail_flags = (
            "subdir-ccflags-y += "
            "-DABK_KSU_RUNTIME_TAIL_SOURCE_VERIFIED=0"
        )
    elif runtime_ksu_tail_policy == RUNTIME_KSU_TAIL_RESUKISU_SUSFS:
        tail_flags = """ifeq ($(CONFIG_KSU_MANUAL_HOOK),y)
$(error ABK KSU Sandbox does not support ReSukiSU manual hook mode)
endif
ifeq ($(CONFIG_KSU_MANUAL_HOOK_AUTO_SETUID_HOOK),y)
$(error ABK KSU Sandbox does not support ReSukiSU manual setuid LSM hooks)
endif
ifeq ($(CONFIG_KSU_MANUAL_HOOK_AUTO_INITRC_HOOK),y)
$(error ABK KSU Sandbox does not support ReSukiSU manual initrc LSM hooks)
endif
subdir-ccflags-y += -DABK_KSU_RUNTIME_TAIL_SOURCE_VERIFIED=1"""
    else:
        raise InstallError(
            f"unknown runtime KSU LSM-tail policy: {runtime_ksu_tail_policy}"
        )
    return render_kbuild_block(tail_flags)


def intermediate_kbuild_blocks() -> tuple[str, str]:
    never = render_kbuild_block(
        "CFLAGS_abk_sandbox/lsm.o += -DABK_KSU_ALLOW_RUNTIME_KSU_TAIL=0"
    )
    resukisu = render_kbuild_block(
        """ifeq ($(CONFIG_KSU_MANUAL_HOOK),y)
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
endif"""
    )
    return never, resukisu


def owned_kbuild_blocks() -> tuple[str, ...]:
    blocks = (
        KBUILD_BLOCK_LEGACY.strip(),
        kbuild_block(RUNTIME_KSU_TAIL_NEVER).strip(),
        kbuild_block(RUNTIME_KSU_TAIL_RESUKISU_SUSFS).strip(),
        *(block.strip() for block in intermediate_kbuild_blocks()),
    )
    return tuple(dict.fromkeys(blocks))


def installed_kbuild_block(path: Path, text: str) -> str:
    validate_kbuild_directives(path, text)
    marker_count = text.count(MARKER)
    if marker_count == 0:
        raise InstallError(f"incomplete sandbox injection: ABK Kbuild block missing in {path}")
    if marker_count != 1:
        raise InstallError(f"conflicting or partial ABK Kbuild injection in {path}")
    occurrences = [
        candidate
        for candidate in owned_kbuild_blocks()
        for _ in range(text.count(candidate))
    ]
    if len(occurrences) != 1:
        raise InstallError(f"conflicting or partial ABK Kbuild injection in {path}")
    installed = occurrences[0]
    start = text.index(installed)
    make_conditional_depth(path, text, start)
    if text[start + len(installed) :].strip():
        raise InstallError(f"conflicting or partial ABK Kbuild injection in {path}")
    for token in (
        "ABK_KSU_RUNTIME_TAIL_SOURCE_VERIFIED",
        "ABK_KSU_ALLOW_RUNTIME_KSU_TAIL",
    ):
        if text.count(token) != installed.count(token):
            raise InstallError(f"conflicting or partial ABK Kbuild injection in {path}")
    return installed


def validate_kbuild_directives(path: Path, text: str) -> None:
    overrides = re.findall(r"(?m)^[ \t]*override(?:[ \t]|$).*$", text)
    if overrides:
        raise InstallError(f"unsupported override directive in {path}")


def make_conditional_depth(path: Path, text: str, boundary: int) -> int:
    depth = 0
    for line in text[:boundary].splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if re.match(r"^(?:ifeq|ifneq|ifdef|ifndef)\b", stripped):
            depth += 1
        elif re.match(r"^endif\b", stripped):
            depth -= 1
            if depth < 0:
                raise InstallError(f"unbalanced Make conditional in {path}")
    if depth:
        raise InstallError(f"ABK Kbuild block is nested in a conditional in {path}")
    return depth


def kconfig_condition_depth(path: Path, text: str, boundary: int) -> int:
    depth = 0
    for line in text[:boundary].splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if re.match(r"^if(?:\s|$)", stripped):
            depth += 1
        elif re.match(r"^endif(?:\s|$)", stripped):
            depth -= 1
            if depth < 0:
                raise InstallError(f"unbalanced Kconfig conditional in {path}")
    if depth:
        raise InstallError(f"ABK Kconfig block is nested in a conditional in {path}")
    return depth


def installed_kconfig_block(path: Path, text: str) -> str:
    desired = KCONFIG_BLOCK.strip()
    definitions = re.findall(
        r"(?m)^[ \t]*(?:menuconfig|config)[ \t]+KSU_ABK_SANDBOX\b", text
    )
    if text.count(MARKER) != 1 or len(definitions) != 1 or text.count(desired) != 1:
        raise InstallError(f"conflicting or partial ABK Kconfig injection in {path}")
    start = text.index(desired)
    kconfig_condition_depth(path, text, start)
    suffix = text[start + len(desired) :]
    if not re.match(r"^[ \t\r\n]*endmenu(?:\s|$)", suffix):
        raise InstallError(f"conflicting or partial ABK Kconfig injection in {path}")
    return desired


_ACTIVE_TRANSACTION: InstallTransaction | None = None
_VALIDATION_ONLY = False


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
    if _VALIDATION_ONLY:
        raise InstallError(f"incomplete sandbox injection: validation would update {path}")
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


_C_LEXEME_PATTERN = re.compile(
    r"\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|//[^\n]*|/\*.*?\*/",
    flags=re.DOTALL,
)


def masked_lexeme(match: re.Match[str]) -> str:
    return "".join("\n" if character == "\n" else " " for character in match.group())


def mask_c_comments(text: str) -> str:
    def mask(match: re.Match[str]) -> str:
        token = match.group()
        if token.startswith("//") or token.startswith("/*"):
            return masked_lexeme(match)
        return token

    return _C_LEXEME_PATTERN.sub(mask, text)


def mask_c_comments_and_literals(text: str) -> str:
    return _C_LEXEME_PATTERN.sub(masked_lexeme, text)


def preprocessor_integer_truth(expression: str) -> bool | None:
    candidate = expression.strip()
    while candidate.startswith("(") and candidate.endswith(")"):
        depth = 0
        wraps_entire_expression = True
        for index, character in enumerate(candidate):
            if character == "(":
                depth += 1
            elif character == ")":
                depth -= 1
                if depth == 0 and index != len(candidate) - 1:
                    wraps_entire_expression = False
                    break
            if depth < 0:
                return None
        if depth or not wraps_entire_expression:
            break
        candidate = candidate[1:-1].strip()
    if candidate.startswith("!"):
        nested = preprocessor_integer_truth(candidate[1:])
        return None if nested is None else not nested
    match = re.fullmatch(
        r"([+-]?)(0[xX][0-9A-Fa-f]+|0[bB][01]+|0[0-7]*|[1-9][0-9]*)"
        r"[uUlL]*",
        candidate,
    )
    if not match:
        return None
    sign, literal = match.groups()
    if literal.lower().startswith("0x"):
        value = int(literal[2:], 16)
    elif literal.lower().startswith("0b"):
        value = int(literal[2:], 2)
    elif len(literal) > 1 and literal.startswith("0"):
        value = int(literal, 8)
    else:
        value = int(literal, 10)
    if sign == "-":
        value = -value
    return value != 0


def mask_c_definitely_inactive(text: str) -> str:
    lexical = mask_c_comments_and_literals(text)
    stack: list[tuple[bool, bool]] = []
    possible = True
    output: list[str] = []
    directive_pattern = re.compile(
        r"^[ \t]*#[ \t]*(if|ifdef|ifndef|elif|else|endif)\b(.*)$"
    )
    for raw_line, lexical_line in zip(
        text.splitlines(keepends=True), lexical.splitlines(keepends=True)
    ):
        match = directive_pattern.match(lexical_line)
        line_possible = possible
        if match:
            directive, expression = match.groups()
            expression = expression.strip()
            if directive in {"if", "ifdef", "ifndef"}:
                parent_possible = possible
                truth = (
                    preprocessor_integer_truth(expression)
                    if directive == "if"
                    else None
                )
                definitely_taken = truth is True
                branch_possible = truth is not False
                stack.append((parent_possible, definitely_taken))
                possible = parent_possible and branch_possible
            elif directive == "elif":
                if not stack:
                    raise InstallError("unmatched #elif in C source")
                parent_possible, definitely_taken = stack[-1]
                truth = preprocessor_integer_truth(expression)
                branch_possible = not definitely_taken and truth is not False
                if not definitely_taken and truth is True:
                    stack[-1] = (parent_possible, True)
                possible = parent_possible and branch_possible
            elif directive == "else":
                if not stack:
                    raise InstallError("unmatched #else in C source")
                parent_possible, definitely_taken = stack[-1]
                possible = parent_possible and not definitely_taken
                stack[-1] = (parent_possible, True)
            else:
                if not stack:
                    raise InstallError("unmatched #endif in C source")
                parent_possible, _ = stack.pop()
                possible = parent_possible
            line_possible = possible or directive == "endif"
        output.append(
            raw_line
            if line_possible
            else "".join("\n" if character == "\n" else " " for character in raw_line)
        )
    if stack:
        raise InstallError("unterminated preprocessor conditional in C source")
    return "".join(output)


def mask_c_live_code(text: str, *, literals: bool = True) -> str:
    active = mask_c_definitely_inactive(text)
    return (
        mask_c_comments_and_literals(active)
        if literals
        else mask_c_comments(active)
    )


def collapse_c_line_continuations(text: str) -> str:
    pattern = re.compile(r"\\(?:\r\n|\n|\r)")
    collapsed = text
    while pattern.search(collapsed):
        collapsed = pattern.sub("", collapsed)
    return collapsed


def mask_c_injection_context(text: str, marker: str) -> str:
    active = mask_c_definitely_inactive(text)

    def mask(match: re.Match[str]) -> str:
        token = match.group()
        if token.startswith("//") or token.startswith("/*"):
            stripped = token.strip()
            if stripped in {f"/* {marker} */", f"// {marker}"}:
                return token
            return masked_lexeme(match)
        return token

    return _C_LEXEME_PATTERN.sub(mask, active)


def c_scope_bounds(path: Path, text: str, anchor: str) -> tuple[int, int]:
    masked = mask_c_live_code(text)
    occurrences: list[int] = []
    cursor = 0
    while True:
        occurrence = masked.find(anchor, cursor)
        if occurrence < 0:
            break
        occurrences.append(occurrence)
        cursor = occurrence + len(anchor)
    if not occurrences:
        raise InstallError(f"C scope anchor {anchor!r} not found in {path}")

    stack: list[int] = []
    pairs: list[tuple[int, int]] = []
    for index, character in enumerate(masked):
        if character == "{":
            stack.append(index)
        elif character == "}" and stack:
            pairs.append((stack.pop(), index))
    if stack:
        raise InstallError(f"unbalanced C scope while locating {anchor!r} in {path}")

    candidates: set[tuple[int, int]] = set()
    pairs_by_start = {start: (start, end) for start, end in pairs}
    for occurrence in occurrences:
        containing = [
            pair for pair in pairs if pair[0] < occurrence < pair[1]
        ]
        if containing:
            candidates.add(min(containing, key=lambda pair: pair[0]))
            continue

        anchor_end = occurrence + len(anchor)
        body_brace = masked.find("{", occurrence, anchor_end)
        if body_brace < 0:
            body_brace = masked.find("{", anchor_end)
            semicolon = masked.find(";", anchor_end)
            if body_brace < 0 or (semicolon >= 0 and semicolon < body_brace):
                continue
        if body_brace in pairs_by_start:
            candidates.add(pairs_by_start[body_brace])

    if len(candidates) != 1:
        raise InstallError(f"C function scope for {anchor!r} not found in {path}")
    return next(iter(candidates))


def c_scope_containing(path: Path, text: str, anchor: str) -> str:
    start, end = c_scope_bounds(path, text, anchor)
    return text[start : end + 1]


def exact_injection_installed(
    path: Path,
    text: str,
    marker: str,
    contexts: tuple[str, ...],
    *,
    scope: str | None = None,
    forbidden: tuple[str, ...] = (),
    global_counts: tuple[tuple[str, int], ...] = (),
    live_scope_counts: tuple[tuple[str, int], ...] = (),
    live_global_counts: tuple[tuple[str, int], ...] = (),
    code_global_counts: tuple[tuple[str, int], ...] = (),
) -> bool:
    context_global = mask_c_injection_context(text, marker)
    if marker not in context_global:
        if marker in text:
            raise InstallError(f"conflicting or partial ABK injection in {path}: {marker}")
        return False
    inspected = text if scope is None else scope
    context_scope = mask_c_injection_context(inspected, marker)
    invalid = context_global.count(marker) != 1 or context_scope.count(marker) != 1
    invalid = invalid or any(context_scope.count(context) != 1 for context in contexts)
    live_scope = mask_c_live_code(inspected)
    live_global = mask_c_live_code(text)
    code_scope = mask_c_live_code(inspected, literals=False)
    invalid = invalid or any(forbidden_text in code_scope for forbidden_text in forbidden)
    invalid = invalid or any(
        context_global.count(token) != expected for token, expected in global_counts
    )
    invalid = invalid or any(
        live_scope.count(token) != expected
        for token, expected in live_scope_counts
    )
    invalid = invalid or any(
        live_global.count(token) != expected
        for token, expected in live_global_counts
    )
    code_global = mask_c_live_code(text, literals=False)
    invalid = invalid or any(
        code_global.count(token) != expected
        for token, expected in code_global_counts
    )
    if invalid:
        raise InstallError(f"conflicting or partial ABK injection in {path}: {marker}")
    return True


def replace_live_in_scope(
    path: Path,
    text: str,
    scope_anchor: str,
    old: str,
    new: str,
    error: str,
) -> str:
    scope_start, scope_end = c_scope_bounds(path, text, scope_anchor)
    scope = text[scope_start : scope_end + 1]
    live_scope = mask_c_live_code(scope, literals=False)
    if live_scope.count(old) != 1:
        raise InstallError(f"{error} in {path}")
    relative = live_scope.index(old)
    start = scope_start + relative
    return text[:start] + new + text[start + len(old) :]


def replace_live_global(
    path: Path,
    text: str,
    old: str,
    new: str,
    error: str,
) -> str:
    live = mask_c_live_code(text, literals=False)
    if live.count(old) != 1:
        raise InstallError(f"{error} in {path}")
    start = live.index(old)
    return text[:start] + new + text[start + len(old) :]


def replace_live_regex_in_scope(
    path: Path,
    text: str,
    scope_anchor: str,
    pattern: re.Pattern[str],
    replacement: str,
    error: str,
) -> str:
    scope_start, scope_end = c_scope_bounds(path, text, scope_anchor)
    scope = text[scope_start : scope_end + 1]
    live_scope = mask_c_live_code(scope, literals=False)
    matches = list(pattern.finditer(live_scope))
    if len(matches) != 1:
        raise InstallError(f"{error} in {path}")
    match = matches[0]
    start = scope_start + match.start()
    end = scope_start + match.end()
    return text[:start] + replacement + text[end:]


def insert_live_scope_start(
    path: Path,
    text: str,
    scope_anchor: str,
    insertion: str,
    error: str,
) -> str:
    scope_start, _ = c_scope_bounds(path, text, scope_anchor)
    if text[scope_start] != "{":
        raise InstallError(f"{error} in {path}")
    return text[: scope_start + 1] + insertion + text[scope_start + 1 :]


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


def config_state(defconfig: Path, symbol: str) -> str | None:
    text = read(defconfig)
    pattern = re.compile(
        rf"(?m)^(?:CONFIG_{re.escape(symbol)}=([^\n]+)|# CONFIG_{re.escape(symbol)} is not set)$"
    )
    matches = pattern.findall(text)
    if len(matches) > 1:
        raise InstallError(f"defconfig contains duplicate CONFIG_{symbol} entries")
    if not matches:
        return None
    return matches[0] or "n"


def extract_resukisu_modern_lsm_branch(path: Path, text: str) -> str:
    lexical = mask_c_comments_and_literals(text)
    lines = text.splitlines(keepends=True)
    lexical_lines = lexical.splitlines(keepends=True)
    target = re.compile(
        r"^[ \t]*#[ \t]*if[ \t]+LINUX_VERSION_CODE[ \t]*>=[ \t]*"
        r"KERNEL_VERSION[ \t]*\([ \t]*4[ \t]*,[ \t]*2[ \t]*,[ \t]*0[ \t]*\)"
        r"[ \t]*\|\|[ \t]*defined[ \t]*\([ \t]*"
        r"KSU_COMPAT_HAS_LIST_OF_LSM_HOOKS[ \t]*\)[ \t]*(?:\r?\n)?$"
    )
    directive = re.compile(
        r"^[ \t]*#[ \t]*(if|ifdef|ifndef|elif|else|endif)\b"
    )
    depth = 0
    candidates: list[int] = []
    for index, line in enumerate(lexical_lines):
        match = directive.match(line)
        if not match:
            continue
        kind = match.group(1)
        if kind in {"if", "ifdef", "ifndef"}:
            if target.fullmatch(line) and depth == 0:
                candidates.append(index)
            depth += 1
        elif kind == "endif":
            depth -= 1
            if depth < 0:
                raise InstallError(f"unbalanced preprocessor conditional in {path}")
    if depth or len(candidates) != 1:
        raise InstallError(
            "unsupported ReSukiSU runtime LSM hook shape: modern branch"
        )

    candidate = candidates[0]
    nested = 1
    branch_end: int | None = None
    branch_close: int | None = None
    for index in range(candidate + 1, len(lines)):
        match = directive.match(lexical_lines[index])
        if not match:
            continue
        kind = match.group(1)
        if kind in {"if", "ifdef", "ifndef"}:
            nested += 1
        elif kind == "endif":
            nested -= 1
            if nested == 0:
                branch_close = index
                break
        elif nested == 1 and kind == "else":
            if branch_end is not None:
                raise InstallError(
                    "unsupported ReSukiSU runtime LSM hook shape: modern branch"
                )
            branch_end = index
        elif nested == 1 and kind == "elif":
            raise InstallError(
                "unsupported ReSukiSU runtime LSM hook shape: modern branch"
            )
    if branch_end is None or branch_close is None:
        raise InstallError(
            "unsupported ReSukiSU runtime LSM hook shape: modern branch"
        )
    return "".join(lines[candidate + 1 : branch_end])


def resukisu_registration_sources(ksu: Path) -> list[tuple[Path, int]]:
    sources: list[tuple[Path, int]] = []
    audited_suffixes = {".c", ".h", ".inc", ".inl", ".s", ".S"}
    for source in sorted(ksu.rglob("*")):
        relative = source.relative_to(ksu)
        if (
            "abk_sandbox" in relative.parts
            or not source.is_file()
            or source.suffix not in audited_suffixes
        ):
            continue
        raw = source.read_bytes()
        if b"security_add_" not in raw:
            continue
        decoded = raw.decode("utf-8", errors="replace")
        code = collapse_c_line_continuations(
            mask_c_comments_and_literals(decoded)
        )
        if re.search(r"\bsecurity_add_\s*##\s*hooks\b", code):
            raise InstallError(
                "unsupported ReSukiSU runtime LSM hook shape: token-pasted registration"
            )
        count = len(re.findall(r"\bsecurity_add_hooks\b", code))
        if count:
            sources.append((source, count))
    return sources


def validate_resukisu_runtime_lsm_hooks(ksu: Path) -> None:
    hook_path = ksu / "hook/lsm_hooks.c"
    raw_text = read(hook_path)
    branch = extract_resukisu_modern_lsm_branch(hook_path, raw_text)
    text = collapse_c_line_continuations(mask_c_comments(branch))
    modern = re.fullmatch(
        r"\s*#\s*include\s*<linux/lsm_hooks\.h>\s*"
        r"static\s+struct\s+security_hook_list\s+ksu_hooks\[\]\s*=\s*"
        r"\{(?P<array>.*?)\};\s*"
        r"void\s+__init\s+ksu_lsm_hook_built_in_init\s*\(\s*void\s*\)\s*"
        r"(?P<registration>\{.*\})\s*",
        text,
        flags=re.DOTALL,
    )
    if modern is None:
        raise InstallError("unsupported ReSukiSU runtime LSM hook shape: ksu_hooks array")
    body = modern.group("array")
    audited_shape = re.compile(
        r"\s*LSM_HOOK_INIT\s*\(\s*inode_rename\s*,\s*ksu_inode_rename\s*\)\s*,\s*"
        r"#\s*ifdef\s+CONFIG_KSU_MANUAL_HOOK_AUTO_SETUID_HOOK\b\s*"
        r"LSM_HOOK_INIT\s*\(\s*task_fix_setuid\s*,\s*ksu_task_fix_setuid\s*\)\s*,\s*"
        r"#\s*endif\s*"
        r"#\s*ifdef\s+CONFIG_KSU_MANUAL_HOOK_AUTO_INITRC_HOOK\b\s*"
        r"LSM_HOOK_INIT\s*\(\s*file_permission\s*,\s*ksu_file_permission\s*\)\s*,\s*"
        r"#\s*endif\s*",
        flags=re.DOTALL,
    )
    if not audited_shape.fullmatch(body):
        raise InstallError(
            "unsupported ReSukiSU runtime LSM hook shape: array contents"
        )

    registration_scope = modern.group("registration")
    audited_registration = re.compile(
        r"\{\s*"
        r"if\s*\(\s*ARRAY_SIZE\s*\(\s*ksu_hooks\s*\)\s*==\s*0\s*\)\s*"
        r"return\s*;\s*"
        r"#\s*if\s+LINUX_VERSION_CODE\s*>=\s*"
        r"KERNEL_VERSION\s*\(\s*4\s*,\s*11\s*,\s*0\s*\)\s*\|\|\s*"
        r"defined\s*\(\s*KSU_COMPAT_REQUIRE_PROVIDE_LSM_NAME\s*\)\s*"
        r"security_add_hooks\s*\(\s*ksu_hooks\s*,\s*"
        r"ARRAY_SIZE\s*\(\s*ksu_hooks\s*\)\s*,\s*\"ksu\"\s*\)\s*;\s*"
        r"#\s*else\s*"
        r"security_add_hooks\s*\(\s*ksu_hooks\s*,\s*"
        r"ARRAY_SIZE\s*\(\s*ksu_hooks\s*\)\s*\)\s*;\s*"
        r"#\s*endif\s*\}",
        flags=re.DOTALL,
    )
    if not audited_registration.fullmatch(registration_scope):
        raise InstallError(
            "unsupported ReSukiSU runtime LSM hook shape: registration function"
        )

    registration_sources = resukisu_registration_sources(ksu)
    if registration_sources != [(hook_path, 2)]:
        raise InstallError(
            "unsupported ReSukiSU runtime LSM hook shape: extra registration token"
        )


def runtime_ksu_tail_policy(layout: Layout) -> str:
    if layout.variant != "resukisu":
        return RUNTIME_KSU_TAIL_NEVER
    major, minor = (int(part) for part in layout.version.split("."))
    if (major, minor) >= (6, 8):
        return RUNTIME_KSU_TAIL_NEVER
    validate_resukisu_runtime_lsm_hooks(layout.ksu)
    return RUNTIME_KSU_TAIL_RESUKISU_SUSFS


def validate_runtime_ksu_tail_config(
    policy: str, defconfig: Path | None
) -> None:
    if policy != RUNTIME_KSU_TAIL_RESUKISU_SUSFS or defconfig is None:
        return
    modes = {
        symbol: config_state(defconfig, symbol)
        for symbol in ("KSU_TRACEPOINT_HOOK", "KSU_MANUAL_HOOK", "KSU_SUSFS")
    }
    enabled = [symbol for symbol, state in modes.items() if state == "y"]
    if len(enabled) > 1:
        raise InstallError(
            "ReSukiSU defconfig enables multiple hook modes: " + ", ".join(enabled)
        )
    if modes["KSU_MANUAL_HOOK"] == "y":
        raise InstallError(
            "ReSukiSU manual LSM credential hooks are unsupported with ABK KSU Sandbox"
        )
    for symbol in (
        "KSU_MANUAL_HOOK_AUTO_SETUID_HOOK",
        "KSU_MANUAL_HOOK_AUTO_INITRC_HOOK",
    ):
        if config_state(defconfig, symbol) == "y":
            raise InstallError(
                f"ReSukiSU optional LSM hook CONFIG_{symbol}=y is unsupported"
            )


def install_kbuild(path: Path, block: str) -> None:
    text = read(path)
    validate_kbuild_directives(path, text)
    desired = block.strip()
    if MARKER not in text:
        write(path, text.rstrip() + "\n" + block.lstrip("\n"))
        return
    installed = installed_kbuild_block(path, text)
    if installed == desired:
        return
    write(path, text.replace(installed, desired, 1))


def insert_before_last(path: Path, needle: str, block: str) -> None:
    text = read(path)
    definition_pattern = re.compile(
        r"(?m)^[ \t]*(?:menuconfig|config)[ \t]+KSU_ABK_SANDBOX\b"
    )
    if MARKER in text or definition_pattern.search(text):
        installed_kconfig_block(path, text)
        return
    anchors = list(
        re.finditer(
            rf"(?m)^[ \t]*{re.escape(needle)}[ \t]*(?:#.*)?$", text
        )
    )
    if not anchors:
        raise InstallError(f"injection anchor {needle!r} not found in {path}")
    index = anchors[-1].start()
    kconfig_condition_depth(path, text, index)
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
    marker = f"{MARKER}: escape"
    signature = "int escape_with_root_profile(void)\n{"
    hook = f"""

#ifdef CONFIG_KSU_ABK_SANDBOX
    /* {marker} */
    {{
        bool handled = false;
        int sandbox_ret = abk_sandbox_try_escape(&handled);

        if (handled)
            return sandbox_ret;
    }}
#endif"""
    scope = c_scope_containing(path, text, signature)
    if exact_injection_installed(
        path,
        text,
        marker,
        ("{" + hook,),
        scope=scope,
        live_scope_counts=(("abk_sandbox_try_escape", 1),),
        live_global_counts=(("abk_sandbox_try_escape", 1),),
        code_global_counts=(('#include "abk_sandbox/abk_sandbox.h"', 1),),
    ):
        return
    text = add_include(text, '#include "abk_sandbox/abk_sandbox.h"', path)
    text = insert_live_scope_start(
        path,
        text,
        signature,
        hook,
        "escape_with_root_profile anchor not found",
    )
    write(path, text)


def patch_supercall_dispatch(ksu: Path) -> None:
    path = ksu / "supercall/dispatch.c"
    text = read(path)
    marker = f"{MARKER}: deny sandbox supercalls"
    anchor = (
        "long ksu_supercall_handle_ioctl(unsigned int cmd, void __user *argp)\n"
        "{\n"
    )
    hook = f"""{anchor}#ifdef CONFIG_KSU_ABK_SANDBOX
    /* {marker} */
    if (abk_sandbox_current(NULL, NULL))
        return -EPERM;
#endif
"""
    scope = c_scope_containing(path, text, anchor.rstrip("\n"))
    body_hook = hook[len(anchor) :]
    if exact_injection_installed(
        path,
        text,
        marker,
        ("{\n" + body_hook,),
        scope=scope,
        global_counts=(
            (anchor.rstrip("\n"), 1),
        ),
        live_scope_counts=(("abk_sandbox_current", 1),),
        live_global_counts=(("abk_sandbox_current", 1),),
        code_global_counts=(('#include "abk_sandbox/abk_sandbox.h"', 1),),
    ):
        return

    text = add_include(text, '#include "abk_sandbox/abk_sandbox.h"', path)
    write(
        path,
        insert_live_scope_start(
            path,
            text,
            anchor.rstrip("\n"),
            "\n" + body_hook,
            "KernelSU supercall dispatch anchor not found",
        ),
    )


def patch_allowlist(ksu: Path) -> None:
    path = ksu / "policy/allowlist.c"
    text = read(path)
    revoke_marker = f"{MARKER}: revoke"
    prune_marker = f"{MARKER}: prune"
    hook = f"""#ifdef CONFIG_KSU_ABK_SANDBOX
    /* {revoke_marker} */
    if (!result && !profile->allow_su)
        abk_sandbox_revoke_uid_async(profile->curr_uid);
#endif
"""
    prune_hook = f"""#ifdef CONFIG_KSU_ABK_SANDBOX
            /* {prune_marker} */
            abk_sandbox_revoke_uid_async(uid);
#endif
"""
    if revoke_marker in text or prune_marker in text:
        profile_scope = c_scope_containing(
            path, text, "int ksu_set_app_profile(struct app_profile *profile)"
        )
        prune_scope = c_scope_containing(path, text, "void ksu_prune_allowlist(")
        exact_injection_installed(
            path,
            text,
            revoke_marker,
            (hook + "    return result;",),
            scope=profile_scope,
            live_scope_counts=(("abk_sandbox_revoke_uid_async", 1),),
            code_global_counts=(('#include "abk_sandbox/abk_sandbox.h"', 1),),
        )
        exact_injection_installed(
            path,
            text,
            prune_marker,
            (prune_hook + "            hlist_del_rcu(&np->list);",),
            scope=prune_scope,
            live_scope_counts=(("abk_sandbox_revoke_uid_async", 1),),
            live_global_counts=(("abk_sandbox_revoke_uid_async", 2),),
        )
        return
    text = add_include(text, '#include "abk_sandbox/abk_sandbox.h"', path)
    text = replace_live_in_scope(
        path,
        text,
        "int ksu_set_app_profile(struct app_profile *profile)",
        "    return result;",
        hook + "    return result;",
        "ksu_set_app_profile return anchor not found",
    )
    text = replace_live_in_scope(
        path,
        text,
        "void ksu_prune_allowlist(",
        "            hlist_del_rcu(&np->list);",
        prune_hook + "            hlist_del_rcu(&np->list);",
        "allowlist prune removal anchor not found",
    )
    write(path, text)


def patch_policy_lock_order(ksu: Path) -> None:
    path = ksu / "selinux/rules.c"
    text = read(path)
    marker = f"{MARKER}: policy snapshot under lock"
    declaration = "struct selinux_policy *pol, *old_pol = selinux_state.policy;"
    replacement_declaration = "struct selinux_policy *pol, *old_pol;"
    lock = "    mutex_lock(&selinux_state.policy_mutex);"
    assignment = f"""
    /* {marker} */
    old_pol = rcu_dereference_protected(selinux_state.policy,
                    lockdep_is_held(&selinux_state.policy_mutex));"""
    scope = c_scope_containing(path, text, "void apply_kernelsu_rules()")
    if exact_injection_installed(
        path,
        text,
        marker,
        (replacement_declaration, lock + assignment),
        scope=scope,
        forbidden=(declaration,),
        live_scope_counts=(
            ("old_pol = rcu_dereference_protected(selinux_state.policy", 1),
        ),
    ):
        return

    text = replace_live_in_scope(
        path,
        text,
        "void apply_kernelsu_rules()",
        declaration,
        replacement_declaration,
        "SELinux policy snapshot declaration anchor not found",
    )
    text = replace_live_in_scope(
        path,
        text,
        "void apply_kernelsu_rules()",
        lock,
        lock + assignment,
        "SELinux policy lock anchor not found",
    )
    write(path, text)


def patch_policy_reapply(ksu: Path) -> None:
    path = ksu / "selinux/rules.c"
    text = read(path)
    marker = f"{MARKER}: policy reapply"
    database_assignment = "    db = &pol->policydb;"
    hook = f"""
#ifdef CONFIG_KSU_ABK_SANDBOX
    /* {marker} */
    if (abk_sandbox_policy_reapply(db)) {{
        ksu_destroy_sepolicy(pol);
        goto out_unlock;
    }}
#endif"""
    scope = c_scope_containing(path, text, "void apply_kernelsu_rules()")
    if exact_injection_installed(
        path,
        text,
        marker,
        (database_assignment + hook,),
        scope=scope,
        live_scope_counts=(("abk_sandbox_policy_reapply", 1),),
        live_global_counts=(("abk_sandbox_policy_reapply", 1),),
        code_global_counts=(('#include "abk_sandbox/abk_sandbox.h"', 1),),
    ):
        return
    text = add_include(text, '#include "abk_sandbox/abk_sandbox.h"', path)
    text = replace_live_in_scope(
        path,
        text,
        "void apply_kernelsu_rules()",
        database_assignment,
        database_assignment + hook,
        "policy database anchor not found",
    )
    write(path, text)


def patch_sucompat_fail_closed(layout: Layout) -> None:
    if layout.variant not in {"official", "sukisu"}:
        return
    path = layout.ksu / "feature/sucompat.c"
    text = read(path)
    marker = f"{MARKER}: sucompat fail closed"
    anchor = """    ret = escape_with_root_profile();
    if (ret) {
        pr_err("escape_with_root_profile failed: %ld\\n", ret);
    }"""
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
    scope = c_scope_containing(path, text, "long ksu_handle_execve_sucompat(")
    if exact_injection_installed(
        path,
        text,
        marker,
        (replacement,),
        scope=scope,
        forbidden=(anchor,),
        live_scope_counts=(("escape_with_root_profile", 1),),
    ):
        return
    write(
        path,
        replace_live_in_scope(
            path,
            text,
            "long ksu_handle_execve_sucompat(",
            anchor,
            replacement,
            "sucompat fail-closed anchor not found",
        ),
    )


def patch_resukisu_manual_fail_closed(layout: Layout) -> None:
    if layout.variant != "resukisu":
        return
    path = layout.ksu / "feature/sucompat.c"
    text = read(path)
    marker = f"{MARKER}: manual su fail closed"
    anchor = "    escape_with_root_profile();"
    hook = f"""    /* {marker} */
    {{
        int sandbox_ret = escape_with_root_profile();

        if (sandbox_ret)
            return sandbox_ret;
    }}"""
    scope = c_scope_containing(
        path, text, "static inline int do_ksu_handle_execveat_sucompat("
    )
    if exact_injection_installed(
        path,
        text,
        marker,
        (hook,),
        scope=scope,
        forbidden=(anchor,),
        live_scope_counts=(("escape_with_root_profile", 1),),
    ):
        return
    write(
        path,
        replace_live_in_scope(
            path,
            text,
            "static inline int do_ksu_handle_execveat_sucompat(",
            anchor,
            hook,
            "ReSukiSU manual su anchor not found",
        ),
    )


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
    marker = f"{MARKER}: lsm count"
    definition_anchor = "#define MAX_LSM_COUNT \\\n"
    list_anchor = "\t\tIPE_ENABLED)"
    definition = f"""/* {marker} */
#if IS_ENABLED(CONFIG_KSU_ABK_SANDBOX)
#define ABK_KSU_SANDBOX_ENABLED 1,
#else
#define ABK_KSU_SANDBOX_ENABLED
#endif

"""
    list_injection = "\t\tABK_KSU_SANDBOX_ENABLED\\\n" + list_anchor
    if exact_injection_installed(
        path,
        text,
        marker,
        (definition, list_injection),
        global_counts=(("ABK_KSU_SANDBOX_ENABLED", 3),),
    ):
        return
    text = replace_live_global(
        path,
        text,
        definition_anchor,
        definition + definition_anchor,
        "LSM count definition anchor not found",
    )
    text = replace_live_global(
        path,
        text,
        list_anchor,
        list_injection,
        "LSM count list anchor not found",
    )
    write(path, text)


def patch_kernel_hooks(common: Path) -> None:
    seccomp = common / "kernel/seccomp.c"
    text = read(seccomp)
    normalized = add_include(text, "#include <linux/abk_ksu_sandbox.h>", seccomp)
    if normalized != text:
        write(seccomp, normalized)
        text = normalized
    seccomp_marker = f"{MARKER}: seccomp entry"
    seccomp_hook = (
        f"\n\t/* {seccomp_marker} */\n"
        "\tif (abk_ksu_sandbox_seccomp_allow_syscall(this_syscall))\n"
        "\t\treturn 0;\n"
    )
    seccomp_pattern = re.compile(
        r"(?m)^(\s*this_syscall = sd \? sd->nr :\n"
        r"\s*syscall_get_nr\(current, current_pt_regs\(\)\);)$"
    )
    seccomp_call = "abk_ksu_sandbox_seccomp_allow_syscall(this_syscall)"
    if seccomp_marker in text and seccomp_call not in mask_c_live_code(
        text, literals=False
    ):
        raise InstallError(
            f"incomplete sandbox injection: {seccomp_call!r} missing from {seccomp}"
        )
    seccomp_scope = c_scope_containing(
        seccomp, text, "this_syscall = sd ? sd->nr :"
    )
    seccomp_matches = list(seccomp_pattern.finditer(mask_c_live_code(seccomp_scope, literals=False)))
    if len(seccomp_matches) != 1:
        raise InstallError(f"__secure_computing entry anchor not found in {seccomp}")
    seccomp_match = seccomp_matches[0]
    seccomp_assignment = seccomp_scope[seccomp_match.start() : seccomp_match.end()]
    if not exact_injection_installed(
        seccomp,
        text,
        seccomp_marker,
        (seccomp_assignment + seccomp_hook,),
        scope=seccomp_scope,
        live_scope_counts=(("abk_ksu_sandbox_seccomp_allow_syscall", 1),),
        live_global_counts=(("abk_ksu_sandbox_seccomp_allow_syscall", 1),),
        code_global_counts=(("#include <linux/abk_ksu_sandbox.h>", 1),),
    ):
        scope_start = text.index(seccomp_scope)
        insertion = scope_start + seccomp_match.end()
        text = text[:insertion] + seccomp_hook + text[insertion:]
        write(seccomp, text)

    namespace = common / "fs/namespace.c"
    text = read(namespace)
    normalized = add_include(text, "#include <linux/abk_ksu_sandbox.h>", namespace)
    if normalized != text:
        write(namespace, normalized)
        text = normalized
    mount_privilege_marker = f"{MARKER}: legacy mount privilege"
    privilege_anchor = "\tif (!may_mount())\n\t\treturn -EPERM;"
    mount_privilege_hook = (
        f"\t/* {mount_privilege_marker} */\n"
        "\tif (!may_mount() && !abk_ksu_sandbox_may_mount())\n"
        "\t\treturn -EPERM;"
    )
    if "int path_mount(" not in mask_c_live_code(text):
        raise InstallError(f"path_mount privilege anchor not found in {namespace}")
    path_mount_scope = c_scope_containing(namespace, text, "int path_mount(")
    if not exact_injection_installed(
        namespace,
        text,
        mount_privilege_marker,
        (mount_privilege_hook,),
        scope=path_mount_scope,
        forbidden=(privilege_anchor,),
        live_scope_counts=(("abk_ksu_sandbox_may_mount", 1),),
        code_global_counts=(("#include <linux/abk_ksu_sandbox.h>", 1),),
    ):
        text = replace_live_in_scope(
            namespace,
            text,
            "int path_mount(",
            privilege_anchor,
            mount_privilege_hook,
            "path_mount privilege anchor not found",
        )
        write(namespace, text)

    text = read(namespace)
    old_bind_validation = "abk_ksu_sandbox_bind_validate(&old_path, path)"
    new_bind_validation = (
        "abk_ksu_sandbox_bind_validate(&old_path, path, recurse)"
    )
    bind_marker = f"{MARKER}: resolved bind source"
    if bind_marker in text and old_bind_validation in text:
        text = replace_live_in_scope(
            namespace,
            text,
            "static int do_loopback(",
            old_bind_validation,
            new_bind_validation,
            "legacy bind validation anchor not found",
        )
        write(namespace, text)
    bind_pattern = re.compile(
        r"(\terr = kern_path\(old_name, LOOKUP_FOLLOW\|LOOKUP_AUTOMOUNT, &old_path\);\n"
        r"\tif \(err\)\n\t\treturn err;)"
    )
    bind_scope = c_scope_containing(namespace, text, "static int do_loopback(")
    bind_matches = list(bind_pattern.finditer(mask_c_live_code(bind_scope, literals=False)))
    if len(bind_matches) != 1:
        raise InstallError(f"do_loopback resolved-source anchor not found in {namespace}")
    bind_match = bind_matches[0]
    bind_anchor = bind_scope[bind_match.start() : bind_match.end()]
    bind_hook = (
        bind_anchor
        + f"\n\n\t/* {bind_marker} */"
        + "\n\terr = abk_ksu_sandbox_bind_validate(&old_path, path, recurse);"
        + "\n\tif (err)"
        + "\n\t\tgoto out;"
    )
    if not exact_injection_installed(
        namespace,
        text,
        bind_marker,
        (bind_hook,),
        scope=bind_scope,
        live_scope_counts=(
            ("abk_ksu_sandbox_bind_validate", 1),
            ("kern_path(old_name", 1),
        ),
        live_global_counts=(("abk_ksu_sandbox_bind_validate", 1),),
    ):
        scope_start = text.index(bind_scope)
        start = scope_start + bind_match.start()
        end = scope_start + bind_match.end()
        text = text[:start] + bind_hook + text[end:]
        write(namespace, text)

    text = read(namespace)
    umount_privilege_marker = f"{MARKER}: legacy umount privilege"
    umount_privilege_hook = (
        f"\t/* {umount_privilege_marker} */\n"
        "\tif (!may_mount() && !abk_ksu_sandbox_may_mount())\n"
        "\t\treturn -EPERM;"
    )
    can_umount_scope = c_scope_containing(namespace, text, "static int can_umount(")
    if not exact_injection_installed(
        namespace,
        text,
        umount_privilege_marker,
        (umount_privilege_hook,),
        scope=can_umount_scope,
        forbidden=(privilege_anchor,),
        live_scope_counts=(("abk_ksu_sandbox_may_mount", 1),),
    ):
        text = replace_live_in_scope(
            namespace,
            text,
            "static int can_umount(",
            privilege_anchor,
            umount_privilege_hook,
            "can_umount privilege anchor not found",
        )
        write(namespace, text)

    text = read(namespace)
    mount_result_marker = f"{MARKER}: mount result"
    security_anchor = (
        "\tret = security_sb_mount(dev_name, path, type_page, flags, data_page);\n"
        "\tif (ret)\n"
        "\t\treturn ret;"
    )
    security_hook = (
        "\tret = security_sb_mount(dev_name, path, type_page, flags, data_page);\n"
        "\tif (ret) {\n"
        f"\t\t/* {mount_result_marker} */\n"
        "\t\tabk_ksu_sandbox_mount_result(path, ret);\n"
        "\t\treturn ret;\n"
        "\t}"
    )
    mount_bind_anchor = (
        "\tif (flags & MS_BIND)\n"
        "\t\treturn do_loopback(path, dev_name, flags & MS_REC);"
    )
    mount_bind_hook = (
        "\tif (flags & MS_BIND) {\n"
        "\t\tret = do_loopback(path, dev_name, flags & MS_REC);\n"
        "\t\tabk_ksu_sandbox_mount_result(path, ret);\n"
        "\t\treturn ret;\n"
        "\t}"
    )
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
    path_mount_scope = c_scope_containing(namespace, text, "int path_mount(")
    mount_result_installed = exact_injection_installed(
        namespace,
        text,
        mount_result_marker,
        (security_hook, mount_bind_hook, new_mount_hook),
        scope=path_mount_scope,
        forbidden=(security_anchor, mount_bind_anchor),
        live_scope_counts=(("abk_ksu_sandbox_mount_result", 3),),
        live_global_counts=(("abk_ksu_sandbox_mount_result", 3),),
    )
    old_new_mounts = list(
        new_mount_pattern.finditer(mask_c_live_code(path_mount_scope, literals=False))
    )
    if mount_result_installed:
        if old_new_mounts:
            raise InstallError(
                f"conflicting or partial ABK injection in {namespace}: {mount_result_marker}"
            )
    else:
        text = replace_live_in_scope(
            namespace,
            text,
            "int path_mount(",
            security_anchor,
            security_hook,
            "path_mount security anchor not found",
        )
        text = replace_live_in_scope(
            namespace,
            text,
            "int path_mount(",
            mount_bind_anchor,
            mount_bind_hook,
            "path_mount bind anchor not found",
        )
        text = replace_live_regex_in_scope(
            namespace,
            text,
            "int path_mount(",
            new_mount_pattern,
            new_mount_hook,
            "path_mount new-mount anchor not found",
        )
        write(namespace, text)

    text = read(namespace)
    umount_marker = f"{MARKER}: umount validate"
    umount_anchor = (
        "\tret = can_umount(path, flags);\n"
        "\tif (!ret)\n"
        "\t\tret = do_umount(mnt, flags);"
    )
    umount_hook = (
        f"\t/* {umount_marker} */\n"
        "\tret = abk_ksu_sandbox_umount_validate(path, flags);\n"
        "\tif (!ret)\n"
        "\t\tret = can_umount(path, flags);\n"
        "\tif (!ret)\n"
        "\t\tret = do_umount(mnt, flags);\n"
        "\tabk_ksu_sandbox_umount_result(path, ret);"
    )
    path_umount_scope = c_scope_containing(namespace, text, "int path_umount(")
    if not exact_injection_installed(
        namespace,
        text,
        umount_marker,
        (umount_hook,),
        scope=path_umount_scope,
        live_scope_counts=(
            ("abk_ksu_sandbox_umount_validate", 1),
            ("abk_ksu_sandbox_umount_result", 1),
        ),
        live_global_counts=(
            ("abk_ksu_sandbox_umount_validate", 1),
            ("abk_ksu_sandbox_umount_result", 1),
        ),
    ):
        text = replace_live_in_scope(
            namespace,
            text,
            "int path_umount(",
            umount_anchor,
            umount_hook,
            "path_umount anchor not found",
        )
        write(namespace, text)

    ptrace = common / "kernel/ptrace.c"
    text = read(ptrace)
    normalized = add_include(text, "#include <linux/abk_ksu_sandbox.h>", ptrace)
    if normalized != text:
        write(ptrace, normalized)
        text = normalized
    ptrace_marker = f"{MARKER}: ptrace"
    ptrace_anchor = "\ttcred = __task_cred(task);"
    ptrace_code = (
        ptrace_anchor
        + f"\n\t/* {ptrace_marker} */"
        + "\n\tif (abk_ksu_sandbox_may_ptrace(tcred))"
        + "\n\t\tgoto ok;"
    )
    dumpable = (
        "\tif (mm &&\n"
        "\t    ((get_dumpable(mm) != SUID_DUMP_USER) &&\n"
        "\t     !ptrace_has_cap(mm->user_ns, mode)))"
    )
    dumpable_hook = (
        "\tif (mm &&\n"
        "\t    ((get_dumpable(mm) != SUID_DUMP_USER) &&\n"
        "\t     !abk_ksu_sandbox_may_ptrace_task(task) &&\n"
        "\t     !ptrace_has_cap(mm->user_ns, mode)))"
    )
    ptrace_scope = c_scope_containing(ptrace, text, ptrace_anchor)
    if not exact_injection_installed(
        ptrace,
        text,
        ptrace_marker,
        (ptrace_code, dumpable_hook),
        scope=ptrace_scope,
        forbidden=(dumpable,),
        live_scope_counts=(
            ("abk_ksu_sandbox_may_ptrace(", 1),
            ("abk_ksu_sandbox_may_ptrace_task(", 1),
        ),
        code_global_counts=(("#include <linux/abk_ksu_sandbox.h>", 1),),
    ):
        text = replace_live_in_scope(
            ptrace,
            text,
            ptrace_anchor,
            ptrace_anchor,
            ptrace_code,
            "ptrace target credential anchor not found",
        )
        text = replace_live_in_scope(
            ptrace,
            text,
            ptrace_anchor,
            dumpable,
            dumpable_hook,
            "ptrace dumpability anchor not found",
        )
        write(ptrace, text)

    signal = common / "kernel/signal.c"
    text = read(signal)
    normalized = add_include(text, "#include <linux/abk_ksu_sandbox.h>", signal)
    if normalized != text:
        write(signal, normalized)
        text = normalized
    signal_marker = f"{MARKER}: signal"
    signal_pattern = re.compile(
        r"if \(!same_thread_group\(current, t\) &&\n"
        r"\s*!kill_ok_by_cred\(t\)\) \{"
    )
    signal_replacement = (
        "if (!same_thread_group(current, t) &&\n"
        f"\t    /* {signal_marker} */\n"
        "\t    !abk_ksu_sandbox_may_signal(t) &&\n"
        "\t    !kill_ok_by_cred(t)) {"
    )
    signal_anchor = "if (!same_thread_group(current, t) &&"
    if signal_anchor not in mask_c_live_code(text):
        raise InstallError(
            f"check_kill_permission credential anchor not found in {signal}"
        )
    signal_scope = c_scope_containing(
        signal, text, signal_anchor
    )
    old_signal_matches = list(
        signal_pattern.finditer(mask_c_live_code(signal_scope, literals=False))
    )
    signal_installed = exact_injection_installed(
        signal,
        text,
        signal_marker,
        (signal_replacement,),
        scope=signal_scope,
        live_scope_counts=(("abk_ksu_sandbox_may_signal", 1),),
        live_global_counts=(("abk_ksu_sandbox_may_signal", 1),),
        code_global_counts=(("#include <linux/abk_ksu_sandbox.h>", 1),),
    )
    if signal_installed:
        if old_signal_matches:
            raise InstallError(
                f"conflicting or partial ABK injection in {signal}: {signal_marker}"
            )
    else:
        text = replace_live_regex_in_scope(
            signal,
            text,
            signal_anchor,
            signal_pattern,
            signal_replacement,
            "check_kill_permission credential anchor not found",
        )
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
    ksu_state = config_state(defconfig, "KSU")
    if ksu_state == "m":
        raise InstallError("CONFIG_KSU=m is unsupported; built-in CONFIG_KSU=y is required")
    for symbol, message in (
        ("KSU", "built-in CONFIG_KSU=y is required"),
        ("SECURITY_SELINUX", "CONFIG_SECURITY_SELINUX=y is required"),
        ("NAMESPACES", "CONFIG_NAMESPACES=y is required"),
    ):
        if config_state(defconfig, symbol) != "y":
            raise InstallError(message)
    if require_sandbox and config_state(defconfig, "KSU_ABK_SANDBOX") != "y":
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
    tail_policy = runtime_ksu_tail_policy(layout)
    validate_runtime_ksu_tail_config(tail_policy, defconfig)
    with InstallTransaction():
        copy_sources(layout.ksu, module_root)
        install_kbuild(layout.ksu / "Kbuild", kbuild_block(tail_policy))
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
        f"ABK KSU Sandbox: installed variant={layout.variant} kernel={layout.version} "
        f"runtime_ksu_tail_policy={tail_policy} ksu={layout.ksu}"
    )


def validate_patch_sources(layout: Layout, module_root: Path) -> None:
    global _VALIDATION_ONLY

    previous = _VALIDATION_ONLY
    _VALIDATION_ONLY = True
    try:
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
    finally:
        _VALIDATION_ONLY = previous


def verify(layout: Layout, module_root: Path, defconfig: Path | None) -> None:
    tail_policy = runtime_ksu_tail_policy(layout)
    validate_runtime_ksu_tail_config(tail_policy, defconfig)
    expected_kbuild = kbuild_block(tail_policy).strip()
    kbuild_path = layout.ksu / "Kbuild"
    installed_kbuild = installed_kbuild_block(kbuild_path, read(kbuild_path))
    if installed_kbuild != expected_kbuild:
        raise InstallError(
            "incomplete sandbox injection: installed ABK Kbuild runtime "
            "LSM-tail policy does not match the target configuration"
        )
    validate_patch_sources(layout, module_root)
    checks = {
        layout.ksu / "Kbuild": [
            MARKER,
            "requires CONFIG_KSU_ABK_SANDBOX=y",
            "ABK_KSU_RUNTIME_TAIL_SOURCE_VERIFIED",
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
    installed_kconfig_block(
        layout.ksu / "Kconfig", read(layout.ksu / "Kconfig")
    )
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
    for source in (
        "Makefile",
        "core.c",
        "policy.c",
        "namespace.c",
        "lsm.c",
        "abk_sandbox.h",
        "lsm_build_config.h",
        "lsm_order.h",
    ):
        installed = layout.ksu / "abk_sandbox" / source
        if read(installed) != read(source_dir / source):
            raise InstallError(f"installed source differs from module template: {installed}")
    header = layout.common / "include/linux/abk_ksu_sandbox.h"
    if read(header) != read(source_dir / "abk_ksu_sandbox_api.h"):
        raise InstallError(f"installed public header differs from module template: {header}")
    if defconfig:
        validate_defconfig(defconfig, require_sandbox=True)
    print(
        f"ABK KSU Sandbox: verified variant={layout.variant} kernel={layout.version} "
        f"runtime_ksu_tail_policy={tail_policy} ksu={layout.ksu}"
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
