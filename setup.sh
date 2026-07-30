#!/usr/bin/env bash
set -euo pipefail

MODULE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

if [ -f "$MODULE_DIR/module.conf" ]; then
  # shellcheck disable=SC1091
  source "$MODULE_DIR/module.conf"
fi

# shellcheck disable=SC1091
source "$MODULE_DIR/scripts/libabk.sh"

abk_require_env KERNEL_ROOT DEFCONFIG CUSTOM_EXTERNAL_MODULE_STAGE

abk_log "module: ${ABK_MODULE_NAME:-ABK KSU Sandbox}"
abk_log "version: ${ABK_MODULE_VERSION:-unknown}"
abk_log "stage: $CUSTOM_EXTERNAL_MODULE_STAGE"
abk_log "kernel root: $KERNEL_ROOT"

abk_ensure_builtin_ksu() {
  local ksu_line

  abk_require_file "$DEFCONFIG"
  ksu_line="$(grep -E '^(CONFIG_KSU=|# CONFIG_KSU is not set$)' "$DEFCONFIG" || true)"
  case "$ksu_line" in
    CONFIG_KSU=y)
      ;;
    "")
      abk_enable_config CONFIG_KSU
      ;;
    *)
      abk_die "CONFIG_KSU must be built-in (y); refusing $ksu_line"
      ;;
  esac
}

case "$CUSTOM_EXTERNAL_MODULE_STAGE" in
  after_patch)
    abk_ensure_builtin_ksu
    python3 "$MODULE_DIR/scripts/install.py" install \
      --kernel-root "$KERNEL_ROOT" \
      --module-root "$MODULE_DIR" \
      --defconfig "$DEFCONFIG"
    ;;
  before_build)
    abk_enable_config CONFIG_KSU_ABK_SANDBOX
    abk_enable_lsm abk_ksu_sandbox
    python3 "$MODULE_DIR/scripts/install.py" verify \
      --kernel-root "$KERNEL_ROOT" \
      --module-root "$MODULE_DIR" \
      --defconfig "$DEFCONFIG"
    ;;
  *)
    abk_die "unsupported CUSTOM_EXTERNAL_MODULE_STAGE: $CUSTOM_EXTERNAL_MODULE_STAGE"
    ;;
esac

abk_log "done"
